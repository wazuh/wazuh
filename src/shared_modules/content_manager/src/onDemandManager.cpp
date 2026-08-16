/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "onDemandManager.hpp"
#include "actionOrchestrator.hpp"
#include "contentOnDemand.hpp"
#include "sharedDefs.hpp"

#include <utility>

namespace content_manager
{
    void
    dispatchOnDemand(const std::string& topic, int offset, std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
    {
        OnDemandManager::instance().dispatch(topic, offset, std::move(responder));
    }
} // namespace content_manager

OnDemandManager::~OnDemandManager()
{
    stopWorkers();
}

void OnDemandManager::addEndpoint(const std::string& endpoint, std::function<bool(ActionOrchestrator::UpdateData)> func)
{
    std::unique_lock<std::shared_mutex> lock {m_registryMutex};
    if (m_endpoints.find(endpoint) != m_endpoints.end())
    {
        throw std::runtime_error("Endpoint already exists");
    }
    m_endpoints[endpoint] = std::move(func);

    // Lazily bring the lane up with the first topic (the old server started the same way).
    std::lock_guard<std::mutex> laneLock {m_laneMutex};
    startWorkersLocked();
}

void OnDemandManager::removeEndpoint(const std::string& endpoint)
{
    bool becameEmpty = false;
    {
        // The unique_lock is the guarantee: a worker runs callbacks under a shared_lock, so once
        // this is held no callback of the removed topic is in flight -- Action teardown relies
        // on exactly that, unchanged from the old server.
        std::unique_lock<std::shared_mutex> lock {m_registryMutex};
        m_endpoints.erase(endpoint);
        becameEmpty = m_endpoints.empty();
    }
    if (becameEmpty)
    {
        // OUTSIDE the registry lock: stopWorkers() joins, and a worker may be blocked acquiring
        // the shared_lock this thread would still be holding.
        stopWorkers();
    }
}

void OnDemandManager::clearEndpoints()
{
    {
        std::unique_lock<std::shared_mutex> lock {m_registryMutex};
        m_endpoints.clear();
    }
    stopWorkers();
}

void OnDemandManager::dispatch(const std::string& topic,
                               int offset,
                               std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
{
    {
        // Unknown topics are answered inline: no queue slot is spent on a request that can never
        // run. The authoritative lookup still happens in the worker (the topic can be removed
        // while queued).
        std::shared_lock<std::shared_mutex> lock {m_registryMutex};
        if (m_endpoints.find(topic) == m_endpoints.end())
        {
            lock.unlock();
            logUnknownTopic(topic);
            responder->send(wazuh::uds_http::HttpResponse::json(404, R"({"error":"unknown_topic","retryable":false})"));
            return;
        }
    }

    auto laneFull = false;
    {
        std::lock_guard<std::mutex> lock {m_laneMutex};
        if (m_stopping || m_workers.empty())
        {
            // Not logged per request: shutdown is bounded and stopWorkers() reports what it shed.
            responder->send(wazuh::uds_http::HttpResponse::json(503, R"({"error":"shutting_down","retryable":true})"));
            return;
        }
        laneFull = m_queue.size() >= QUEUE_SLOTS;
        if (!laneFull)
        {
            m_queue.push_back(Job {topic, offset, std::move(responder)});
        }
    }

    if (laneFull)
    {
        // Formatted outside m_laneMutex on purpose: a burst that fills the lane is exactly when
        // the workers need that lock to drain it.
        if (const auto decision = m_laneFullThrottle.record())
        {
            logWarn(WM_CONTENTUPDATER,
                    "Rejected %llu on-demand update(s) with 503 in the last %d s: the on-demand lane is full "
                    "(%zu slot(s)) (last topic: '%s').",
                    static_cast<unsigned long long>(decision.total),
                    wazuh::uds_http::LogThrottle::kDefaultWindowSeconds,
                    QUEUE_SLOTS,
                    topic.c_str());
        }
        responder->send(
            wazuh::uds_http::HttpResponse::json(503, R"({"error":"ondemand_queue_full","retryable":true})"));
        return;
    }

    m_wake.notify_one();
}

void OnDemandManager::logUnknownTopic(const std::string& topic)
{
    // Shared by both lookups -- the inline one and the worker's re-check after the topic was
    // removed while the job waited. Same condition from the caller's side, same window.
    if (const auto decision = m_unknownTopicThrottle.record())
    {
        logWarn(WM_CONTENTUPDATER,
                "Rejected %llu on-demand request(s) with 404 in the last %d s: unknown topic (last: '%s').",
                static_cast<unsigned long long>(decision.total),
                wazuh::uds_http::LogThrottle::kDefaultWindowSeconds,
                topic.c_str());
    }
}

void OnDemandManager::startWorkersLocked()
{
    if (!m_workers.empty())
    {
        return;
    }
    m_stopping = false;
    for (std::size_t i = 0; i < WORKER_COUNT; ++i)
    {
        m_workers.emplace_back([this] { run(); });
    }
}

void OnDemandManager::stopWorkers()
{
    std::vector<std::thread> workers;
    std::deque<Job> abandoned;
    {
        std::lock_guard<std::mutex> lock {m_laneMutex};
        if (m_workers.empty())
        {
            return;
        }
        m_stopping = true;
        abandoned.swap(m_queue);
        workers.swap(m_workers);
    }
    m_wake.notify_all();
    for (auto& job : abandoned)
    {
        // send() is exactly-once and a defined no-op after the transport stopped.
        job.responder->send(wazuh::uds_http::HttpResponse::json(503, R"({"error":"shutting_down","retryable":true})"));
    }
    for (auto& worker : workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    if (abandoned.empty())
    {
        logDebug1(WM_CONTENTUPDATER, "On-demand lane stopped");
    }
    else
    {
        // Worth an INFO: work was accepted and then shed, which the operator cannot see anywhere
        // else (the per-request 503s of a shutdown are deliberately not logged).
        logInfo(WM_CONTENTUPDATER, "On-demand lane stopped; %zu queued update(s) were answered 503.", abandoned.size());
    }
}

void OnDemandManager::run()
{
    for (;;)
    {
        Job job;
        {
            std::unique_lock<std::mutex> lock {m_laneMutex};
            m_wake.wait(lock, [this] { return m_stopping || !m_queue.empty(); });
            if (m_stopping)
            {
                return; // stopWorkers() already answered whatever was queued
            }
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }

        // SHARED lock for the whole run: the contract removeEndpoint() builds its "nothing of
        // mine still runs" guarantee on. Blocking here is fine -- this is a lane worker, never a
        // transport I/O thread.
        std::shared_lock<std::shared_mutex> lock {m_registryMutex};
        const auto it = m_endpoints.find(job.topic);
        if (it == m_endpoints.end())
        {
            logUnknownTopic(job.topic);
            job.responder->send(
                wazuh::uds_http::HttpResponse::json(404, R"({"error":"unknown_topic","retryable":false})"));
            continue;
        }

        try
        {
            if (it->second(ActionOrchestrator::UpdateData::createContentUpdateData(job.offset)))
            {
                job.responder->send(wazuh::uds_http::HttpResponse::json(200, R"({"status":"ok"})"));
            }
            else
            {
                // The honest answer the old server never gave: it said 200 to a request it had
                // silently ignored because that topic's update was already running. INFO, not a
                // warning: coalescing concurrent triggers for one topic is the design working.
                if (const auto decision = m_inProgressThrottle.record())
                {
                    logInfo(WM_CONTENTUPDATER,
                            "Answered %llu on-demand request(s) with 409 in the last %d s: an update for that topic "
                            "was already running (last: '%s').",
                            static_cast<unsigned long long>(decision.total),
                            wazuh::uds_http::LogThrottle::kDefaultWindowSeconds,
                            job.topic.c_str());
                }
                job.responder->send(
                    wazuh::uds_http::HttpResponse::json(409, R"({"error":"update_in_progress","retryable":true})"));
            }
        }
        catch (const std::exception& e)
        {
            logWarn(WM_CONTENTUPDATER, "On-demand update for '%s' failed: %s", job.topic.c_str(), e.what());
            job.responder->send(
                wazuh::uds_http::HttpResponse::json(500, R"({"error":"update_failed","retryable":true})"));
        }
    }
}
