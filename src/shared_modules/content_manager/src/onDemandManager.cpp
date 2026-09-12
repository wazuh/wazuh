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
#include "contentOnDemand.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"

#include <stdexcept>
#include <utility>

namespace content_manager
{
    void
    requestOnDemand(const std::string& topic, RunRequest req, std::function<void(OnDemandResult)> completion) noexcept
    {
        try
        {
            req.onDemand = true;
            OnDemandManager::instance().dispatch(topic, req, std::move(completion));
        }
        catch (const std::exception& e)
        {
            logWarn(WM_CONTENTUPDATER, "Failed to queue the on-demand update for '%s': %s", topic.c_str(), e.what());
        }
        catch (...)
        {
            logWarn(WM_CONTENTUPDATER, "Failed to queue the on-demand update for '%s'.", topic.c_str());
        }
    }
} // namespace content_manager

OnDemandManager::~OnDemandManager()
{
    stopWorkers();
}

void OnDemandManager::addEndpoint(const std::string& endpoint, UpdateFunction func)
{
    std::unique_lock<std::shared_mutex> lock {m_registryMutex};
    if (m_endpoints.find(endpoint) != m_endpoints.end())
    {
        throw std::runtime_error("Endpoint already exists");
    }
    m_endpoints[endpoint] = std::move(func);

    // Lazily bring the lane up with the first topic.
    std::lock_guard<std::mutex> laneLock {m_laneMutex};
    startWorkersLocked();
}

void OnDemandManager::removeEndpoint(const std::string& endpoint)
{
    bool becameEmpty = false;
    {
        // The unique lock is the guarantee: a worker runs callbacks under a shared lock, so once
        // this is held no callback of the removed topic is in flight. Topic teardown relies on
        // exactly that.
        std::unique_lock<std::shared_mutex> lock {m_registryMutex};
        m_endpoints.erase(endpoint);
        becameEmpty = m_endpoints.empty();
    }
    if (becameEmpty)
    {
        // OUTSIDE the registry lock: stopWorkers() joins, and a worker may be blocked acquiring the
        // shared lock this thread would still be holding.
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
                               content_manager::RunRequest request,
                               std::function<void(content_manager::OnDemandResult)> completion)
{
    Job job {topic, request, std::move(completion)};

    {
        // Unknown topics are answered inline: no queue slot is spent on a request that can never
        // run. The authoritative lookup still happens in the worker, since the topic can be removed
        // while the job waits.
        std::shared_lock<std::shared_mutex> lock {m_registryMutex};
        if (m_endpoints.find(topic) == m_endpoints.end())
        {
            lock.unlock();
            logUnknownTopic(topic);
            answer(job, content_manager::OnDemandCode::UnknownTopic, "unknown topic");
            return;
        }
    }

    auto laneFull = false;
    {
        std::lock_guard<std::mutex> lock {m_laneMutex};
        if (m_stopping || m_workers.empty())
        {
            // Not logged per request: shutdown is bounded and stopWorkers() reports what it shed.
            answer(job, content_manager::OnDemandCode::ShuttingDown, "the on-demand lane is shutting down");
            return;
        }
        laneFull = m_queue.size() >= QUEUE_SLOTS;
        if (!laneFull)
        {
            m_queue.push_back(std::move(job));
        }
    }

    if (laneFull)
    {
        // Formatted outside m_laneMutex on purpose: a burst that fills the lane is exactly when the
        // workers need that lock to drain it.
        if (const auto decision = m_laneFullThrottle.record())
        {
            logWarn(WM_CONTENTUPDATER,
                    "Rejected %llu on-demand update(s) in the last %d s: the on-demand lane is full "
                    "(%zu slot(s)) (last topic: '%s').",
                    static_cast<unsigned long long>(decision.total),
                    LogThrottle::DEFAULT_WINDOW_SECONDS,
                    QUEUE_SLOTS,
                    topic.c_str());
        }
        answer(job, content_manager::OnDemandCode::QueueFull, "the on-demand lane is full");
        return;
    }

    m_wake.notify_one();
}

void OnDemandManager::answer(const Job& job, content_manager::OnDemandCode code, std::string detail)
{
    if (!job.completion)
    {
        return;
    }

    try
    {
        job.completion(content_manager::OnDemandResult {code, std::move(detail)});
    }
    catch (const std::exception& e)
    {
        // The completion belongs to the host and may live in another DSO; its failure must not take
        // a lane worker with it.
        logWarn(WM_CONTENTUPDATER, "On-demand completion for '%s' threw: %s", job.topic.c_str(), e.what());
    }
    catch (...)
    {
        logWarn(WM_CONTENTUPDATER, "On-demand completion for '%s' threw.", job.topic.c_str());
    }
}

void OnDemandManager::logUnknownTopic(const std::string& topic)
{
    // Shared by both lookups — the inline one and the worker's re-check after the topic was removed
    // while the job waited. Same condition from the caller's side, same window.
    if (const auto decision = m_unknownTopicThrottle.record())
    {
        logWarn(WM_CONTENTUPDATER,
                "Rejected %llu on-demand request(s) in the last %d s: unknown topic (last: '%s').",
                static_cast<unsigned long long>(decision.total),
                LogThrottle::DEFAULT_WINDOW_SECONDS,
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
    for (const auto& job : abandoned)
    {
        answer(job, content_manager::OnDemandCode::ShuttingDown, "the on-demand lane is shutting down");
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
        // else.
        logInfo(WM_CONTENTUPDATER,
                "On-demand lane stopped; %zu queued update(s) were rejected.",
                abandoned.size());
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

        // SHARED lock for the whole run: the contract removeEndpoint() builds its "nothing of mine
        // still runs" guarantee on. Blocking here is fine — this is a lane worker, never a
        // transport I/O thread.
        std::shared_lock<std::shared_mutex> lock {m_registryMutex};
        const auto it = m_endpoints.find(job.topic);
        if (it == m_endpoints.end())
        {
            logUnknownTopic(job.topic);
            answer(job, content_manager::OnDemandCode::UnknownTopic, "unknown topic");
            continue;
        }

        try
        {
            const auto result = it->second(job.request);
            if (!result.ran)
            {
                // Coalescing concurrent triggers for one topic is the design working, so this is
                // INFO rather than a warning — but it IS reported, where the pre-lane server used
                // to answer success to a request it had silently dropped.
                if (const auto decision = m_inProgressThrottle.record())
                {
                    logInfo(WM_CONTENTUPDATER,
                            "Refused %llu on-demand request(s) in the last %d s: an update for that topic was "
                            "already running (last: '%s').",
                            static_cast<unsigned long long>(decision.total),
                            LogThrottle::DEFAULT_WINDOW_SECONDS,
                            job.topic.c_str());
                }
                answer(job, content_manager::OnDemandCode::AlreadyRunning, "an update for that topic is running");
                continue;
            }

            const auto failed = result.outcome.status == content_manager::CycleStatus::FailedTransport ||
                                result.outcome.status == content_manager::CycleStatus::FailedSink ||
                                result.outcome.status == content_manager::CycleStatus::FailedConfig;

            answer(job,
                   failed ? content_manager::OnDemandCode::Failed : content_manager::OnDemandCode::Completed,
                   result.outcome.detail);
        }
        catch (const std::exception& e)
        {
            logWarn(WM_CONTENTUPDATER, "On-demand update for '%s' failed: %s", job.topic.c_str(), e.what());
            answer(job, content_manager::OnDemandCode::Failed, e.what());
        }
    }
}
