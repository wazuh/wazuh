/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
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

#include <optional>
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
    // Serialised against clearEndpoints(): otherwise a topic registered while the lane is being
    // stopped would see the workers still up, start none, and then be left with none at all.
    std::lock_guard<std::mutex> lifecycle {m_lifecycleMutex};
    {
        std::lock_guard<std::mutex> lock {m_registryMutex};
        if (m_endpoints.find(endpoint) != m_endpoints.end())
        {
            throw std::runtime_error("Endpoint already exists");
        }
        m_endpoints[endpoint] = std::make_shared<Endpoint>(Endpoint {std::move(func), 0});
    }

    // Lazily bring the lane up with the first topic (or again after clearEndpoints()).
    std::lock_guard<std::mutex> laneLock {m_laneMutex};
    startWorkersLocked();
}

void OnDemandManager::removeEndpoint(const std::string& endpoint)
{
    std::unique_lock<std::mutex> lock {m_registryMutex};
    const auto it = m_endpoints.find(endpoint);
    if (it == m_endpoints.end())
    {
        return;
    }

    // Erased first, so no worker can start a new run of it; then wait for the runs already started.
    // That is the guarantee topic teardown (~Action) relies on: once this returns, no callback of
    // the removed topic is in flight. Only this topic's runs are waited for -- an update of another
    // topic, however long, does not hold this up.
    const auto removed = it->second;
    m_endpoints.erase(it);
    m_idle.wait(lock, [&removed]() { return removed->inFlight == 0; });

    // The workers are deliberately left running when the registry empties. Stopping them here
    // would race a concurrent addEndpoint(), which could see them up and start none; they are idle
    // threads, stopped by clearEndpoints() or the destructor.
}

void OnDemandManager::clearEndpoints()
{
    std::lock_guard<std::mutex> lifecycle {m_lifecycleMutex};
    {
        std::lock_guard<std::mutex> lock {m_registryMutex};
        m_endpoints.clear();
    }
    // Joins the workers, so every run already started has finished when this returns.
    stopWorkers();
}

void OnDemandManager::dispatch(const std::string& topic,
                               content_manager::RunRequest request,
                               std::function<void(content_manager::OnDemandResult)> completion)
{
    Job job {topic, request, std::move(completion)};

    // The completion is owed exactly once. Every early return answers it, and a successful enqueue
    // moves it into the queue (and empties `job`, so answer() below is a no-op); anything that throws
    // in between (a lock, the deque growing) would otherwise drop it, and an HTTP caller waiting on it
    // would hang until its own timeout.
    try
    {
        {
            // Unknown topics are answered inline: no queue slot is spent on a request that can never
            // run. The authoritative lookup still happens in the worker, since the topic can be removed
            // while the job waits.
            bool known = false;
            {
                std::lock_guard<std::mutex> lock {m_registryMutex};
                known = m_endpoints.find(topic) != m_endpoints.end();
            }
            if (!known)
            {
                logUnknownTopic(topic);
                answer(job, content_manager::OnDemandCode::UnknownTopic, "unknown topic");
                return;
            }
        }

        // Every completion below is invoked with no lock held: a completion may dispatch the next
        // update itself, and doing that under m_laneMutex would deadlock on it.
        auto stopping = false;
        auto laneFull = false;
        {
            std::lock_guard<std::mutex> lock {m_laneMutex};
            stopping = m_stopping || m_workers.empty();
            laneFull = !stopping && m_queue.size() >= QUEUE_SLOTS;
            if (!stopping && !laneFull)
            {
                m_queue.push_back(std::move(job));
                job.completion = nullptr; // Owned by the queue now; a moved-from function is unspecified.
            }
        }

        if (stopping)
        {
            // Not logged per request: shutdown is bounded and stopWorkers() reports what it shed.
            answer(job, content_manager::OnDemandCode::ShuttingDown, "the on-demand lane is shutting down");
            return;
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
    }
    catch (...)
    {
        answer(job, content_manager::OnDemandCode::Failed, "the on-demand request could not be queued");
        throw;
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
        logInfo(WM_CONTENTUPDATER, "On-demand lane stopped; %zu queued update(s) were rejected.", abandoned.size());
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

        // The registry lock is held only to find the topic and count this run in -- never across
        // the run itself. A download takes minutes, and holding it would make every registration
        // and removal in the process wait for every update in flight, of any topic.
        // removeEndpoint() keeps its guarantee through the count instead: it erases the topic, then
        // waits for this topic's count to reach zero.
        std::shared_ptr<Endpoint> endpoint;
        {
            std::lock_guard<std::mutex> lock {m_registryMutex};
            if (const auto it = m_endpoints.find(job.topic); it != m_endpoints.end())
            {
                endpoint = it->second;
                ++endpoint->inFlight;
            }
        }
        if (!endpoint)
        {
            logUnknownTopic(job.topic);
            answer(job, content_manager::OnDemandCode::UnknownTopic, "unknown topic");
            continue;
        }

        RunResult result;
        std::optional<std::string> error;
        try
        {
            result = endpoint->func(job.request);
        }
        catch (const std::exception& e)
        {
            error = e.what();
        }
        catch (...)
        {
            // A host callback can throw anything; letting it escape would terminate the process.
            error = "unknown exception";
        }

        {
            std::lock_guard<std::mutex> lock {m_registryMutex};
            --endpoint->inFlight;
        }
        m_idle.notify_all();

        if (error.has_value())
        {
            logWarn(WM_CONTENTUPDATER, "On-demand update for '%s' failed: %s", job.topic.c_str(), error->c_str());
            answer(job, content_manager::OnDemandCode::Failed, *error);
            continue;
        }

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
}
