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

#ifndef _ONDEMAND_MANAGER_HPP
#define _ONDEMAND_MANAGER_HPP

#include "contentOnDemand.hpp"
#include "contentTypes.hpp"
#include "logThrottle.hpp"
#include "singleton.hpp"

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Registry and bounded execution lane for on-demand content updates.
 *
 * An update runs a whole content download, so it must never run inline on whatever thread asked for
 * it; it is queued here — on a deliberately SHORT queue, because depth would only accumulate stale
 * requests — and its completion callback is invoked when it finishes.
 *
 * The lane used to answer through a `uds_http` responder, which tied this library to one transport
 * that only one of its hosts uses. It now answers through a plain `std::function`, and the HTTP
 * mapping lives next to each host's route. Nothing else about the lane changed.
 *
 * Locking contract, unchanged and depended upon: a worker holds `m_registryMutex` SHARED for the
 * whole callback run, so `removeEndpoint`'s unique lock keeps its guarantee that no callback of the
 * removed topic is in flight once it returns — which is exactly what `~Action` relies on, and what
 * makes it safe for a host to add and remove topics at runtime. Workers start lazily with the first
 * endpoint and stop — OUTSIDE the registry lock, or the join would deadlock against a running
 * callback's shared lock — when the last one is removed.
 */
class OnDemandManager final : public Singleton<OnDemandManager>
{
public:
    /// What a registered topic's update callback reports back.
    struct RunResult
    {
        bool ran {false};                      ///< False when an update for that topic was already running.
        content_manager::CycleOutcome outcome; ///< What the cycle did, when it ran.
    };

    /// A registered topic's update callback.
    using UpdateFunction = std::function<RunResult(content_manager::RunRequest)>;

    /**
     * @brief Stop the lane and join its workers.
     */
    ~OnDemandManager();

    /**
     * @brief Register a topic; the lane is started with the first one.
     *
     * @param endpoint Topic name.
     * @param func Update callback.
     * @throws std::runtime_error if the topic is already registered.
     */
    void addEndpoint(const std::string& endpoint, UpdateFunction func);

    /**
     * @brief Remove a topic.
     *
     * Blocks until no callback of it is in flight; stops the lane when the registry empties.
     *
     * @param endpoint Topic name.
     */
    void removeEndpoint(const std::string& endpoint);

    /**
     * @brief Remove every topic and stop the lane.
     */
    void clearEndpoints();

    /**
     * @brief Queue one update.
     *
     * Non-blocking: rejections are answered inline through @p completion.
     *
     * @param topic Topic name.
     * @param request What the update should do.
     * @param completion Invoked exactly once with the outcome. May be empty.
     */
    void dispatch(const std::string& topic,
                  content_manager::RunRequest request,
                  std::function<void(content_manager::OnDemandResult)> completion);

private:
    struct Job
    {
        std::string topic;
        content_manager::RunRequest request;
        std::function<void(content_manager::OnDemandResult)> completion;
    };

    /// Short on purpose: an update takes as long as its download, so depth would only accumulate
    /// stale requests — the caller retries against an explicit rejection instead.
    static constexpr std::size_t QUEUE_SLOTS {4};
    /// Two, so two different topics' updates can run concurrently. Same-topic concurrency is
    /// already refused by the topic's own exclusivity check.
    static constexpr std::size_t WORKER_COUNT {2};

    void startWorkersLocked(); ///< Requires m_laneMutex held.
    void stopWorkers();        ///< Must be called WITHOUT m_registryMutex held (joins workers).
    void run();
    void logUnknownTopic(const std::string& topic); ///< Throttled; shared by both 404 paths.

    static void answer(const Job& job, content_manager::OnDemandCode code, std::string detail);

    std::map<std::string, UpdateFunction> m_endpoints {};
    std::shared_mutex m_registryMutex {};

    std::mutex m_laneMutex {};
    std::condition_variable m_wake {};
    std::deque<Job> m_queue {};
    bool m_stopping {false};
    std::vector<std::thread> m_workers {};

    /// One window per condition, so a persistent one cannot mask a newly-appearing different one.
    /// NOTE for tests: this manager is a singleton with no reset, so these windows live for the
    /// whole process — after the first emission a 90 s silence is expected behaviour, not a lost
    /// log line.
    LogThrottle m_laneFullThrottle {};
    LogThrottle m_unknownTopicThrottle {};
    LogThrottle m_inProgressThrottle {};
};

#endif // _ONDEMAND_MANAGER_HPP
