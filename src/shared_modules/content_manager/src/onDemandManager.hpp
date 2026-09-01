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

#include "actionOrchestrator.hpp"
#include "singleton.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/logThrottle.hpp>

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Registry and bounded execution lane for on-demand content updates.
 *
 * This used to own a raw cpp-httplib server on its own socket; since the vd-http.sock unification the
 * HTTP surface is ONE route (POST /ondemand) registered by the vulnerability scanner on the
 * shared transport, and this class keeps what was always application-level: the topic registry
 * and -- new -- the lane that runs updates off the transport's I/O threads. An update runs a
 * whole content download, so it must never run inline in a handler; it is queued here (SHORT
 * queue: beyond it the caller gets an explicit retryable 503 instead of the old invisible pile-up
 * in the httplib pool) and answered through the deferred responder when it finishes.
 *
 * Callbacks return bool -- false meaning "an update for this topic is already in progress"
 * (Action's runActionExclusively lost its CAS) -- so the caller finally gets an honest 409 where
 * the old server answered a lying 200.
 *
 * Locking contract, preserved from the old server: a worker holds m_registryMutex SHARED for the
 * whole callback run, so removeEndpoint()'s unique_lock keeps its guarantee that no callback of
 * the removed topic is in flight once it returns (Action's teardown relies on it). Workers are
 * lazily started with the first endpoint and stopped -- OUTSIDE the registry lock, or the join
 * would deadlock against a running callback's shared_lock -- when the last one is removed.
 */
class OnDemandManager final : public Singleton<OnDemandManager>
{
public:
    /**
     * @brief OnDemandManager destructor. Stops the lane and joins its workers.
     */
    ~OnDemandManager();

    /**
     * @brief Register a topic; the lane is started with the first one.
     *
     * @param endpoint Topic name (the old path segment).
     * @param func Update callback; returns false when the topic's update was already running.
     */
    void addEndpoint(const std::string& endpoint, std::function<bool(ActionOrchestrator::UpdateData)> func);

    /**
     * @brief Remove a topic. Blocks until no callback of it is in flight; stops the lane when the
     *        registry empties.
     *
     * @param endpoint Endpoint to remove
     */
    void removeEndpoint(const std::string& endpoint);

    /**
     * @brief Clear every endpoint and stop the lane.
     */
    void clearEndpoints();

    /**
     * @brief Queue one update for @p topic (see contentOnDemand.hpp for the response contract).
     *
     * Non-blocking: rejections (unknown topic, lane full, shutting down) are answered inline.
     */
    void dispatch(const std::string& topic, int offset, std::shared_ptr<wazuh::uds_http::IHttpResponder> responder);

private:
    struct Job
    {
        std::string topic;
        int offset;
        std::shared_ptr<wazuh::uds_http::IHttpResponder> responder;
    };

    /// Short on purpose: an update takes as long as its download, so depth would only accumulate
    /// stale requests -- the caller retries against an explicit 503.
    static constexpr std::size_t QUEUE_SLOTS {4};
    /// Two, preserving the old thread pool's ability to run two different topics' updates
    /// concurrently (same-topic concurrency is already refused by the Action's own CAS -> 409).
    static constexpr std::size_t WORKER_COUNT {2};

    void startWorkersLocked(); ///< Requires m_laneMutex held.
    void stopWorkers();        ///< Must be called WITHOUT m_registryMutex held (joins workers).
    void run();
    void logUnknownTopic(const std::string& topic); ///< Throttled; shared by both 404 paths.

    std::map<std::string, std::function<bool(ActionOrchestrator::UpdateData)>> m_endpoints {};
    std::shared_mutex m_registryMutex {};

    std::mutex m_laneMutex {};
    std::condition_variable m_wake {};
    std::deque<Job> m_queue {};
    bool m_stopping {false};
    std::vector<std::thread> m_workers {};

    /// One window per condition, so a persistent one cannot mask a newly-appearing different
    /// one. NOTE for tests: this manager is a singleton with no reset, so these windows live
    /// for the whole process -- after the first emission a 90 s silence is expected behaviour,
    /// not a lost log line.
    wazuh::uds_http::LogThrottle m_laneFullThrottle {};
    wazuh::uds_http::LogThrottle m_unknownTopicThrottle {};
    wazuh::uds_http::LogThrottle m_inProgressThrottle {};
};

#endif // _ONDEMAND_MANAGER_HPP
