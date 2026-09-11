/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_SERVICE_HPP
#define _TASK_MANAGER_UPGRADE_SERVICE_HPP

#include "handlers/iHandler.hpp"
#include "upgradeOrchestrator.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace task_manager::upgrade
{
    /**
     * @brief The worker pool that runs upgrade batches off the HTTP I/O threads.
     *
     * WHY THIS EXISTS AT ALL. uds_http_server handlers run inline on an I/O thread and must not
     * block -- one that does head-of-line-blocks every connection sharing its strand, including
     * /v1/tasks/pending, which every agent poller hits. An upgrade batch reads wazuh-db once per
     * agent and may download 100 MB. So the route parks its responder here and returns immediately,
     * and this pool answers when the work is done. The transport supports exactly that: a responder
     * may be retained and called minutes later from any thread.
     *
     * CONCURRENCY IS OVER BATCHES, NOT AGENTS. Per-agent work is one wazuh-db round trip on a
     * mutex-guarded socket plus pure CPU; running agents in parallel would multiply contention on
     * that mutex to buy nothing. What genuinely arrives in parallel is whole requests -- the Server
     * API chunks a fleet at 500 and every cluster node broadcasts -- so that is what the pool sizes
     * for.
     *
     * THE QUEUE IS BOUNDED AND SHEDS. The transport's Control class guarantees the data plane
     * cannot starve these routes; it does NOT bound the work behind them, and its own documentation
     * says a Control route that does real work must shed its own capacity module-side. Over the
     * depth, a request is answered 503 immediately rather than queued behind minutes of downloads.
     */
    class UpgradeService
    {
    public:
        struct Options
        {
            /// @brief Concurrent BATCHES. Default clamp(hardware/2, 1, 4) is applied by the facade.
            int workers {2};
            /// @brief Queued batches before a request is shed. Small: each one is expensive.
            std::size_t queueDepth {8};
        };

        /**
         * @brief @param remotedProvider Called ONCE PER BATCH to read remoted's delivery settings.
         *        A callback rather than a stored copy so that -- if the settings ever become live
         *        again -- only this one line changes.
         */
        UpgradeService(UpgradeOrchestrator& orchestrator,
                       std::function<RemotedSettings()> remotedProvider,
                       Options options);
        ~UpgradeService();

        UpgradeService(const UpgradeService&) = delete;
        UpgradeService& operator=(const UpgradeService&) = delete;

        void start();

        /**
         * @brief Refuse new work, answer everything already accepted, and join.
         *
         * NO RESPONDER IS EVER DROPPED. Dropping one makes the transport answer 503, and the Server
         * API does not treat a 503 the way it treats a per-agent error 4: it raises rather than
         * halving the chunk and retrying, so a shutdown during a fleet upgrade would fail the whole
         * chunk instead of being retried. Everything queued is therefore answered with a
         * well-formed envelope carrying error 4 per agent.
         *
         * In-flight batches are joined without a separate timeout, matching Executor::stop(). The
         * bound is the StopToken, and it is only a real bound because EVERY phase of a batch
         * observes it: between agents, between WPK groups, between download attempts, while queued
         * for a download slot, and inside libcurl's transfer callback. A phase that waited on
         * anything else -- the batch deadline alone, say, at up to three minutes -- would make this
         * join as long as that wait, and modulesd runs every module's stop() under one shared
         * budget. What remains genuinely unbounded is one wazuh-db call, itself capped at ten
         * seconds by the host, and one file digest.
         */
        void stop();

        using ParsedRequest = std::variant<UpgradeRequest, UpgradeCustomRequest>;

        /**
         * @brief Hand a parsed batch to the pool.
         *
         * @return false when the queue is full or the service is stopping; the caller then answers
         *         503 itself and this never takes ownership of the responder.
         */
        bool submit(ParsedRequest request, std::shared_ptr<wazuh::uds_http::IHttpResponder> responder);

        /// @brief Batches waiting for a worker. For metrics.
        std::size_t queueDepth() const;
        /// @brief Batches refused because the queue was full. For metrics.
        std::size_t shedCount() const;

    private:
        struct Job
        {
            ParsedRequest request;
            std::shared_ptr<wazuh::uds_http::IHttpResponder> responder;
        };

        void workerLoop();
        void run(Job& job);
        static void answer(const std::shared_ptr<wazuh::uds_http::IHttpResponder>& responder, const std::string& body);
        static std::vector<int> agentsOf(const ParsedRequest& request);

        UpgradeOrchestrator& m_orchestrator;
        std::function<RemotedSettings()> m_remotedProvider;
        Options m_options;

        mutable std::mutex m_mutex;
        std::condition_variable m_queued;
        std::deque<Job> m_jobs;
        std::vector<std::thread> m_workers;
        bool m_stopping {false};
        std::size_t m_shed {0};

        /// @brief Shared by every in-flight batch, so a shutdown cuts downloads short rather than
        ///        waiting out a 100 MB transfer.
        StopToken m_stopToken;
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_SERVICE_HPP
