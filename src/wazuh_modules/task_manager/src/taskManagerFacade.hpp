/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_FACADE_HPP
#define _TASK_MANAGER_FACADE_HPP

#include "cache/pendingCache.hpp"
#include "execution/executor.hpp"
#include "execution/sweeper.hpp"
#include "host/cHostOps.hpp"
#include "http/apiHandlers.hpp"
#include "http/httpServer.hpp"
#include "metrics/taskMetrics.hpp"
#include "registry/builtinTypes.hpp"
#include "schedule/scheduler.hpp"
#include "storage/sqliteTaskStore.hpp"
#include "taskManagerLog.hpp"
#include "task_manager.h"

#include <wazuh_metrics/manager.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace task_manager
{
    /**
     * @brief Owns every part of the module and the order they are built and torn down in.
     *
     * CONSTRUCTION ORDER follows the dependency graph: store, then registry (whose handlers need
     * the host ops), then executor, then sweeper, then scheduler, then the HTTP surface last --
     * because the moment the socket is bound, producers can create tasks, and everything that
     * executes them must already exist.
     *
     * TEARDOWN ORDER is not the reverse, and the difference is deliberate:
     *
     *   1. stopAccepting() -- no new requests, and every handler that had started has RETURNED.
     *      The I/O runtime stays alive, so deferred replies can still land.
     *   2. stop the scheduler, so nothing new is spawned or swept.
     *   3. stop the executor, which finishes the task each worker is running and joins.
     *   4. flush the store, making every batched outcome durable.
     *   5. stop() the HTTP server, releasing the runtime.
     *   6. close the store.
     *
     * Doing 5 before 3 would tear down the runtime while a handler might still answer through a
     * responder; doing 4 before 3 would flush a batch the executor is still adding to. In-flight
     * rows are left `claimed` on purpose -- the next boot's startup sweep reclaims them, and every
     * handler is idempotent.
     */
    class TaskManagerFacade
    {
    public:
        TaskManagerFacade() = default;
        ~TaskManagerFacade() { stop(); }

        TaskManagerFacade(const TaskManagerFacade&) = delete;
        TaskManagerFacade& operator=(const TaskManagerFacade&) = delete;

        void start(const task_manager_config_t& config, const task_manager_host_ops_t& hostOps)
        {
            std::lock_guard lock {m_mutex};

            if (m_running)
            {
                LOGFN_WARN(moduleLogFn(), "Ignoring a second start request; the module is already running.");
                return;
            }

            m_hostOps = std::make_unique<host::CHostOps>(hostOps);

            if (const auto missing {m_hostOps->missingOperations()}; !missing.empty())
            {
                // Reported once, here, rather than discovered by a handler hours later. A stale
                // .so paired with a newer modulesd should degrade visibly.
                std::string names;
                for (const auto& name : missing)
                {
                    names += (names.empty() ? "" : ", ") + name;
                }
                LOGFN_WARN(moduleLogFn(),
                           "modulesd did not supply these operations: %s. The work that needs them will be "
                           "skipped.",
                           names.c_str());
            }

            m_metricsManager = std::make_shared<wazuh::metrics::Manager>();
            m_metrics = std::make_shared<metrics::TaskMetrics>(m_metricsManager);

            storage::SqliteTaskStore::Options storeOptions;
            storeOptions.dbPath = config.db_path;
            m_store = std::make_unique<storage::SqliteTaskStore>(std::move(storeOptions));

            const auto localConfig {buildLocalConfig(config)};
            m_registry = std::make_unique<registry::TaskRegistry>(
                registry::buildBuiltinRegistry(config, *m_hostOps, localConfig));

            execution::Executor::Options executorOptions;
            executorOptions.workerCount = resolveWorkerCount(config);
            executorOptions.claimGrace = std::chrono::seconds {valueOr(config.claim_grace, 30)};
            m_executor = std::make_unique<execution::Executor>(
                *m_store, *m_registry, executorOptions, m_metrics);

            m_executor->registerPeriodicAction(
                registry::makeSizeRotationAction(*m_hostOps, localConfig));

            execution::Sweeper::Options sweeperOptions;
            sweeperOptions.claimGrace = executorOptions.claimGrace;
            m_sweeper = std::make_unique<execution::Sweeper>(
                *m_store, *m_registry, *m_executor, sweeperOptions, m_metrics);

            schedule::Scheduler::Options schedulerOptions;
            schedulerOptions.wakeBackstop = std::chrono::seconds {valueOr(config.wake_backstop, 60)};
            schedulerOptions.sweepInterval = std::chrono::seconds {valueOr(config.sweep_interval, 60)};
            schedulerOptions.cleanupInterval = std::chrono::seconds {valueOr(config.cleanup_interval, 300)};
            schedulerOptions.agentTaskTtl = std::chrono::seconds {valueOr(config.task_ttl, 3600)};
            schedulerOptions.retentionDays = valueOr(config.retention_days, 7);
            schedulerOptions.deadLetterRetentionDays = valueOr(config.dead_letter_retention_days, 30);
            schedulerOptions.historyPerSchedule = valueOr(config.history_per_schedule, 20);
            schedulerOptions.maxRows = valueOr(config.max_rows, 100000);

            m_scheduler = std::make_unique<schedule::Scheduler>(*m_store,
                                                                *m_executor,
                                                                *m_sweeper,
                                                                *m_hostOps,
                                                                registry::buildBuiltinSchedules(config),
                                                                schedulerOptions,
                                                                m_metrics);

            m_cache = std::make_unique<cache::PendingCache>();

            // Both notifications wake the machinery immediately, which is why a task created
            // through the socket starts now rather than at some poll interval -- there is none.
            m_api = std::make_unique<http::ApiHandlers>(
                *m_store,
                *m_registry,
                *m_cache,
                [this](const std::string& taskType)
                {
                    m_executor->notify(taskType);
                    m_scheduler->wake();
                },
                [](const std::string&) {},
                m_metrics,
                valueOr(config.max_payload_bytes, 1048576),
                valueOr(config.max_tasks_per_poll, 100));

            m_executor->start();
            m_scheduler->start();

            http::HttpServer::Options httpOptions;
            httpOptions.socketPath = config.socket_path;
            httpOptions.ioThreads = valueOr(config.io_threads, 2);
            m_server = std::make_unique<http::HttpServer>(*m_api, httpOptions);

            // Bound LAST. Everything that executes a task must exist before a producer can create
            // one.
            m_server->start();
            m_server->registerDiagnostics(*m_metrics);

            registerQueueMetrics();

            m_running = true;
            LOGFN_INFO(moduleLogFn(),
                       "Task manager started: %d executor workers, database '%s'",
                       executorOptions.workerCount,
                       config.db_path);
        }

        void stop()
        {
            std::lock_guard lock {m_mutex};

            if (!m_running)
            {
                return;
            }

            if (m_server)
            {
                m_server->stopAccepting();
            }
            if (m_scheduler)
            {
                m_scheduler->stop();
            }
            if (m_executor)
            {
                m_executor->stop();
            }
            if (m_store)
            {
                m_store->flushWrites();
            }
            if (m_server)
            {
                m_server->stop();
            }

            m_server.reset();
            m_api.reset();
            m_cache.reset();
            m_scheduler.reset();
            m_sweeper.reset();
            m_executor.reset();
            m_registry.reset();
            m_store.reset();
            m_metrics.reset();
            m_metricsManager.reset();
            m_hostOps.reset();

            m_running = false;
            LOGFN_INFO(moduleLogFn(), "Task manager stopped.");
        }

    private:
        static int valueOr(const int configured, const int fallback)
        {
            return configured > 0 ? configured : fallback;
        }

        static int resolveWorkerCount(const task_manager_config_t& config)
        {
            if (config.executor_threads > 0)
            {
                return config.executor_threads;
            }

            // Enough to keep the deletion group's cap of four busy while a scan and a periodic
            // type run alongside, without one thread per type. The retired implementation ran six
            // lane threads plus a scheduler plus eight socket workers; this is the whole executor.
            const auto hardware {static_cast<int>(std::thread::hardware_concurrency())};
            return std::max(2, std::min(hardware > 0 ? hardware : 4, 8));
        }

        static handlers::LocalConfig buildLocalConfig(const task_manager_config_t& config)
        {
            handlers::LocalConfig local;
            local.disconnectionTime = std::chrono::seconds {valueOr(config.disconnection_time, 900)};
            local.deleteOldAgents = config.delete_old_agents;
            local.monitorAgents = config.monitor_agents != 0;
            local.disconnectLogMax = valueOr(config.disconnect_log_max, 200);
            local.compressRotatedLogs = config.compress != 0;
            local.keepLogDays = valueOr(config.keep_log_days, 31);
            local.dailyRotations = valueOr(config.daily_rotations, 12);
            local.sizeRotateBytes = static_cast<long>(valueOr(config.size_rotate_mb, 512)) * 1024 * 1024;
            local.deleteOldBatch = valueOr(config.delete_old_batch, 200);
            local.deleteOldBudget = std::chrono::seconds {valueOr(config.delete_old_budget, 30)};
            local.authdTimeout = std::chrono::seconds {valueOr(config.wdb_timeout, 10)};
            return local;
        }

        /// @brief Queue depth per type, and the negative cache's size, as pull metrics.
        ///
        /// This is the half of the picture the retired implementation could not publish at all:
        /// wazuh_metrics is C++ with no C ABI, so a plain-C module could only ever report what
        /// wazuh-db counted, which described the database rather than the queue.
        void registerQueueMetrics()
        {
            for (const auto& descriptor : m_registry->all())
            {
                const auto name {descriptor.name};
                m_metrics->registerPull(
                    "task_manager.queue.pending." + name,
                    [this, name]
                    {
                        try
                        {
                            return static_cast<std::uint64_t>(
                                m_store->countManagerTasks(name, TaskStatus::Pending));
                        }
                        catch (const std::exception&)
                        {
                            return std::uint64_t {0};
                        }
                    },
                    "Pending manager tasks of type " + name,
                    "tasks");
            }

            m_metrics->registerPull(
                "task_manager.agent_tasks.empty_cache_entries",
                [this] { return static_cast<std::uint64_t>(m_cache->size()); },
                "Agents known to have no pending agent tasks",
                "agents");
        }

        std::mutex m_mutex;
        bool m_running {false};

        std::unique_ptr<host::CHostOps> m_hostOps;
        std::shared_ptr<wazuh::metrics::Manager> m_metricsManager;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;
        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::unique_ptr<registry::TaskRegistry> m_registry;
        std::unique_ptr<execution::Executor> m_executor;
        std::unique_ptr<execution::Sweeper> m_sweeper;
        std::unique_ptr<schedule::Scheduler> m_scheduler;
        std::unique_ptr<cache::PendingCache> m_cache;
        std::unique_ptr<http::ApiHandlers> m_api;
        std::unique_ptr<http::HttpServer> m_server;
    };
} // namespace task_manager

#endif // _TASK_MANAGER_FACADE_HPP
