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
#include "upgrade/httpWpkRepository.hpp"
#include "upgrade/upgradeApi.hpp"
#include "upgrade/upgradeOrchestrator.hpp"
#include "upgrade/upgradeService.hpp"
#include "upgrade/versionsCache.hpp"
#include "upgrade/wpkCache.hpp"

#include <wazuh_metrics/manager.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
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
        ~TaskManagerFacade()
        {
            stop();
        }

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

            // Anything already built is released before the failure leaves this function. Without
            // it a throw past the first thread-starting step -- and the likeliest failure, the
            // socket bind, is well past all of them -- would leak the executor, scheduler and
            // upgrade threads: `m_running` would still be false, so stop() and the destructor would
            // both take their early return and never join them. See teardownLocked().
            try
            {
                startLocked(config, hostOps);
            }
            catch (...)
            {
                teardownLocked();
                throw;
            }
        }

        void stop()
        {
            std::lock_guard lock {m_mutex};

            if (!m_running)
            {
                return;
            }

            teardownLocked();

            m_running = false;
            LOGFN_INFO(moduleLogFn(), "Task manager stopped.");
        }

    private:
        void startLocked(const task_manager_config_t& config, const task_manager_host_ops_t& hostOps)
        {
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
            m_executor = std::make_unique<execution::Executor>(*m_store, *m_registry, executorOptions, m_metrics);

            // `manager_task_log_rotate` turns BOTH rotations off, and the two are expressed
            // differently: the daily one is a schedule, so it is simply disabled
            // (registry::buildBuiltinSchedules), while the size-triggered one is not a schedule at
            // all -- so turning it off means not registering the action AND not signalling it. One
            // flag decides both, computed once here so the two cannot drift apart. Registering it
            // unconditionally left `rotate_log=0` still rewriting the log at its size threshold,
            // which is not what the option says it does.
            const bool sizeRotationEnabled {config.rotate_log != 0 &&
                                            valueOrAllowingZero(config.size_rotate_mb, 512) > 0};

            if (sizeRotationEnabled)
            {
                m_executor->registerPeriodicAction(registry::makeSizeRotationAction(*m_hostOps, localConfig));
            }

            execution::Sweeper::Options sweeperOptions;
            sweeperOptions.claimGrace = executorOptions.claimGrace;
            m_sweeper =
                std::make_unique<execution::Sweeper>(*m_store, *m_registry, *m_executor, sweeperOptions, m_metrics);

            schedule::Scheduler::Options schedulerOptions;
            schedulerOptions.wakeBackstop = std::chrono::seconds {valueOr(config.wake_backstop, 60)};
            schedulerOptions.sweepInterval = std::chrono::seconds {valueOr(config.sweep_interval, 60)};
            schedulerOptions.cleanupInterval = std::chrono::seconds {valueOr(config.cleanup_interval, 300)};
            schedulerOptions.agentTaskTtl = std::chrono::seconds {valueOr(config.task_ttl, 3600)};
            schedulerOptions.retentionDays = valueOr(config.retention_days, 7);
            schedulerOptions.deadLetterRetentionDays = valueOr(config.dead_letter_retention_days, 30);
            schedulerOptions.historyPerSchedule = valueOr(config.history_per_schedule, 20);
            schedulerOptions.maxRows = valueOr(config.max_rows, 100000);
            schedulerOptions.sizeRotationEnabled = sizeRotationEnabled;

            m_scheduler = std::make_unique<schedule::Scheduler>(*m_store,
                                                                *m_executor,
                                                                *m_sweeper,
                                                                *m_hostOps,
                                                                registry::buildBuiltinSchedules(config),
                                                                schedulerOptions,
                                                                m_metrics);

            m_cache = std::make_unique<cache::PendingCache>();

            // The notification wakes the machinery immediately, which is why a manager task
            // created through the socket starts now rather than at some poll interval -- there is
            // none. Agent tasks get no such callback: nothing here executes them.
            m_api = std::make_unique<http::ApiHandlers>(
                *m_store,
                *m_registry,
                *m_cache,
                [this](const std::string& taskType)
                {
                    m_executor->notify(taskType);
                    m_scheduler->wake();
                },
                m_metrics,
                valueOr(config.max_payload_bytes, 1048576),
                valueOr(config.max_tasks_per_poll, 100));

            m_executor->start();
            m_scheduler->start();

            buildUpgradeSubsystem(config);

            http::HttpServer::Options httpOptions;
            httpOptions.socketPath = config.socket_path;
            httpOptions.ioThreads = valueOr(config.io_threads, 2);
            // The manager-task create route must admit one whole max_payload_bytes, or configuring
            // that option above the transport's 64 KB Control default would silently do nothing.
            // Scoped to that one route rather than the class -- see the field.
            httpOptions.createMaxBodyBytes =
                static_cast<std::size_t>(valueOr(config.max_payload_bytes, 1048576)) + (64UL * 1024);
            m_server = std::make_unique<http::HttpServer>(*m_api, httpOptions);

            if (m_upgradeApi)
            {
                // Before start(): the transport refuses addRoute() once the socket is bound.
                m_server->setUpgradeApi(*m_upgradeApi);
            }

            // Likewise before start(). This is what makes everything metrics/taskMetrics.cpp
            // records readable from outside the process.
            m_server->setMetricsManager(m_metricsManager);

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

        /**
         * @brief Stop and release everything that exists, in the order described on the class.
         *
         * Every step is guarded, because this runs from TWO callers with different amounts built:
         * stop() on a fully started module, and start()'s own failure path on a partly built one.
         *
         * THAT SECOND CALLER IS THE POINT. `m_running` is set on the last line of start(), so a
         * throw anywhere before it -- and the likeliest one by far is the socket bind, which fails
         * on a stale path or a permissions problem -- used to leave `m_running` false with the
         * executor, the scheduler and the upgrade pool already running their threads. stop() would
         * then return immediately on the `!m_running` check and the destructor would call the same
         * no-op, so those threads outlived the object holding what they point at. It was survivable
         * only because the shim answers a failed start with mterror_exit(), which is to say it was
         * masked by the process dying rather than actually handled.
         */
        void teardownLocked()
        {
            if (m_server)
            {
                m_server->stopAccepting();
            }
            // Second, and the position matters at both ends. AFTER stopAccepting(), because until
            // then a new batch can still arrive. BEFORE flushWrites() below, because a batch writes
            // agent tasks through the store and those rows must be in the flushed transaction --
            // and long before m_server->stop(), which is what ends a retained responder's ability
            // to answer at all. Every parked request is answered here; none is dropped.
            //
            // The repository is stopped FIRST so a 100 MB download in flight is cut short rather
            // than waited out; without it the service's join below would block for the remainder of
            // the transfer, well past the shutdown budget modulesd allows every module to share.
            if (m_wpkRepository)
            {
                m_wpkRepository->requestStop();
            }
            if (m_upgradeService)
            {
                m_upgradeService->stop();
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
            // Torn down in construction order reversed: the API points at the service, the service
            // at the orchestrator, and the orchestrator at the caches and the store.
            m_upgradeApi.reset();
            m_upgradeService.reset();
            m_upgradeOrchestrator.reset();
            m_versionsCache.reset();
            m_wpkCache.reset();
            m_wpkRepository.reset();
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
        }

        static int valueOr(const int configured, const int fallback)
        {
            return configured > 0 ? configured : fallback;
        }

        /**
         * @brief Resolve a field whose ZERO is a real setting rather than "no opinion".
         *
         * The ABI's ordinary sentinel is `<= 0`, which works for every value whose domain starts at
         * one. It cannot work for the handful whose zero MEANS something -- "log nothing", "cache
         * nothing", "no bound", "keep no rotated logs" -- because valueOr() would hand each of those
         * straight back the default the operator was trying to turn off.
         *
         * Those fields carry three states, and -1 rather than 0 is the disabling one (see the
         * sentinel note in task_manager.h): 0 still means "no opinion", so a zero-initialised config
         * struct means every default, and the shim maps a configured zero to -1 on the way in.
         *
         * Documented at both ends deliberately: a field read with the wrong helper silently ignores
         * configuration, which is the failure mode this pair exists to make impossible to miss.
         */
        static int valueOrAllowingZero(const int configured, const int fallback)
        {
            if (configured < 0)
            {
                return 0; // The operator asked for zero.
            }
            return configured > 0 ? configured : fallback;
        }

        static std::string stringOr(const char* configured, const char* fallback)
        {
            return (configured != nullptr && configured[0] != '\0') ? configured : fallback;
        }

        /**
         * @brief Build the agent upgrade subsystem: repository client, caches, orchestrator, pool.
         *
         * Constructed AFTER the executor and scheduler and BEFORE the server binds, like everything
         * else that has to be able to serve a request the moment the socket exists.
         *
         * Nothing here is conditional on `upgrade_enabled`. The routes are registered either way and
         * the flag is checked per request, because the retired module expressed "disabled" by never
         * binding its own socket -- and with the socket now shared there is nothing to leave unbound.
         * A disabled module answering every agent with a clear code beats one whose route 404s.
         */
        void buildUpgradeSubsystem(const task_manager_config_t& config)
        {
            upgrade::HttpWpkRepository::Options repositoryOptions;
            repositoryOptions.downloadTimeout =
                std::chrono::milliseconds {valueOr(config.upgrade_download_timeout, 45000)};
            m_wpkRepository = std::make_unique<upgrade::HttpWpkRepository>(repositoryOptions);

            if (!m_wpkRepository->hasCaBundle())
            {
                // Reported once, loudly, rather than per request -- and NOT acted on: verification
                // stays on and HTTPS to the repository will fail closed. The digest a WPK is checked
                // against is fetched over that same channel, so relaxing it would make the integrity
                // check confirm an attacker's work rather than ours.
                LOGFN_WARN(moduleLogFn(),
                           "No CA bundle was found on this host. HTTPS requests to the WPK repository "
                           "will fail; agent upgrades over https are unavailable until one is installed.");
            }

            upgrade::WpkCache::Options wpkOptions;
            wpkOptions.upgradeDir = stringOr(config.upgrade_dir, "var/upgrade/");
            wpkOptions.downloadAttempts = valueOr(config.upgrade_download_attempts, 3);
            wpkOptions.maxConcurrentDownloads = valueOr(config.upgrade_max_concurrent_downloads, 2);
            m_wpkCache = std::make_unique<upgrade::WpkCache>(*m_wpkRepository, wpkOptions);

            // Zero is meaningful here too: it means "fetch every time", which a TTL of zero
            // expresses exactly -- an entry stamped `now + 0` is already expired when it is read.
            m_versionsCache = std::make_unique<upgrade::VersionsCache>(
                *m_wpkRepository, std::chrono::seconds {valueOrAllowingZero(config.upgrade_versions_ttl, 300)});

            upgrade::UpgradeOrchestrator::Options orchestratorOptions;
            orchestratorOptions.configuredRepository = config.wpk_repository;
            orchestratorOptions.managerVersion = config.manager_version;
            orchestratorOptions.upgradeDir = wpkOptions.upgradeDir;
            orchestratorOptions.batchDeadline = std::chrono::seconds {valueOr(config.upgrade_batch_deadline, 180)};
            orchestratorOptions.maxAgents = static_cast<std::size_t>(valueOr(config.upgrade_max_agents, 500));
            // The SAME PendingCache the pending-tasks route reads. A separate one would let an
            // upgrade task be written while the route still believes the agent has nothing.
            m_upgradeOrchestrator = std::make_unique<upgrade::UpgradeOrchestrator>(
                *m_hostOps, *m_store, *m_cache, *m_wpkCache, *m_versionsCache, orchestratorOptions);

            // Copied once here rather than re-read per request: the retired code re-read remoted's
            // configuration once per AGENT, parsing the same file for every agent in a batch.
            upgrade::RemotedSettings remoted;
            remoted.valid = config.remoted_config_read != 0;
            remoted.legacyEnabled = config.remoted_legacy_enabled != 0;
            remoted.verificationMode = config.remoted_verification_mode;

            upgrade::UpgradeService::Options serviceOptions;
            serviceOptions.workers = valueOr(config.upgrade_workers, resolveUpgradeWorkers());
            serviceOptions.queueDepth = static_cast<std::size_t>(valueOr(config.upgrade_queue_depth, 8));
            m_upgradeService = std::make_unique<upgrade::UpgradeService>(
                *m_upgradeOrchestrator, [remoted] { return remoted; }, serviceOptions);
            m_upgradeService->start();

            m_upgradeApi = std::make_unique<upgrade::UpgradeApi>(
                *m_upgradeService,
                [] { return static_cast<Timestamp>(std::time(nullptr)); },
                config.upgrade_enabled != 0);

            if (config.upgrade_enabled == 0)
            {
                LOGFN_INFO(moduleLogFn(),
                           "Agent upgrades are disabled by configuration; the upgrade routes will refuse "
                           "every request.");
            }

            registerUpgradeMetrics();
        }

        /// @brief Half the cores, clamped to [1, 4]. Batches are mostly waiting on one wazuh-db
        ///        socket and one download slot, so more workers buy contention rather than progress.
        static int resolveUpgradeWorkers()
        {
            const auto cores {static_cast<int>(std::thread::hardware_concurrency())};
            return std::max(1, std::min(cores > 0 ? cores / 2 : 1, 4));
        }

        void registerUpgradeMetrics()
        {
            // Pull metrics, like the queue gauges: the counters are already maintained, so reading
            // them on demand costs nothing. Nothing the retired C module could publish at all.
            m_metrics->registerPull(
                "task_manager.upgrade.queue_depth",
                [this] { return m_upgradeService ? static_cast<std::int64_t>(m_upgradeService->queueDepth()) : 0; },
                "Upgrade batches waiting for a worker",
                "batches");

            m_metrics->registerPull(
                "task_manager.upgrade.batches_shed",
                [this] { return m_upgradeService ? static_cast<std::int64_t>(m_upgradeService->shedCount()) : 0; },
                "Upgrade requests refused because the queue was full",
                "requests");

            m_metrics->registerPull(
                "task_manager.upgrade.wpk_downloads",
                [this] { return m_wpkCache ? static_cast<std::int64_t>(m_wpkCache->downloadCount()) : 0; },
                "WPK downloads performed",
                "downloads");

            m_metrics->registerPull(
                "task_manager.upgrade.wpk_cache_hits",
                [this] { return m_wpkCache ? static_cast<std::int64_t>(m_wpkCache->memoHitCount()) : 0; },
                "Upgrade requests answered from an already-verified WPK",
                "requests");

            m_metrics->registerPull(
                "task_manager.upgrade.versions_fetches",
                [this] { return m_versionsCache ? static_cast<std::int64_t>(m_versionsCache->fetchCount()) : 0; },
                "Repository `versions` files fetched",
                "requests");

            m_metrics->registerPull(
                "task_manager.upgrade.versions_cache_hits",
                [this] { return m_versionsCache ? static_cast<std::int64_t>(m_versionsCache->hitCount()) : 0; },
                "Repository `versions` lookups answered from cache",
                "requests");
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
            // Zero is a setting for these three, not an absence: "name no agent individually",
            // "keep no rotated logs", "never rotate by size".
            local.disconnectLogMax = valueOrAllowingZero(config.disconnect_log_max, 200);
            local.compressRotatedLogs = config.compress != 0;
            local.keepLogDays = valueOrAllowingZero(config.keep_log_days, 31);
            local.dailyRotations = valueOr(config.daily_rotations, 12);
            local.sizeRotateBytes = static_cast<long>(valueOrAllowingZero(config.size_rotate_mb, 512)) * 1024 * 1024;
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
        ///
        /// Every getter below checks the member it reads, exactly as the upgrade getters do. The
        /// ordering in stop() already makes that unnecessary -- stopAccepting() comes first and
        /// guarantees no handler is still running before anything is reset -- but a pull metric is
        /// read from an I/O thread the facade does not own, and a getter that assumes an ordering
        /// somebody else maintains is one edit away from a use-after-free.
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
                            return m_store ? static_cast<std::uint64_t>(
                                                 m_store->countManagerTasks(name, TaskStatus::Pending))
                                           : std::uint64_t {0};
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
                [this] { return m_cache ? static_cast<std::uint64_t>(m_cache->size()) : std::uint64_t {0}; },
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

        // The agent upgrade subsystem, declared in dependency order: each of these holds a
        // reference to the one above it, so destruction runs bottom-up and stop() resets them in
        // that order explicitly rather than relying on member order alone.
        std::unique_ptr<upgrade::HttpWpkRepository> m_wpkRepository;
        std::unique_ptr<upgrade::WpkCache> m_wpkCache;
        std::unique_ptr<upgrade::VersionsCache> m_versionsCache;
        std::unique_ptr<upgrade::UpgradeOrchestrator> m_upgradeOrchestrator;
        std::unique_ptr<upgrade::UpgradeService> m_upgradeService;
        std::unique_ptr<upgrade::UpgradeApi> m_upgradeApi;

        std::unique_ptr<http::HttpServer> m_server;
    };
} // namespace task_manager

#endif // _TASK_MANAGER_FACADE_HPP
