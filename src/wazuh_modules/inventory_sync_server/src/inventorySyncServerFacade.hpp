/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SERVER_FACADE_HPP
#define _INVENTORY_SYNC_SERVER_FACADE_HPP

#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "common/clusterIdentity.hpp"
#include "common/metricNames.hpp"
#include "common/socketPathCheck.hpp"
#include "endpoints/configEndpoint.hpp"
#include "endpoints/deleteAgentEndpoint.hpp"
#include "endpoints/metricsEndpoint.hpp"
#include "endpoints/statsEndpoint.hpp"
#include "endpoints/syncEndpoint.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "http_server/udsHttpServerConfig.hpp"
#include "http_server/udsHttpServerFactory.hpp"
#include "indexer/IIndexerConnectorAsync.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/IIndexerSession.hpp"
#include "indexer/indexerConnectorAsyncAdapter.hpp"
#include "indexer/indexerConnectorConfig.hpp"
#include "indexer/indexerConnectorSyncAdapter.hpp"
#include "indexer/indexerSessionAdapter.hpp"
#include "inventory_sync_server.h"
#include "loggerHelper.h"
#include "proc.hpp"
#include "singleton.hpp"
#include "sync/syncPipeline.hpp"
#include "vd/IVdScanner.hpp"
#include "vd/agentInFlightRegistry.hpp"
#include "vd/serverScanCoordinator.hpp"
#include "vd/vdScanLane.hpp"
#include "vd/vdScannerFactory.hpp"

#include <wazuh_metrics/manager.hpp>

#include <functional>
#include <json.hpp>

namespace invsync
{

    /// Tag used for this module's logging. A literal rather than modulesd's ARGV0, matching how
    /// inventory_sync's C++ side does it -- and deliberately distinct from `:inventory-sync` so an
    /// operator can tell the two modules apart in wazuh-manager.log while both are running.
    constexpr auto INVENTORY_SYNC_SERVER_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server"};

    /*
     * Distinct tags for the three indexer objects, so their own log lines can be told apart. Passing
     * one shared tag would make the session's, the sync connector's and the async connector's output
     * indistinguishable, which matters most exactly when one of them is misbehaving.
     *
     * The `:suffix` form is load-bearing: LogFn::compose() truncates from the first '(', so a
     * parenthesised suffix would be discarded, while a colon survives. These end up rendered as
     * "...:inventory-sync-server:indexer(indexer-connector)" and so on.
     */
    constexpr auto INVENTORY_SYNC_SERVER_SESSION_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:indexer"};
    constexpr auto INVENTORY_SYNC_SERVER_SYNC_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:sync"};
    constexpr auto INVENTORY_SYNC_SERVER_ASYNC_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:async"};

    /// Not a member: LogFn has hidden ELF visibility (loggerHelper.h wraps everything in a
    /// visibility pragma), so holding one as a field of a default-visibility class trips
    /// -Wattributes. A function-local static also costs one allocation ever instead of one per
    /// log call.
    inline const LogFn& moduleLogFn()
    {
        static const LogFn instance {INVENTORY_SYNC_SERVER_LOGTAG};
        return instance;
    }

    /// Heartbeat period for the worker loop; also the retry period for a failed server start.
    constexpr auto INVENTORY_SYNC_SERVER_HEARTBEAT_SECS {60};

    /// Pipeline queue byte cap when 'inventory_sync_server_sync_queue_bytes' has no opinion.
    constexpr std::size_t DEFAULT_SYNC_QUEUE_BYTES {64U * 1024U * 1024U};
    /// Group-commit flush threshold fallback; mirrors the sync connector's own max_bulk_size default.
    constexpr std::size_t DEFAULT_BULK_FLUSH_BYTES {10U * 1024U * 1024U};
    /// Retry-After fallback for rejected vulnerability-detection sessions (D17).
    constexpr int DEFAULT_VD_RETRY_AFTER_SECS {60};
    /// The demoted flush timer of the pipeline's connectors -- see the overlay in
    /// tryStartHttpServer() for why this is a correctness requirement rather than tuning.
    constexpr int PIPELINE_CONNECTOR_FLUSH_INTERVAL_SECS {3600};
    /// VD scan lane worker fallback: 1 until the scanner gains real scan parallelism (its global
    /// mutex serializes scans anyway -- REQ-VDQ-7).
    constexpr std::size_t DEFAULT_VD_WORKERS {1};

    /**
     * @brief RocksDB store path, RESERVED for the ingestion pipeline. Nothing opens it yet.
     *
     * Hyphenated on purpose: the retired legacy module recursively removed `queue/inventory_sync`
     * at startup, and an underscored `queue/inventory_sync_server` would have matched an
     * `inventory_sync*` glob. The hyphenated form stays so upgraded installs never collide with
     * that leftover directory.
     */
    [[maybe_unused]] constexpr auto INVENTORY_SYNC_SERVER_STORE_PATH {"queue/inventory-sync-server"};

    /**
     * @brief Internal engine of the inventory_sync_server module.
     *
     * Owns the worker std::thread and implements the canonical cooperative-shutdown lifecycle
     * (atomic flag + condition_variable + join), plus the HTTP-over-UDS transport behind our own
     * IUdsHttpServer interface.
     */
    class InventorySyncServerFacade final : public Singleton<InventorySyncServerFacade>
    {
    public:
        bool start(const std::function<void(
                       const int, const char*, const char*, const int, const char*, const char*, va_list)>& logFunction,
                   const inventory_sync_server_config_t& configuration,
                   nlohmann::json indexerConfig)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);

            // Route the module's LOGFN_* calls back through modulesd's logger.
            Log::assignLogFunction(logFunction);

            if (m_running)
            {
                LOGFN_WARN(moduleLogFn(), "inventory sync server already started, ignoring start request.");
                return true;
            }

            {
                // Before anything is allocated or spawned: an unusable socket path means this module can
                // never serve, and modulesd must not come up pretending inventory ingress exists.
                const auto resolved = invsync::http::buildServerConfig(configuration);
                std::string reason;
                if (!invsync::common::socketPathIsUsable(resolved.socketPath, reason))
                {
                    LOGFN_ERROR(moduleLogFn(),
                                "The inventory sync server cannot use its socket path '%s': %s. This path is fixed, "
                                "not configurable.",
                                resolved.socketPath.c_str(),
                                reason.c_str());
                    return false;
                }
            }

            m_config = configuration;
            m_indexerConfig = std::move(indexerConfig);
            m_logFunction = logFunction;
            m_stopping = false;
            // Fresh escalation state for this run: a stale count carried over from a previous
            // start()/stop() cycle would desync reportFailedStart()'s "first attempt" ERROR branch
            // from what is actually the first failure THIS time.
            //
            // Safe to touch without m_attemptMutex, which the attempt path holds: the worker thread
            // does not exist yet at this point, and the previous cycle's worker was joined by stop().
            // Taking m_attemptMutex here would invert the documented lock order and could deadlock.
            m_failedStartAttempts = 0;
            m_lastIndexerAvailable.reset();
            ++m_startGeneration;

            LOGFN_INFO(moduleLogFn(), "Starting inventory sync server (cluster='%s').", m_config.cluster_name);

            // The UDS server itself is started from run() (see tryStartHttpServer()), which keeps
            // start() fast and gives the retry loop for free. m_running is set only AFTER the
            // thread exists: set first, a throwing std::thread constructor would leave the facade
            // claiming to run with no worker, permanently wedged behind the guard above.
            try
            {
                m_worker = std::thread(&InventorySyncServerFacade::run, this);
            }
            catch (const std::exception& e)
            {
                LOGFN_ERROR(moduleLogFn(), "Could not launch the inventory sync server worker thread: %s.", e.what());
                throw;
            }

            m_running = true;
            return true;
        }

        void stop()
        {
            std::thread workerToJoin;

            {
                std::lock_guard<std::mutex> lock(m_lifecycleMutex);

                if (!m_running)
                {
                    return;
                }

                // NOTE: this runs from modulesd's signal handler, which calls every module's stop()
                // sequentially before joining them all under one shared 30 s budget. Nothing here
                // may block on I/O, and the transport's own drain window is deliberately short for
                // the same reason.
                LOGFN_INFO(moduleLogFn(), "Stopping inventory sync server.");

                // Phase 1: stop ACCEPTING. After this returns no route handler will run again, but
                // the transport's I/O runtime is deliberately still alive so a response for a
                // request already handed off can still be delivered.
                if (m_httpServer)
                {
                    m_httpServer->stopAccepting();
                }

                // Phase 2: tear down the pipeline, the connectors and the session, in REVERSE
                // construction order. The pipeline goes FIRST -- its workers stage into the
                // connectors, and stop() joins them (answering 503 to whatever was queued, WITHOUT
                // waiting on indexer I/O), so by the time the connectors reset nothing touches
                // them. All unconditional: the gate can legitimately leave only some of them
                // built, and each carries live background threads from construction, so gating one
                // reset on another's pointer would leak those threads. The endpoint handlers hold
                // the pipeline and the connectors WEAKLY (see their makeHandler()) precisely so
                // these resets stay destructive and the teardown stays ordered here.
                if (m_scanCoordinator)
                {
                    // Out of the scanner's registry FIRST, so no feed-update call races the lane
                    // teardown below (a call already in flight degrades on the weak lane pointer).
                    vd_sync::ScanCoordinatorRegistry::instance().remove(m_scanCoordinator);
                    m_scanCoordinator.reset();
                }
                if (m_vdScanLane)
                {
                    m_vdScanLane->stop();
                }
                m_vdScanLane.reset();
                m_vdScanner.reset();
                if (m_syncPipeline)
                {
                    m_syncPipeline->stop();
                }
                m_syncPipeline.reset();
                // AFTER both lanes are joined and reset: their registry listeners capture `this`
                // of the objects just destroyed, and the next start() must register fresh ones on
                // a fresh registry -- reusing this one would accumulate dangling closures that the
                // first release of the new cycle would invoke.
                m_agentRegistry.reset();
                m_indexerConnectorAsync.reset();
                m_indexerConnectorSync.reset();
                m_indexerSession.reset();

                // Phase 3: now it is safe to release the I/O runtime. Any responder still
                // outstanding is force-closed, and a late send() becomes a well-defined no-op.
                m_httpServer.reset();

                {
                    std::lock_guard<std::mutex> waitLock(m_waitMutex);
                    m_stopping = true;
                }
                m_waitCv.notify_all();

                workerToJoin = std::move(m_worker);
                m_running = false;
            }

            // Join outside the lifecycle lock so a concurrent start() can't deadlock. Guarded: if
            // join() threw with the thread still joinable, ~thread at end of scope would be
            // std::terminate -- before the C-ABI's own catch could ever run.
            if (workerToJoin.joinable())
            {
                try
                {
                    workerToJoin.join();
                }
                // LCOV_EXCL_START -- join() throws only for deadlock/invalid-handle programming
                // errors; there is no way to stage one without corrupting the thread object
                catch (const std::exception& e)
                {
                    LOGFN_ERROR(moduleLogFn(), "Could not join the inventory sync server worker: %s.", e.what());
                    try
                    {
                        workerToJoin.detach();
                    }
                    catch (...)
                    {
                    }
                }
                // LCOV_EXCL_STOP
            }

            LOGFN_INFO(moduleLogFn(), "inventory sync server stopped.");
        }

        /*
         * Factories for the three indexer objects the gate builds, in order. The default, production
         * values construct the real adapters; tests substitute fakes so the gate can be exercised
         * without the real per-host health-check I/O.
         *
         * Three separate factories rather than one bundle: a gate test needs to fail exactly one of
         * the three while leaving the others healthy, which requires overriding them independently.
         */
        using IndexerSessionFactory =
            std::function<std::unique_ptr<invsync::indexer::IIndexerSession>(const nlohmann::json&, LoggingContext)>;
        using IndexerConnectorSyncFactory = std::function<std::unique_ptr<invsync::indexer::IIndexerConnectorSync>(
            const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)>;
        using IndexerConnectorAsyncFactory = std::function<std::unique_ptr<invsync::indexer::IIndexerConnectorAsync>(
            const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)>;
        /// Builds the scan lane's seam over the vulnerability scanner; tests substitute a fake so
        /// the D22 gating can be pinned without a CVE feed.
        using VdScannerFactory = std::function<std::shared_ptr<invsync::vd::IVdScanner>()>;

        /**
         * @brief TEST-ONLY. Override how the shared indexer session is constructed.
         *
         * Never called in production -- modulesd only ever calls start()/stop(). Exists so a test can
         * drive the startup gate deterministically, without waiting on the real session's per-host
         * health checks (5 s timeout each).
         */
        void setIndexerSessionFactoryForTests(IndexerSessionFactory factory)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            m_indexerSessionFactory = std::move(factory);
        }

        /// TEST-ONLY. Override how the sync indexer connector is constructed. See above.
        void setIndexerConnectorSyncFactoryForTests(IndexerConnectorSyncFactory factory)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            m_indexerConnectorSyncFactory = std::move(factory);
        }

        /// TEST-ONLY. Override how the async indexer connector is constructed. See above.
        void setIndexerConnectorAsyncFactoryForTests(IndexerConnectorAsyncFactory factory)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            m_indexerConnectorAsyncFactory = std::move(factory);
        }

        /// TEST-ONLY. Override the scan lane's scanner seam. See above.
        void setVdScannerFactoryForTests(VdScannerFactory factory)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            m_vdScannerFactory = std::move(factory);
        }

        /// TEST-ONLY. Forces one retry attempt synchronously instead of waiting out the real 60 s
        /// heartbeat. Never called in production.
        void forceRetryForTests()
        {
            tryStartHttpServer();
        }

        /// TEST-ONLY. Runs one indexer-health poll synchronously, as the worker's heartbeat would.
        void pollIndexerHealthForTests()
        {
            logIndexerHealthTransition();
        }

    private:
        void startHttpServer(const invsync::http::UdsHttpServerConfig& config)
        {
            m_httpServer = invsync::http::makeUdsHttpServer();

            // Liveness probe. Exempt from the in-flight byte budget so it keeps answering under
            // memory pressure -- which is exactly when someone is most likely to be probing it.
            m_httpServer->addRoute(
                invsync::http::Method::Get,
                "/",
                [](std::shared_ptr<const invsync::http::HttpRequest>,
                   std::shared_ptr<invsync::http::IHttpResponder> responder)
                {
                    responder->send(
                        invsync::http::HttpResponse::json(200, R"({"status":"ok","module":"inventory_sync_server"})"));
                },
                /*countAgainstBudget=*/false);

            // The endpoint handlers take their dependencies WEAKLY (the shared_ptr members convert
            // to the weak_ptr fields implicitly) -- see stop()'s phase 2 for why that matters. Safe
            // to read the members here: buildAndPublish() publishes each slot as soon as it
            // succeeds, and this runs afterwards, in the same attempt.
            //
            // It also takes this manager's cluster identity, built fresh (a cheap string copy)
            // rather than cached across retries -- m_config does not change within a start()/stop()
            // cycle, so there is nothing stale to worry about, and this keeps startHttpServer() the
            // only place that reads m_config for the routes it registers.
            const auto clusterIdentity = invsync::common::buildClusterIdentity(m_config);
            if (clusterIdentity.sanitized)
            {
                // Once, here, instead of once per request: this name is stamped onto every
                // enriched document, so invalid UTF-8 in it is the manager's fault, not the agent's.
                LOGFN_WARN(moduleLogFn(),
                           "The configured cluster name contains bytes that are not valid UTF-8; they have been "
                           "replaced with '?' so documents can still be serialized. Fix <cluster><name> in the "
                           "manager configuration.");
            }

            // The ingestion route: everything past the strand-side validation runs on the
            // pipeline, or on the VD scan lane for vulnerability-detection data sessions.
            m_httpServer->addRoute(
                invsync::endpoints::sync::method(),
                invsync::endpoints::sync::path(),
                invsync::endpoints::sync::makeHandler(invsync::endpoints::sync::Dependencies {
                    m_syncPipeline,
                    m_indexerConnectorSync,
                    clusterIdentity,
                    m_config.vd_feed_retry_after_seconds > 0 ? m_config.vd_feed_retry_after_seconds
                                                             : DEFAULT_VD_RETRY_AFTER_SECS,
                    m_vdScanLane,
                    m_vdScanner,
                    invsync::metrics::RequestCounters::make(*m_metricsManager),
                    m_metricsManager->getOrCreateCounter(invsync::metrics::VD_RETRY_AFTER_TOTAL,
                                                         "503 responses carrying a Retry-After header",
                                                         "count")}));

            // Reached through remoted's authenticated /stats and /config routes. Registered separately
            // rather than sharing one handler because their real payloads will diverge.
            m_httpServer->addRoute(invsync::endpoints::stats::method(),
                                   invsync::endpoints::stats::path(),
                                   invsync::endpoints::stats::makeHandler(m_indexerConnectorAsync, clusterIdentity));

            m_httpServer->addRoute(invsync::endpoints::config::method(),
                                   invsync::endpoints::config::path(),
                                   invsync::endpoints::config::makeHandler(m_indexerConnectorAsync, clusterIdentity));

            // Whole-agent deletion (design doc 04): UDS-local, deferred to the agent's pipeline
            // shard. Registered on the canonical DELETE and on a POST alias with the SAME handler
            // -- authd's C-side HTTP helper (uhttp_*) only speaks POST.
            {
                const invsync::endpoints::delete_agent::Dependencies deleteDeps {m_syncPipeline,
                                                                                 m_indexerConnectorSync};
                m_httpServer->addRoute(invsync::endpoints::delete_agent::method(),
                                       invsync::endpoints::delete_agent::path(),
                                       invsync::endpoints::delete_agent::makeHandler(deleteDeps));
                m_httpServer->addRoute(invsync::endpoints::delete_agent::altMethod(),
                                       invsync::endpoints::delete_agent::altPath(),
                                       invsync::endpoints::delete_agent::makeHandler(deleteDeps));
            }

            // The D18 statistics dump. Budget-exempt like the health probe: reading metrics is
            // most valuable exactly when the byte budget is under pressure.
            m_httpServer->addRoute(invsync::endpoints::metrics::method(),
                                   invsync::endpoints::metrics::path(),
                                   invsync::endpoints::metrics::makeHandler(m_metricsManager),
                                   /*countAgainstBudget=*/false);

            m_httpServer->start(config);

            LOGFN_INFO(moduleLogFn(),
                       "inventory sync server listening on '%s' (routes: GET /, GET %s, %s, %s, %s and DELETE %s; "
                       "%zu sync worker(s)).",
                       config.socketPath.c_str(),
                       invsync::endpoints::metrics::path(),
                       invsync::endpoints::sync::path(),
                       invsync::endpoints::stats::path(),
                       invsync::endpoints::config::path(),
                       invsync::endpoints::delete_agent::path(),
                       m_syncPipeline ? m_syncPipeline->workerCount() : 0);
        }

        /**
         * @brief Once per heartbeat: logs indexer availability TRANSITIONS, never steady state.
         *
         * The only production caller of the connectors' isAvailable(); without it the log has no
         * record of when the indexer went away or came back. Reads the connector without holding
         * m_lifecycleMutex so a slow health round can never delay stop().
         */
        void logIndexerHealthTransition()
        {
            try
            {
                std::shared_ptr<invsync::indexer::IIndexerConnectorAsync> connector;
                {
                    std::lock_guard<std::mutex> lock(m_lifecycleMutex);
                    connector = m_indexerConnectorAsync;
                }
                if (!connector)
                {
                    return; // not built yet; the gate reports its own progress
                }

                const bool available = connector->isAvailable();
                if (m_lastIndexerAvailable.has_value() && *m_lastIndexerAvailable == available)
                {
                    return;
                }
                m_lastIndexerAvailable = available;

                if (available)
                {
                    LOGFN_INFO(moduleLogFn(), "The indexer is reachable; inventory documents can be delivered.");
                }
                else
                {
                    LOGFN_WARN(moduleLogFn(),
                               "No configured indexer host is currently reachable. Documents will queue or be "
                               "retried until one comes back; checking again every %d s.",
                               INVENTORY_SYNC_SERVER_HEARTBEAT_SECS);
                }
            }
            // LCOV_EXCL_START -- a connector mid-teardown is the only thrower, and forcing that
            // interleaving from a test would pin a race, not behaviour
            catch (...)
            {
                // The next heartbeat retries. Never let this kill the worker: run()'s barrier
                // deliberately does not re-enter the loop.
            }
            // LCOV_EXCL_STOP
        }

        /**
         * @brief Report what arrived in the <indexer> block, without its secrets.
         *
         * Runs on any attempt that still has something to build, immediately before it tries -- so a
         * misconfigured <indexer> shows up here as `hosts=0` alongside whatever construction-failure
         * reason follows, rather than as a silent mismatch later.
         *
         * Counts and set/unset only -- never values. The hosts can contain credentials in the URL
         * and the certificate paths are not useful in a log line.
         */
        void logIndexerSummary() const
        {
            const auto arraySize = [this](const char* key) -> std::size_t
            {
                const auto it = m_indexerConfig.find(key);
                return (it != m_indexerConfig.end() && it->is_array()) ? it->size() : 0U;
            };

            std::size_t caCount {0};
            bool hasCertificate {false};
            bool hasKey {false};

            const auto ssl = m_indexerConfig.find("ssl");
            if (ssl != m_indexerConfig.end() && ssl->is_object())
            {
                const auto ca = ssl->find("certificate_authorities");
                if (ca != ssl->end() && ca->is_array())
                {
                    caCount = ca->size();
                }
                hasCertificate = ssl->contains("certificate");
                hasKey = ssl->contains("key");
            }

            LOGFN_DEBUG1(moduleLogFn(),
                         "Indexer configuration received: hosts=%zu, ssl.certificate_authorities=%zu, "
                         "ssl.certificate=%s, ssl.key=%s.",
                         arraySize("hosts"),
                         caCount,
                         hasCertificate ? "<set>" : "<unset>",
                         hasKey ? "<set>" : "<unset>");
        }

        /// Which part of tryStartHttpServer()'s work a failure belongs to, because the ERROR must
        /// name WHICH object failed: each has its own, independently tunable option family, and
        /// pointing an operator at the wrong one costs a debugging session.
        enum class FailureStage
        {
            Configuration,
            IndexerSession,
            SyncIndexerConnector,
            AsyncIndexerConnector,
            SyncPipeline,
            VdScanLane,
            HttpServer
        };

        /// sync_workers <= 0 means "half the cores, at least one": ingestion shares the host with
        /// every other manager daemon, so taking every core by default would be antisocial, while
        /// one worker per two cores still scales the shard count with the machine.
        static std::size_t resolveSyncWorkers(const inventory_sync_server_config_t& config)
        {
            if (config.sync_workers > 0)
            {
                return static_cast<std::size_t>(config.sync_workers);
            }
            const auto cores = static_cast<std::size_t>(cpp_get_nproc());
            return cores / 2 > 0 ? cores / 2 : 1;
        }

        /// Diagnostic text for a stage. `label` appears in EVERY escalation branch; `settingHint`
        /// only in the first-attempt ERROR. One switch so a new stage cannot be half-added.
        struct StageDiagnostics
        {
            const char* m_label;
            const char* m_settingHint;
        };

        static StageDiagnostics stageDiagnostics(FailureStage stage)
        {
            switch (stage)
            {
                case FailureStage::Configuration:
                    return {"module configuration", "the 'wazuh_modules.inventory_sync_server_*' settings"};
                case FailureStage::IndexerSession:
                    return {"indexer session", "the <indexer> configuration block (hosts, ssl.*)"};
                case FailureStage::SyncIndexerConnector:
                    return {"sync indexer connector", "the 'inventory_sync_server_indexer_sync_*' settings"};
                case FailureStage::AsyncIndexerConnector:
                    return {"async indexer connector", "the 'inventory_sync_server_indexer_async_*' settings"};
                case FailureStage::SyncPipeline:
                    // The pipeline's extra worker connectors are built with the sync connector's
                    // configuration, so that family is the actionable one alongside its own.
                    return {"sync pipeline",
                            "the 'inventory_sync_server_sync_*' and 'inventory_sync_server_indexer_sync_*' settings"};
                case FailureStage::VdScanLane:
                    return {"VD scan lane",
                            "the 'inventory_sync_server_vd_*' and 'inventory_sync_server_indexer_sync_*' settings"};
                    // NOT a setting: the socket path is fixed (internal options cannot carry strings),
                    // so pointing an operator at one would send them looking for something that does
                    // not exist. Name what they can actually act on -- the directory.
                case FailureStage::HttpServer:
                    return {"UDS socket", "that the socket's parent directory exists and is writable"};
            }
            return {"unknown stage", "the module configuration"};
        }

        /**
         * @brief Builds ONE indexer object outside the lifecycle lock, then publishes it into @p slot.
         *
         * The gate is "did construction throw" (configuration validity), never "is the indexer
         * reachable" -- the indexer is allowed to start after modulesd. Publishing happens
         * immediately on success so a persistently failing LATER stage cannot force a rebuilt slot
         * (for the session that would mean a full round of per-host health checks every heartbeat;
         * `TheSucceedingSlotsAreNotRebuiltWhileAnotherRetries` pins this). Construction runs WITHOUT
         * m_lifecycleMutex so stop() never queues behind the health checks; the generation re-check
         * at publish keeps a stale attempt out of a newer start()/stop() cycle.
         *
         * @return false if this attempt must not continue -- the build failed (already reported) or
         *         the cycle moved on, in which case the freshly built object is dropped here.
         */
        template<typename TSlot, typename TBuild>
        bool buildAndPublish(TSlot& slot, FailureStage stage, std::uint64_t generation, TBuild&& build)
        {
            TSlot built;

            try
            {
                built = build();
                if (!built)
                {
                    // A factory returning null without throwing would otherwise pass the gate with
                    // nothing constructed, and never be retried.
                    reportFailedStart(stage, "the factory returned nothing");
                    return false;
                }
            }
            catch (const std::exception& e)
            {
                reportFailedStart(stage, e.what());
                return false;
            }
            catch (...)
            {
                reportFailedStart(stage, "non-standard exception");
                return false;
            }

            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            if (m_stopping || generation != m_startGeneration)
            {
                return false; // drops `built`, tearing down exactly what this attempt just made
            }
            slot = std::move(built);
            return true;
        }

        /**
         * @brief One startup attempt: resolve configuration, build what is missing, open the socket.
         *
         * Three phases so the slow part -- the session's synchronous `GET /_cat/health` per host,
         * 5 s timeout each -- does NOT hold the mutex stop() needs: stop() can set m_stopping
         * immediately and the m_stopping checks in phase B bail early.
         */
        void tryStartHttpServer()
        {
            // Serialises ATTEMPTS against each other (the worker's heartbeat vs. forceRetryForTests())
            // without being the mutex stop() needs. Phase B runs without m_lifecycleMutex, so without
            // this a second attempt could build duplicate objects and race m_failedStartAttempts.
            //
            // LOCK ORDER INVARIANT: m_attemptMutex is ALWAYS taken before m_lifecycleMutex, never the
            // other way round. start() resets m_failedStartAttempts before the worker thread exists,
            // so it does not need this mutex -- and must not take it, or the order inverts and
            // deadlocks.
            std::lock_guard<std::mutex> attemptLock(m_attemptMutex);

            invsync::http::UdsHttpServerConfig serverConfig;
            nlohmann::json rawIndexerConfig;
            nlohmann::json syncConnectorConfig;
            nlohmann::json asyncConnectorConfig;
            IndexerSessionFactory sessionFactory;
            IndexerConnectorSyncFactory syncFactory;
            IndexerConnectorAsyncFactory asyncFactory;
            invsync::sync::SyncPipelineConfig pipelineConfig;
            std::size_t pipelineWorkers {1};
            std::string pipelineClusterName;
            invsync::vd::VdScanLaneConfig laneConfig;
            std::size_t laneWorkers {DEFAULT_VD_WORKERS};
            VdScannerFactory scannerFactory;
            std::uint64_t generation {0};
            bool needSession {false};
            bool needSync {false};
            bool needAsync {false};
            bool needPipeline {false};
            bool needLane {false};

            /*
             * ---- Phase A: snapshot under the lifecycle lock. No I/O, so stop() never waits. ----
             *
             * Wrapped in try/catch like the other two phases: it copies the <indexer> JSON and builds
             * two overlays, and a throw escaping to run()'s barrier kills the worker -- and with it
             * the 60 s retry -- for the rest of the daemon's life.
             */
            try
            {
                std::lock_guard<std::mutex> lock(m_lifecycleMutex);

                if (m_stopping || m_httpServer)
                {
                    return;
                }

                generation = m_startGeneration;

                // Resolved once per attempt and kept, so the failure path can name the actual path
                // without rebuilding the configuration (and so the two can never disagree).
                serverConfig = invsync::http::buildServerConfig(m_config);
                m_resolvedSocketPath = serverConfig.socketPath;

                needSession = !m_indexerSession;
                needSync = !m_indexerConnectorSync;
                needAsync = !m_indexerConnectorAsync;
                needPipeline = !m_syncPipeline;
                needLane = !m_vdScanLane;

                // The cross-lane exclusion both the pipeline and the scan lane share. One per
                // start()/stop() cycle: stop() resets it after joining both lanes, because its
                // listeners capture the lanes' `this`.
                if (!m_agentRegistry)
                {
                    m_agentRegistry = std::make_shared<invsync::vd::AgentInFlightRegistry>();
                }

                laneWorkers =
                    m_config.vd_workers > 0 ? static_cast<std::size_t>(m_config.vd_workers) : DEFAULT_VD_WORKERS;
                laneConfig.workers = laneWorkers;
                laneConfig.queueSlots =
                    m_config.vd_scan_queue_slots > 0 ? static_cast<std::size_t>(m_config.vd_scan_queue_slots) : 0;
                laneConfig.retryAfterSeconds = m_config.vd_feed_retry_after_seconds > 0
                                                   ? m_config.vd_feed_retry_after_seconds
                                                   : DEFAULT_VD_RETRY_AFTER_SECS;
                scannerFactory = m_vdScannerFactory;

                sessionFactory = m_indexerSessionFactory;
                syncFactory = m_indexerConnectorSyncFactory;
                asyncFactory = m_indexerConnectorAsyncFactory;

                pipelineWorkers = resolveSyncWorkers(m_config);
                pipelineConfig.maxQueueBytes = m_config.sync_queue_bytes > 0
                                                   ? static_cast<std::size_t>(m_config.sync_queue_bytes)
                                                   : DEFAULT_SYNC_QUEUE_BYTES;
                pipelineConfig.bulkFlushBytes = m_config.indexer_sync_max_bulk_size > 0
                                                    ? static_cast<std::size_t>(m_config.indexer_sync_max_bulk_size)
                                                    : DEFAULT_BULK_FLUSH_BYTES;
                pipelineClusterName = invsync::common::buildClusterIdentity(m_config).clusterName;

                if (needSession || needSync || needAsync || needPipeline)
                {
                    logIndexerSummary();
                    rawIndexerConfig = m_indexerConfig;
                    syncConnectorConfig = invsync::indexer::buildSyncConnectorConfig(m_indexerConfig, m_config);
                    asyncConnectorConfig = invsync::indexer::buildAsyncConnectorConfig(m_indexerConfig, m_config);

                    /*
                     * The pipeline workers own EVERY flush (group commit: flush on queue-drain or
                     * on the byte threshold), so the connector's own flush timer is demoted to a
                     * last-resort safety net. That is a correctness requirement, not tuning: when
                     * the TIMER's flush fails, the connector drops the staged buffer and swallows
                     * the failure inside its background thread -- a worker that later flushed an
                     * emptied buffer would answer 200 for data that was silently lost. The one-hour
                     * interval keeps the timer from ever finding data in practice (a worker never
                     * sleeps on a non-empty buffer) while still bounding a leak if one does.
                     */
                    syncConnectorConfig["flush_interval_seconds"] = PIPELINE_CONNECTOR_FLUSH_INTERVAL_SECS;
                }
            }
            catch (const std::exception& e)
            {
                reportFailedStart(FailureStage::Configuration, e.what());
                return;
            }
            // LCOV_EXCL_START -- no non-std type is thrown by anything reachable here
            catch (...)
            {
                reportFailedStart(FailureStage::Configuration, "non-standard exception");
                return;
            }
            // LCOV_EXCL_STOP

            // ---- Phase B: construct WITHOUT the lifecycle lock. The health checks happen here. ----
            //
            // Chained so the first failure stops the attempt, for three reasons: reportFailedStart()
            // increments the shared attempt counter, so reporting twice per heartbeat would halve the
            // escalation clock and break the "60 attempts is about an hour" contract; the session
            // validates the configuration the connectors depend on, so on a bad <indexer> block all
            // three would fail and emit three messages for one root cause; and there is no point
            // building connectors against a session that does not exist.
            //
            // Each stage publishes as soon as it succeeds -- see buildAndPublish() for why holding
            // them as locals until the end would silently undo the shared session's whole benefit.
            if (needSession &&
                !buildAndPublish(m_indexerSession,
                                 FailureStage::IndexerSession,
                                 generation,
                                 [&]
                                 {
                                     return sessionFactory(
                                         rawIndexerConfig,
                                         LoggingContext {INVENTORY_SYNC_SERVER_SESSION_LOGTAG, m_logFunction});
                                 }))
            {
                return;
            }

            // Own a reference for the rest of this attempt. Taking a copy of the shared_ptr rather
            // than reading the member again is what makes the connector constructions below safe
            // outside the lock: stop() may clear the member at any moment, and a bare pointer into it
            // would dangle while a connector's constructor is still running on it.
            std::shared_ptr<invsync::indexer::IIndexerSession> session;
            {
                std::lock_guard<std::mutex> lock(m_lifecycleMutex);
                if (m_stopping || generation != m_startGeneration)
                {
                    return;
                }
                session = m_indexerSession;
            }

            if (!session)
            {
                return; // stop() raced us; nothing to build connectors on
            }

            if (needSync && !buildAndPublish(m_indexerConnectorSync,
                                             FailureStage::SyncIndexerConnector,
                                             generation,
                                             [&]
                                             {
                                                 return syncFactory(
                                                     syncConnectorConfig,
                                                     *session,
                                                     LoggingContext {INVENTORY_SYNC_SERVER_SYNC_LOGTAG, m_logFunction});
                                             }))
            {
                return;
            }

            if (needAsync &&
                !buildAndPublish(m_indexerConnectorAsync,
                                 FailureStage::AsyncIndexerConnector,
                                 generation,
                                 [&]
                                 {
                                     return asyncFactory(
                                         asyncConnectorConfig,
                                         *session,
                                         LoggingContext {INVENTORY_SYNC_SERVER_ASYNC_LOGTAG, m_logFunction});
                                 }))
            {
                return;
            }

            if (needPipeline)
            {
                // Same counted-reference dance as the session: the pipeline reuses the published
                // sync connector as its first worker's connector (it is otherwise idle -- its other
                // job is the endpoint's admission isAvailable(), which is thread-safe), and builds
                // one more per additional worker, all sharing the session.
                std::shared_ptr<invsync::indexer::IIndexerConnectorSync> syncConnector;
                {
                    std::lock_guard<std::mutex> lock(m_lifecycleMutex);
                    if (m_stopping || generation != m_startGeneration)
                    {
                        return;
                    }
                    syncConnector = m_indexerConnectorSync;
                }

                if (!syncConnector)
                {
                    return; // stop() raced us
                }

                if (!buildAndPublish(
                        m_syncPipeline,
                        FailureStage::SyncPipeline,
                        generation,
                        [&]
                        {
                            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors;
                            connectors.reserve(pipelineWorkers);
                            connectors.push_back(syncConnector);
                            for (std::size_t i = 1; i < pipelineWorkers; ++i)
                            {
                                connectors.emplace_back(
                                    syncFactory(syncConnectorConfig,
                                                *session,
                                                LoggingContext {INVENTORY_SYNC_SERVER_SYNC_LOGTAG, m_logFunction}));
                            }
                            return std::make_shared<invsync::sync::SyncPipeline>(pipelineConfig,
                                                                                 std::move(connectors),
                                                                                 pipelineClusterName,
                                                                                 m_agentRegistry,
                                                                                 m_metricsManager);
                        }))
                {
                    return;
                }
            }

            if (needLane)
            {
                std::shared_ptr<invsync::vd::IVdScanner> builtScanner;
                if (!buildAndPublish(
                        m_vdScanLane,
                        FailureStage::VdScanLane,
                        generation,
                        [&]
                        {
                            builtScanner = scannerFactory();
                            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors;
                            connectors.reserve(laneWorkers);
                            for (std::size_t i = 0; i < laneWorkers; ++i)
                            {
                                connectors.emplace_back(
                                    syncFactory(syncConnectorConfig,
                                                *session,
                                                LoggingContext {INVENTORY_SYNC_SERVER_SYNC_LOGTAG, m_logFunction}));
                            }
                            return std::make_shared<invsync::vd::VdScanLane>(laneConfig,
                                                                             builtScanner,
                                                                             std::move(connectors),
                                                                             m_agentRegistry,
                                                                             pipelineClusterName,
                                                                             m_metricsManager);
                        }))
                {
                    return;
                }

                // Publish the scanner seam and register this server in the vulnerability scanner's
                // neutral coordination registry (agents to skip, VDSync drains, fencing) -- under
                // the lifecycle lock, like every other published slot.
                std::lock_guard<std::mutex> registrationLock(m_lifecycleMutex);
                if (!m_stopping && generation == m_startGeneration && m_vdScanLane)
                {
                    m_vdScanner = std::move(builtScanner);
                    if (!m_scanCoordinator)
                    {
                        m_scanCoordinator = std::make_shared<invsync::vd::ServerScanCoordinator>(m_agentRegistry);
                        vd_sync::ScanCoordinatorRegistry::instance().add(m_scanCoordinator);
                    }
                }
            }

            // ---- Phase C: open the socket, back under the lifecycle lock. ----
            {
                std::lock_guard<std::mutex> lock(m_lifecycleMutex);

                // Re-check: stop() -- and even a later start() -- can have run during phase B.
                if (m_stopping || m_httpServer || generation != m_startGeneration)
                {
                    return;
                }

                try
                {
                    startHttpServer(serverConfig);
                    if (m_failedStartAttempts > 0)
                    {
                        LOGFN_INFO(moduleLogFn(),
                                   "inventory sync server started after %d failed attempt(s).",
                                   m_failedStartAttempts);
                    }
                    m_failedStartAttempts = 0;
                }
                catch (const std::exception& e)
                {
                    reportFailedStart(FailureStage::HttpServer, e.what());
                    m_httpServer.reset();
                }
                // LCOV_EXCL_START -- asio and the standard library only throw std types
                catch (...)
                {
                    reportFailedStart(FailureStage::HttpServer, "non-standard exception");
                    m_httpServer.reset();
                }
                // LCOV_EXCL_STOP
            }
        }

        /**
         * @brief Escalating report for a failed start, either stage.
         *
         * The first attempt is an ERROR naming the real reason and the setting to check, so a
         * permanent misconfiguration is visible immediately. The next hour of retries stays at
         * debug so a transient condition does not flood, and after that one WARN per hour keeps it
         * visible. One shared attempt counter/cadence across both stages -- only the wording (and
         * therefore the setting an operator is pointed at) differs.
         */
        void reportFailedStart(FailureStage stage, const char* reason)
        {
            ++m_failedStartAttempts;

            // 60 attempts at one per heartbeat (60 s) == roughly one hour.
            constexpr int ATTEMPTS_PER_ESCALATION {60};

            const auto diagnostics = stageDiagnostics(stage);

            if (m_failedStartAttempts == 1)
            {
                if (stage == FailureStage::HttpServer)
                {
                    LOGFN_ERROR(moduleLogFn(),
                                "The inventory sync server could not bind '%s': %s. That path is fixed, not "
                                "configurable; check that its parent directory exists and is writable.",
                                m_resolvedSocketPath.c_str(),
                                reason);
                }
                else
                {
                    LOGFN_ERROR(moduleLogFn(),
                                "The inventory sync server could not start: the %s configuration is invalid (%s). "
                                "Retrying every %d s. Check %s.",
                                diagnostics.m_label,
                                reason,
                                INVENTORY_SYNC_SERVER_HEARTBEAT_SECS,
                                diagnostics.m_settingHint);
                }
            }
            else if (m_failedStartAttempts % ATTEMPTS_PER_ESCALATION == 0)
            {
                // The label matters here, not just in the ERROR: with four stages the failing one can
                // ALTERNATE between heartbeats, while the first-attempt ERROR is emitted only once per
                // incident. Without it, an hour of log lines cannot say which part is stuck.
                LOGFN_WARN(moduleLogFn(),
                           "The inventory sync server is still not running after %d attempt(s) (~%d minute(s)); "
                           "currently blocked on the %s: %s",
                           m_failedStartAttempts,
                           m_failedStartAttempts * INVENTORY_SYNC_SERVER_HEARTBEAT_SECS / 60,
                           diagnostics.m_label,
                           reason);
            }
            else
            {
                LOGFN_DEBUG1(moduleLogFn(),
                             "inventory sync server start attempt %d failed on the %s: %s",
                             m_failedStartAttempts,
                             diagnostics.m_label,
                             reason);
            }
        }

        void run()
        {
            // Exception barrier for the worker thread body: a throw escaping a bare std::thread
            // terminates the whole modulesd daemon. tryStartHttpServer() has its own catch, so what
            // this really covers is a non-std::exception from there plus condition-variable and
            // logging failures.
            try
            {
                runLoop();
            }
            catch (const std::exception& e)
            {
                // Deliberately does NOT re-enter the loop: an exception that repeats every iteration
                // would spin forever writing to wazuh-manager.log, which is worse than a dead worker. The
                // module keeps serving on whatever the transport already started.
                LOGFN_ERROR(moduleLogFn(),
                            "The inventory sync server worker thread stopped on an unexpected exception: %s.",
                            e.what());
            }
            // LCOV_EXCL_START -- the barrier of last resort; unreachable without a non-std throw
            catch (...)
            {
                LOGFN_ERROR(moduleLogFn(),
                            "The inventory sync server worker thread stopped on a non-standard exception.");
            }
            // LCOV_EXCL_STOP
        }

        void runLoop()
        {
            LOGFN_INFO(moduleLogFn(), "inventory sync server worker thread running.");

            while (true)
            {
                tryStartHttpServer();
                logIndexerHealthTransition();

                std::unique_lock<std::mutex> lock(m_waitMutex);
                if (m_stopping)
                {
                    break;
                }

                LOGFN_DEBUG1(moduleLogFn(), "inventory sync server heartbeat.");
                m_waitCv.wait_for(lock,
                                  std::chrono::seconds(INVENTORY_SYNC_SERVER_HEARTBEAT_SECS),
                                  [this]() { return m_stopping.load(); });

                if (m_stopping)
                {
                    break;
                }
            }

            LOGFN_INFO(moduleLogFn(), "inventory sync server worker thread finished.");
        }

        std::mutex m_lifecycleMutex; ///< Serializes start()/stop().
        /// Serialises startup ATTEMPTS against each other without being the mutex stop() needs.
        /// LOCK ORDER: always taken BEFORE m_lifecycleMutex -- see tryStartHttpServer().
        std::mutex m_attemptMutex;
        /// Bumped by every start(). An attempt captures it in phase A and re-checks it in phase C, so
        /// a stale attempt from a previous start()/stop() cycle cannot publish into the current one.
        /// Only reachable via forceRetryForTests(), which runs on the test's thread rather than the
        /// worker's; stop() joins the worker, so the worker itself can never straddle two cycles.
        std::uint64_t m_startGeneration {0};
        std::mutex m_waitMutex;              ///< Guards the heartbeat wait.
        std::condition_variable m_waitCv;    ///< Wakes the worker on stop.
        std::atomic_bool m_stopping {false}; ///< Cooperative-shutdown flag.
        bool m_running {false};              ///< Whether the worker is active.
        int m_failedStartAttempts {0};       ///< Consecutive failed server starts; drives log escalation.
        /// Last observed indexer availability; empty until the first heartbeat reads it. Worker-only.
        std::optional<bool> m_lastIndexerAvailable;
        std::thread m_worker; ///< The C++ thread launched for this module.

        inventory_sync_server_config_t m_config {}; ///< Copy of the caller's configuration.
        std::string m_resolvedSocketPath;           ///< Path of the most recent start attempt, for diagnostics.
        /// Owned copy of the <indexer> block, before the bulk-size/flush-interval overlay.
        nlohmann::json m_indexerConfig {nlohmann::json::object()};
        /// Retained so the indexer connector -- built later, on the worker thread -- gets the same
        /// LoggingContext the older inventory_sync module builds inline in its own start().
        std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
            m_logFunction;

        std::unique_ptr<invsync::http::IUdsHttpServer> m_httpServer; ///< HTTP-over-UDS transport.

        /*
         * The three indexer slots, each constructed at most once per start()/stop() cycle and memoised
         * independently -- see buildAndPublish(). The session is retained so a retry of one connector
         * does not pay for another round of host health checks.
         */
        /// shared_ptr, not unique_ptr: an in-flight attempt takes a counted reference so stop()
        /// clearing this member cannot dangle a connector constructor still running on it.
        std::shared_ptr<invsync::indexer::IIndexerSession> m_indexerSession;
        /// shared_ptr for the same reason as the async one below: the sync pipeline workers (F2) will
        /// hold it weakly. The factory still returns unique_ptr; the assignment converts.
        std::shared_ptr<invsync::indexer::IIndexerConnectorSync> m_indexerConnectorSync;
        /// shared_ptr because the /stats and /config handlers hold it WEAKLY (which needs a shared
        /// owner) -- the weak capture is what keeps stop()'s phase-2 reset destructive.
        std::shared_ptr<invsync::indexer::IIndexerConnectorAsync> m_indexerConnectorAsync;
        /// The D18 statistics registry. Created ONCE and NEVER reset in stop(): counters must
        /// survive the HTTP server's restart retries (an operator reading /metrics after a retry
        /// wants totals, not a fresh zeroed registry). Everything downstream (pipeline, lane,
        /// endpoints) resolves its instruments from this one manager, so names dedupe naturally.
        const std::shared_ptr<wazuh::metrics::IManager> m_metricsManager {std::make_shared<wazuh::metrics::Manager>()};
        /// The POST /stateful ingestion pipeline: workers sharded by agent id, one connector each
        /// (worker 0 reuses the slot above). Built after the connectors, torn down before them;
        /// the endpoint handler holds it weakly, like the connectors.
        std::shared_ptr<invsync::sync::SyncPipeline> m_syncPipeline;
        /// Cross-lane per-agent exclusion shared by the pipeline and the scan lane (D22). Reset in
        /// stop() AFTER both lanes joined: the lanes' wake-up listeners capture their `this`, so a
        /// registry surviving into the next cycle would hold dangling closures.
        std::shared_ptr<invsync::vd::AgentInFlightRegistry> m_agentRegistry;
        /// The scan lane's seam over the vulnerability scanner; the endpoint's feed gate reads it.
        std::shared_ptr<invsync::vd::IVdScanner> m_vdScanner;
        /// The D22 scan lane for VD sessions: scan -> (ok) -> index -> respond.
        std::shared_ptr<invsync::vd::VdScanLane> m_vdScanLane;
        /// This server's registration in the scanner's neutral coordination registry.
        std::shared_ptr<invsync::vd::ServerScanCoordinator> m_scanCoordinator;

        IndexerSessionFactory m_indexerSessionFactory {
            [](const nlohmann::json& config, LoggingContext logging)
            { return std::make_unique<invsync::indexer::IndexerSessionAdapter>(config, std::move(logging)); }};

        /*
         * The production connector factories are the only place that knows the seam it is handed wraps
         * a real IndexerSession, so the unwrapping happens here. dynamic_cast on a reference rather
         * than static_cast on purpose: a test that installs a fake session but leaves a production
         * connector factory in place then gets a std::bad_cast, which buildAndPublish() catches and
         * reports as a normal gate failure, instead of undefined behaviour.
         */
        IndexerConnectorSyncFactory m_indexerConnectorSyncFactory {
            [](const nlohmann::json& config, const invsync::indexer::IIndexerSession& session, LoggingContext logging)
            {
                const auto& adapter = dynamic_cast<const invsync::indexer::IndexerSessionAdapter&>(session);
                return std::make_unique<invsync::indexer::IndexerConnectorSyncAdapter>(
                    config, adapter.session(), std::move(logging));
            }};

        VdScannerFactory m_vdScannerFactory {[]() { return invsync::vd::makeProductionVdScanner(); }};

        IndexerConnectorAsyncFactory m_indexerConnectorAsyncFactory {
            [](const nlohmann::json& config, const invsync::indexer::IIndexerSession& session, LoggingContext logging)
            {
                const auto& adapter = dynamic_cast<const invsync::indexer::IndexerSessionAdapter&>(session);
                return std::make_unique<invsync::indexer::IndexerConnectorAsyncAdapter>(
                    config, adapter.session(), std::move(logging));
            }};
    };

} // namespace invsync

#endif // _INVENTORY_SYNC_SERVER_FACADE_HPP
