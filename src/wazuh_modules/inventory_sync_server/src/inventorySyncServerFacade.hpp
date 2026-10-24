/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SERVER_FACADE_HPP
#define _INVENTORY_SYNC_SERVER_FACADE_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/clusterIdentity.hpp"
#include "common/metricNames.hpp"
#include "endpoints/configEndpoint.hpp"
#include "endpoints/deleteAgentEndpoint.hpp"
#include "endpoints/metricsEndpoint.hpp"
#include "endpoints/statsEndpoint.hpp"
#include "endpoints/syncEndpoint.hpp"
#include "endpoints/vdScanEndpoint.hpp"
#include "http_server/udsHttpServerConfig.hpp"
#include "indexer/IIndexerConnectorAsync.hpp"
#include "indexer/IIndexerConnectorSync.hpp"
#include "indexer/IIndexerSession.hpp"
#include "indexer/indexerClientSyncAdapter.hpp"
#include "indexer/indexerConnectorAsyncAdapter.hpp"
#include "indexer/indexerConnectorConfig.hpp"
#include "indexer/indexerFactories.hpp"
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
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/socketPathCheck.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <indexer_client/client.hpp>
#include <indexer_client/metrics.hpp>
#include <indexer_client/runtime.hpp>
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
     * Distinct tags for the two indexer_connector (v1) objects, so their own log lines can be told
     * apart. Passing one shared tag would make the session's and the async connector's output
     * indistinguishable, which matters most exactly when one of them is misbehaving. The sync half
     * runs on indexer_client, which logs through the process runtime under its own tag.
     *
     * The `:suffix` form is load-bearing: LogFn::compose() truncates from the first '(', so a
     * parenthesised suffix would be discarded, while a colon survives. These end up rendered as
     * "...:inventory-sync-server:indexer(indexer-connector)" and so on.
     */
    constexpr auto INVENTORY_SYNC_SERVER_SESSION_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:indexer"};
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
    /// Sessions one agent may have pending when 'inventory_sync_server_max_sessions_per_agent' has no
    /// opinion (D28): the session being applied plus one re-send after remoted gave up waiting.
    constexpr std::size_t DEFAULT_MAX_SESSIONS_PER_AGENT {2};
    /// Retry-After fallback for rejected vulnerability-detection sessions (D17).
    constexpr int DEFAULT_VD_RETRY_AFTER_SECS {10};
    /// modulesd's default for the ignored flush-interval option, mirrored here so start() can
    /// tell "left alone" from "an operator tuned a knob that does nothing" and warn on the latter.
    /// There is no background flush at all: the pipeline workers and the VD scan lane own every
    /// flush, so a flush failure always surfaces on the thread that must answer for it.
    constexpr int IGNORED_SYNC_FLUSH_INTERVAL_DEFAULT_SECS {20};
    /// modulesd's default for the ignored request-timeout option (I138), mirrored for the same reason:
    /// the per-request timeout belongs to the process's indexer client runtime now.
    constexpr int IGNORED_SYNC_REQUEST_TIMEOUT_DEFAULT_SECS {60};
    /// Global quota assumed for sizing the `inventory` bucket when no runtime was published (the
    /// Client then fails to build anyway; this only keeps phase A total).
    constexpr std::uint64_t FALLBACK_GLOBAL_QUOTA_BYTES {256ULL * 1024ULL * 1024ULL};
    /// How long a staged add may wait for bucket quota before its session fails Unavailable (I145b).
    constexpr std::chrono::milliseconds INDEXER_BLOCK_TIMEOUT {2000};
    /// Granularity of every adapter wait: how soon `closing` and a batch deadline are noticed (I141).
    constexpr std::chrono::milliseconds INDEXER_BLOCK_SLICE {250};
    /// QueryOptions::pageDeadline of each adapter query.
    constexpr std::chrono::milliseconds INDEXER_PAGE_DEADLINE {30000};
    /// What stop() grants the Client to finish closing once both lanes are joined (I141b): whatever
    /// is left belongs to sessions already answered 503.
    constexpr std::chrono::milliseconds INDEXER_CLOSE_GRACE {1000};
    /// Longest a cached Client metrics snapshot is served, so one scrape is one Client::metrics() call (I141b).
    constexpr std::chrono::milliseconds INDEXER_METRICS_MAX_AGE {250};

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
                const auto resolved = invsync::buildServerConfig(configuration);
                std::string reason;
                if (!wazuh::uds_http::socketPathIsUsable(resolved.socketPath, reason))
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
            m_bucketWarningLogged = false;
            ++m_startGeneration;

            LOGFN_INFO(moduleLogFn(), "Starting inventory sync server (cluster='%s').", m_config.cluster_name);

            if (m_config.indexer_sync_flush_interval_seconds > 0 &&
                m_config.indexer_sync_flush_interval_seconds != IGNORED_SYNC_FLUSH_INTERVAL_DEFAULT_SECS)
            {
                LOGFN_WARN(moduleLogFn(),
                           "'wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds' (%d) has no "
                           "effect and is slated for removal: the ingestion workers own every flush, so the "
                           "connector's periodic flush is always disabled.",
                           m_config.indexer_sync_flush_interval_seconds);
            }

            if (m_config.indexer_sync_request_timeout_seconds > 0 &&
                m_config.indexer_sync_request_timeout_seconds != IGNORED_SYNC_REQUEST_TIMEOUT_DEFAULT_SECS)
            {
                LOGFN_WARN(moduleLogFn(),
                           "'wazuh_modules.inventory_sync_server_indexer_sync_request_timeout_seconds' (%d) has no "
                           "effect: the request timeout of the indexer client is "
                           "'wazuh_modules.indexer_client_request_timeout_ms'.",
                           m_config.indexer_sync_request_timeout_seconds);
            }

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

                // NOTE: this runs on modulesd's main thread (E7a, I129), the indexer client runtime's
                // owner: wm_shutdown_run() fixes the runtime's shutdown deadline, then calls every
                // module's stop() sequentially before joining them all under one shared budget. So
                // nothing here may block on unbounded I/O: the transport's own drain window is short
                // and the Client gets INDEXER_CLOSE_GRACE once both lanes are joined.
                LOGFN_INFO(moduleLogFn(), "Stopping inventory sync server.");

                // Phase 1: stop ACCEPTING. After this returns no route handler will run again, but
                // the transport's I/O runtime is deliberately still alive so a response for a
                // request already handed off can still be delivered.
                if (m_httpServer)
                {
                    m_httpServer->stopAccepting();
                }

                // Before the lanes stop (I141, D73): `closing` wakes every adapter wait within one
                // slice, and requestClose() closes the Client's admission, so a worker still staging
                // or waiting on the indexer answers its sessions 503 instead of holding the joins
                // below for a whole batch budget.
                if (m_indexerClosing)
                {
                    m_indexerClosing->store(true);
                }
                if (m_indexerClient)
                {
                    m_indexerClient->requestClose();
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
                // Reverse construction order (session, client, sync, async): async first. The sync
                // connectors' destructors discard() whatever they still held; the pipeline and lane
                // ones went with their owners above, this is worker 0's.
                m_indexerConnectorAsync.reset();
                m_indexerConnectorSync.reset();
                // Both lanes are joined, so what the Client still has queued belongs to sessions
                // already answered 503 (I141b): a short, bounded drain, then the Client goes.
                if (m_indexerClient)
                {
                    const auto closed =
                        m_indexerClient->awaitClosed(std::chrono::steady_clock::now() + INDEXER_CLOSE_GRACE);
                    if (!closed.ok())
                    {
                        LOGFN_DEBUG1(moduleLogFn(),
                                     "The indexer client did not close cleanly: %s (%s).",
                                     indexer_client::toString(closed.cause),
                                     closed.reason.c_str());
                    }
                }
                m_indexerClient.reset();
                m_indexerClosing.reset();
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
         * Factories for the indexer objects the gate builds, in order: the v1 session, the
         * indexer_client Client (I144), the sync connectors over that Client, the async connector.
         * The default, production values construct the real objects; tests substitute fakes so the
         * gate can be exercised without the real per-host health-check I/O.
         *
         * Separate factories rather than one bundle: a gate test needs to fail exactly one of them
         * while leaving the others healthy, which requires overriding them independently.
         */
        using IndexerSessionFactory =
            std::function<std::unique_ptr<invsync::indexer::IIndexerSession>(const nlohmann::json&, LoggingContext)>;
        using IndexerClientFactory = invsync::indexer::IndexerClientFactory;
        using IndexerConnectorSyncFactory = invsync::indexer::IndexerConnectorSyncFactory;
        using IndexerConnectorAsyncFactory = std::function<std::unique_ptr<invsync::indexer::IIndexerConnectorAsync>(
            const nlohmann::json&, const invsync::indexer::IIndexerSession&, LoggingContext)>;
        /// Builds the scan lane's seam over the vulnerability scanner; tests substitute a fake so
        /// the D22 gating can be pinned without a CVE feed. Takes whether THIS node's own config
        /// has VD enabled (m_config.vd_configured_enabled), known before the scanner's own
        /// start() has necessarily run -- see feedGateOpen().
        using VdScannerFactory = std::function<std::shared_ptr<invsync::vd::IVdScanner>(bool)>;

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

        /// TEST-ONLY. Override how the module's indexer_client Client is obtained. See above.
        void setIndexerClientFactoryForTests(IndexerClientFactory factory)
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);
            m_indexerClientFactory = std::move(factory);
        }

        /// TEST-ONLY. Override how each worker's sync indexer connector is constructed. See above.
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
        void startHttpServer(const wazuh::uds_http::UdsHttpServerConfig& config)
        {
            m_httpServer = wazuh::uds_http::makeUdsHttpServer();

            // Liveness probe. Exempt from the in-flight byte budget so it keeps answering under
            // memory pressure -- which is exactly when someone is most likely to be probing it.
            m_httpServer->addRoute(
                wazuh::uds_http::Method::Get,
                "/",
                [](std::shared_ptr<const wazuh::uds_http::HttpRequest>,
                   std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
                {
                    responder->send(wazuh::uds_http::HttpResponse::json(
                        200, R"({"status":"ok","module":"inventory_sync_server"})"));
                },
                wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness});

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

            // D28: the per-agent cap on sessions admitted and not yet answered. Owned by the route.
            const auto agentSessions = std::make_shared<invsync::sync::AgentSessionLimiter>(
                m_config.max_sessions_per_agent > 0 ? static_cast<std::size_t>(m_config.max_sessions_per_agent)
                                                    : DEFAULT_MAX_SESSIONS_PER_AGENT);
            const auto agentBusyTotal =
                m_metricsManager->getOrCreateCounter(invsync::metrics::AGENT_BUSY_TOTAL,
                                                     "Sessions refused with 503 because their agent already had "
                                                     "'inventory_sync_server_max_sessions_per_agent' sessions pending",
                                                     "count");

            // The ingestion route: everything past the strand-side validation runs on the
            // pipeline, or on the VD scan lane for vulnerability-detection data sessions.
            m_httpServer->addRoute(invsync::endpoints::sync::method(),
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
                                       // The shared helper, NOT a getOrCreateCounter with its own strings: the lane
                                       // registers this counter too, and getOrCreate keeps only the first
                                       // registration's metadata -- a second copy of the strings here would be dead
                                       // text that silently drifts.
                                       invsync::metrics::makeVdRetryAfterCounter(*m_metricsManager),
                                       agentSessions,
                                       agentBusyTotal}),
                                   wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Data});

            // Reached through remoted's authenticated /stats and /config routes. Registered separately
            // rather than sharing one handler because their real payloads will diverge. DATA class
            // (U4): these carry documents agents send through remoted -- payloads of agent origin
            // that must charge the byte budget exactly like /stateful, not control-plane reads.
            m_httpServer->addRoute(invsync::endpoints::stats::method(),
                                   invsync::endpoints::stats::path(),
                                   invsync::endpoints::stats::makeHandler(m_indexerConnectorAsync, clusterIdentity),
                                   wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Data});

            m_httpServer->addRoute(invsync::endpoints::config::method(),
                                   invsync::endpoints::config::path(),
                                   invsync::endpoints::config::makeHandler(m_indexerConnectorAsync, clusterIdentity),
                                   wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Data});

            // Whole-agent deletion (design doc 04): UDS-local, manager-internal, deferred to the
            // agent's pipeline shard and ANSWERED AT COMPLETION -- the item carries its responder,
            // so the pipeline answers only once the purge has flushed. That is what lets the Task
            // Manager write a row `completed` and have it mean purged, rather than "inventory-sync
            // accepted it". Its caller is the dispatcher, which drives the deletion's retries.
            //
            // CONTROL class (signed decision): the agent id is a few bytes of body, so a saturated
            // ingest budget must never fail deletions that cost it no payload memory. Its capacity
            // bound is the dispatcher's delete-lane depth rather than a queue of its own.
            {
                // Same RequestCounters family as the sync route (getOrCreateCounter dedupes by
                // name). The handler counts only what IT answers -- the inline 400/503 rejections;
                // the terminal response is counted by the pipeline, the site that sends it, so an
                // accepted deletion is counted exactly once.
                //
                // The async connector is in here because the deletion has a half that belongs to
                // it: `wazuh-agent-config` and `wazuh-agent-stats` are written through that
                // connector, so their deletes have to ride its own queue to be ordered after a
                // report it has accepted but not yet pushed (see the route's header).
                const invsync::endpoints::delete_agent::Dependencies deleteDeps {
                    m_syncPipeline,
                    m_indexerConnectorSync,
                    m_indexerConnectorAsync,
                    invsync::metrics::RequestCounters::make(*m_metricsManager)};

                // Its own response backstop, because this is the one route whose peer waits LONGER
                // than the server-wide 300 s -- see responseTimeoutSeconds() for what the inverted
                // pair costs. The zeroes before it keep the class policy's body and session caps.
                m_httpServer->addRoute(
                    invsync::endpoints::delete_agent::method(),
                    invsync::endpoints::delete_agent::path(),
                    invsync::endpoints::delete_agent::makeHandler(deleteDeps),
                    wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Control,
                                                   0,
                                                   0,
                                                   invsync::endpoints::delete_agent::responseTimeoutSeconds()});
            }

            // On-demand vulnerability rescan of one agent (design doc 04's sibling): UDS-local,
            // manager-internal, executed on the VD scan lane and ANSWERED AT COMPLETION, so the
            // Task Manager row behind it means scanned rather than accepted. Its caller is the
            // dispatcher; the scanner's own admission route is untouched.
            //
            // CONTROL class for the same reason as the deletion route: the agent id is a few bytes
            // of body, so a saturated ingest budget must never fail a scan that costs it no payload
            // memory. Its capacity control is the lane's bounded queue, which is what the class
            // contract asks of a route doing real work.
            //
            // And its own response backstop: its peer waits 300 s, which is exactly the
            // server-wide value -- see responseTimeoutSeconds() for what that tie costs.
            m_httpServer->addRoute(
                invsync::endpoints::vd_scan::method(),
                invsync::endpoints::vd_scan::path(),
                invsync::endpoints::vd_scan::makeHandler(invsync::endpoints::vd_scan::Dependencies {
                    m_vdScanLane, invsync::metrics::RequestCounters::make(*m_metricsManager)}),
                wazuh::uds_http::RouteOptions {
                    wazuh::uds_http::RouteClass::Control, 0, 0, invsync::endpoints::vd_scan::responseTimeoutSeconds()});

            // The D18 statistics dump. Budget-exempt like the health probe: reading metrics is
            // most valuable exactly when the byte budget is under pressure.
            m_httpServer->addRoute(invsync::endpoints::metrics::method(),
                                   invsync::endpoints::metrics::path(),
                                   invsync::endpoints::metrics::makeHandler(m_metricsManager),
                                   wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness});

            m_httpServer->start(config);
            registerTransportDiagnostics();
            registerIndexerClientMetrics();

            LOGFN_INFO(moduleLogFn(),
                       "inventory sync server listening on '%s' (routes: GET /, GET %s, %s, %s, %s, %s and %s; "
                       "%zu sync worker(s)).",
                       config.socketPath.c_str(),
                       invsync::endpoints::metrics::path(),
                       invsync::endpoints::sync::path(),
                       invsync::endpoints::stats::path(),
                       invsync::endpoints::config::path(),
                       invsync::endpoints::delete_agent::path(),
                       invsync::endpoints::vd_scan::path(),
                       m_syncPipeline ? m_syncPipeline->workerCount() : 0);
        }

        /**
         * @brief Publish the transport's bounded resources as pull metrics (U10).
         *
         * Called after every successful start: the weak target is repointed at the new server,
         * while the pulls themselves are registered exactly once (iManager has no unregister).
         * After stop() resets m_httpServer the weak_ptr expires and every metric reads 0 --
         * the documented quiesced value -- so a dump can never touch a dead server.
         */
        void registerTransportDiagnostics()
        {
            {
                std::lock_guard<std::mutex> lock {m_transportDiagMutex};
                m_transportDiagTarget = m_httpServer;
            }
            if (m_transportPullsRegistered)
            {
                return;
            }
            m_transportPullsRegistered = true;

            const auto snapshot = [this]() -> wazuh::uds_http::TransportDiagnostics
            {
                std::lock_guard<std::mutex> lock {m_transportDiagMutex};
                if (const auto server = m_transportDiagTarget.lock())
                {
                    return server->diagnostics();
                }
                return {};
            };

            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_BUDGET_AVAILABLE_BYTES,
                [snapshot] { return static_cast<uint64_t>(snapshot().budgetAvailableBytes); },
                "Bytes the in-flight payload budget can still admit",
                "bytes");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_BUDGET_IN_FLIGHT_BYTES,
                [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightBytes); },
                "Bytes currently reserved by admitted requests",
                "bytes");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_BUDGET_IN_FLIGHT_REQUESTS,
                [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightCount); },
                "Requests currently holding a budget reservation",
                "requests");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_SESSIONS_LIVE,
                [snapshot] { return static_cast<uint64_t>(snapshot().liveSessions); },
                "Open transport connections, deferred replies included (superset: the per-class "
                "counts exclude connections still reading their head)",
                "connections");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_SESSIONS_DATA,
                [snapshot]
                {
                    return static_cast<uint64_t>(
                        snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Data)]);
                },
                "Sessions classified on data-class routes",
                "connections");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_SESSIONS_CONTROL,
                [snapshot]
                {
                    return static_cast<uint64_t>(
                        snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Control)]);
                },
                "Sessions classified on control-class routes",
                "connections");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_SESSIONS_LIVENESS,
                [snapshot]
                {
                    return static_cast<uint64_t>(
                        snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Liveness)]);
                },
                "Sessions classified on liveness-class routes",
                "connections");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_REJECTED_BUDGET,
                [snapshot] { return static_cast<uint64_t>(snapshot().rejectedBudgetExhausted); },
                "Requests answered 503 because the in-flight payload budget was exhausted",
                "requests");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_REJECTED_SESSION_CAP,
                [snapshot] { return static_cast<uint64_t>(snapshot().rejectedSessionCap); },
                "Requests answered 503 because their class session cap was reached",
                "requests");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_REJECTED_SHUTDOWN,
                [snapshot] { return static_cast<uint64_t>(snapshot().rejectedShutdown); },
                "Requests answered 503 because the server was already stopping",
                "requests");
            m_metricsManager->registerPullMetric(
                invsync::metrics::SERVER_REJECTED_NO_RESPONSE,
                [snapshot] { return static_cast<uint64_t>(snapshot().rejectedNoResponse); },
                "Requests answered 503 because their handler produced no response",
                "requests");
        }

        /**
         * @brief Publish the Client's `inventory` bucket and the sync.indexer.* totals as pull metrics (I140, I141b).
         *
         * Same shape as registerTransportDiagnostics(): the pulls are registered once per registry (it is never
         * reset and has no unregister), behind a slot holding the Client WEAKLY plus a copy of the RuntimeRef --
         * never a shared_ptr<IClient>, which would keep a stopped Client alive inside the registry. Every start
         * repoints the slot; with no live Client every value reads 0, and a rebuilt Client starts its bucket
         * counters again from 0. One scrape costs one Client::metrics() call: the snapshot is cached for
         * INDEXER_METRICS_MAX_AGE and every getter reads from it.
         *
         * Called under m_lifecycleMutex (from startHttpServer()); the getters never take it.
         */
        void registerIndexerClientMetrics()
        {
            std::optional<indexer_client::RuntimeRef> runtime;
            if (m_config.indexer_runtime != nullptr)
            {
                runtime = *static_cast<const indexer_client::RuntimeRef*>(m_config.indexer_runtime);
            }
            m_indexerMetricsSlot->repoint(m_indexerClient, std::move(runtime));

            if (m_indexerClientPullsRegistered)
            {
                return;
            }
            m_indexerClientPullsRegistered = true;

            const auto slot = m_indexerMetricsSlot;

            // The catalog's names are fixed by the consumer and the bucket, so a shape with no values
            // enumerates them all; only the bucket's own metrics are published here (the 51 of I140).
            indexer_client::ClientMetrics shape;
            shape.consumer = invsync::indexer::INDEXER_CLIENT_CONSUMER;
            shape.buckets.emplace_back();
            shape.buckets.back().consumer = invsync::indexer::INDEXER_CLIENT_CONSUMER;
            shape.buckets.back().bucket = invsync::indexer::INVENTORY_BUCKET;
            const auto prefix = std::string("indexer_client.bucket.") +
                                indexer_client::sanitizeMetricName(invsync::indexer::INDEXER_CLIENT_CONSUMER) + "." +
                                indexer_client::sanitizeMetricName(invsync::indexer::INVENTORY_BUCKET) + ".";
            std::vector<std::pair<std::string, indexer_client::MetricKind>> names;
            indexer_client::forEachMetric(
                shape,
                [&names, &prefix](std::string_view name, indexer_client::MetricKind kind, double)
                {
                    if (name.substr(0, prefix.size()) == prefix)
                    {
                        names.emplace_back(std::string(name), kind);
                    }
                });

            for (const auto& [name, kind] : names)
            {
                m_metricsManager->registerPullMetric(
                    name,
                    [slot, name = name]
                    {
                        return slot->read(
                            [&name](const IndexerClientMetricsSlot& snapshot)
                            {
                                const auto it = snapshot.values.find(name);
                                return it == snapshot.values.end() ? std::uint64_t {0}
                                                                   : static_cast<std::uint64_t>(it->second);
                            });
                    },
                    kind == indexer_client::MetricKind::Counter
                        ? "indexer_client counter of the module's 'inventory' bucket (0 without a live client)"
                        : "indexer_client gauge of the module's 'inventory' bucket (0 without a live client)");
            }

            m_metricsManager->registerPullMetric(
                invsync::metrics::INDEXER_BULK_REQUESTS,
                [slot]
                { return slot->read([](const IndexerClientMetricsSlot& snapshot) { return snapshot.bulkRequests; }); },
                "_bulk requests the 'inventory' bucket completed, whatever their outcome",
                "requests");
            m_metricsManager->registerPullMetric(
                invsync::metrics::INDEXER_BULK_BYTES,
                [slot]
                { return slot->read([](const IndexerClientMetricsSlot& snapshot) { return snapshot.bulkBytes; }); },
                "Body bytes of those _bulk requests (resends count again)",
                "bytes");
            m_metricsManager->registerPullMetric(
                invsync::metrics::INDEXER_CONFLICT_RETRIES,
                [slot]
                {
                    return slot->read([](const IndexerClientMetricsSlot& snapshot)
                                      { return snapshot.conflictRetries; });
                },
                "Version-conflict retries of the process's indexer queries (by-query calls included)",
                "count");
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

        /// vd_workers <= 0 follows the same "half the cores, at least one" convention as
        /// sync_workers above -- the scanner's own per-slot pool (REQ-VDQ-7) makes
        /// raising this safe.
        static std::size_t resolveVdWorkers(const inventory_sync_server_config_t& config)
        {
            if (config.vd_workers > 0)
            {
                return static_cast<std::size_t>(config.vd_workers);
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
                    return {"indexer session",
                            "indexer.hosts and indexer.ssl.* in /etc/wazuh-manager/wazuh-manager.conf"};
                case FailureStage::SyncIndexerConnector:
                    // The Client comes from the process's runtime (I130): without one -- or with one
                    // that refuses this consumer -- the runtime's own startup error names the cause.
                    return {"sync indexer connector",
                            "the indexer client runtime's errors earlier in the log ('wazuh_modules.indexer_client_*', "
                            "indexer.* and the indexer credentials) and the 'inventory_sync_server_indexer_sync_*' "
                            "settings"};
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

            wazuh::uds_http::UdsHttpServerConfig serverConfig;
            nlohmann::json sessionConfig;
            nlohmann::json asyncConnectorConfig;
            IndexerSessionFactory sessionFactory;
            IndexerClientFactory clientFactory;
            IndexerConnectorSyncFactory syncFactory;
            const void* indexerRuntime {nullptr};
            indexer_client::BucketSpec bucketSpec;
            invsync::indexer::AdapterOptions adapterOptions;
            std::shared_ptr<std::atomic<bool>> closing;
            IndexerConnectorAsyncFactory asyncFactory;
            invsync::sync::SyncPipelineConfig pipelineConfig;
            std::size_t pipelineWorkers {1};
            std::string pipelineClusterName;
            invsync::vd::VdScanLaneConfig laneConfig;
            std::size_t laneWorkers {1};
            VdScannerFactory scannerFactory;
            bool vdConfiguredEnabled {false};
            std::uint64_t generation {0};
            bool needSession {false};
            bool needClient {false};
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
                serverConfig = invsync::buildServerConfig(m_config);
                m_resolvedSocketPath = serverConfig.socketPath;

                needSession = !m_indexerSession;
                needClient = !m_indexerClient;
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
                // Likewise one per cycle: stop() sets it (waking every adapter wait) and drops it, so
                // the next cycle's adapters start with a fresh, unset flag (I141).
                if (!m_indexerClosing)
                {
                    m_indexerClosing = std::make_shared<std::atomic<bool>>(false);
                }
                closing = m_indexerClosing;

                laneWorkers = resolveVdWorkers(m_config);
                laneConfig.workers = laneWorkers;
                laneConfig.queueSlots =
                    m_config.vd_scan_queue_slots > 0 ? static_cast<std::size_t>(m_config.vd_scan_queue_slots) : 0;
                laneConfig.retryAfterSeconds = m_config.vd_feed_retry_after_seconds > 0
                                                   ? m_config.vd_feed_retry_after_seconds
                                                   : DEFAULT_VD_RETRY_AFTER_SECS;
                scannerFactory = m_vdScannerFactory;
                vdConfiguredEnabled = m_config.vd_configured_enabled;

                sessionFactory = m_indexerSessionFactory;
                clientFactory = m_indexerClientFactory;
                syncFactory = m_indexerConnectorSyncFactory;
                asyncFactory = m_indexerConnectorAsyncFactory;

                pipelineWorkers = resolveSyncWorkers(m_config);
                pipelineConfig.maxQueueBytes = m_config.sync_queue_bytes > 0
                                                   ? static_cast<std::size_t>(m_config.sync_queue_bytes)
                                                   : DEFAULT_SYNC_QUEUE_BYTES;
                pipelineConfig.bulkFlushBytes = m_config.indexer_sync_max_bulk_size > 0
                                                    ? static_cast<std::size_t>(m_config.indexer_sync_max_bulk_size)
                                                    : DEFAULT_BULK_FLUSH_BYTES;
                pipelineConfig.sessionQueryBatchSize = m_config.session_query_batch_size;
                if (m_config.indexer_sync_max_retry_duration_seconds > 0)
                {
                    pipelineConfig.conflictRetryAfterSeconds = m_config.indexer_sync_max_retry_duration_seconds;
                }
                pipelineClusterName = invsync::common::buildClusterIdentity(m_config).clusterName;

                if (needSession || needClient || needSync || needAsync || needPipeline || needLane)
                {
                    logIndexerSummary();
                }

                // Built on every attempt: any slot below -- the lane included -- may consume these
                // on a retry where every other slot already succeeded.
                sessionConfig = invsync::indexer::buildSessionConfig(m_indexerConfig, m_config);
                asyncConnectorConfig = invsync::indexer::buildAsyncConnectorConfig(m_indexerConfig, m_config);

                // The sync half (E7b): the `inventory` bucket sized from the module's options and the
                // runtime's global quota (I138, I137b, I142b), and every worker's chunk cap over the
                // lanes that share it. snapshot() reads counters under leaf mutexes, no I/O.
                indexerRuntime = m_config.indexer_runtime;
                const auto globalQuota =
                    indexerRuntime != nullptr
                        ? static_cast<const indexer_client::RuntimeRef*>(indexerRuntime)->snapshot().globalQuotaBytes
                        : FALLBACK_GLOBAL_QUOTA_BYTES;
                const auto budgets = invsync::indexer::budgets(m_config);
                std::string bucketWarning;
                bucketSpec =
                    invsync::indexer::inventoryBucketSpec(m_config, globalQuota, INDEXER_BLOCK_TIMEOUT, &bucketWarning);
                if (!bucketWarning.empty() && !m_bucketWarningLogged)
                {
                    m_bucketWarningLogged = true;
                    LOGFN_WARN(moduleLogFn(),
                               "'wazuh_modules.inventory_sync_server_indexer_sync_connector_max_bulk_size': %s.",
                               bucketWarning.c_str());
                }
                const auto lanes = pipelineWorkers + laneWorkers;
                adapterOptions =
                    invsync::indexer::AdapterOptions {invsync::indexer::chunkCap(bucketSpec.quotaBytes, lanes),
                                                      INDEXER_BLOCK_SLICE,
                                                      budgets,
                                                      bucketSpec.retry,
                                                      INDEXER_PAGE_DEADLINE};
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
                                         sessionConfig,
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

            // The sync half's Client, from the process's runtime (I130, I144). Same stage as the
            // connectors built over it: a null runtime or a refused client() fails it with the cause,
            // and the heartbeat retries (I131). The v1 session above stays for the async connector.
            if (needClient && !buildAndPublish(m_indexerClient,
                                               FailureStage::SyncIndexerConnector,
                                               generation,
                                               [&] { return clientFactory(indexerRuntime, bucketSpec); }))
            {
                return;
            }

            // Same counted-reference dance as the session: every sync connector holds the Client.
            std::shared_ptr<indexer_client::IClient> client;
            {
                std::lock_guard<std::mutex> lock(m_lifecycleMutex);
                if (m_stopping || generation != m_startGeneration)
                {
                    return;
                }
                client = m_indexerClient;
            }

            if (!client)
            {
                return; // stop() raced us
            }

            if (needSync && !buildAndPublish(m_indexerConnectorSync,
                                             FailureStage::SyncIndexerConnector,
                                             generation,
                                             [&] { return syncFactory(client, adapterOptions, closing, "w0"); }))
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
                // sync connector as its first worker's connector, `w0` (it is otherwise idle -- its
                // other job is the endpoint's admission isAvailable(), which is thread-safe), and
                // builds one more per additional worker, `w<i>`, all sharing the Client.
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
                                    syncFactory(client, adapterOptions, closing, "w" + std::to_string(i)));
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
                            builtScanner = scannerFactory(vdConfiguredEnabled);
                            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors;
                            connectors.reserve(laneWorkers);
                            // One cancellation tag per scan-lane worker, `vd<i>`.
                            for (std::size_t i = 0; i < laneWorkers; ++i)
                            {
                                connectors.emplace_back(
                                    syncFactory(client, adapterOptions, closing, "vd" + std::to_string(i)));
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

        /// HTTP-over-UDS transport. shared_ptr (not unique) so the transport-diagnostics pull
        /// metrics can hold a WEAK reference that expires the moment stop() resets this.
        std::shared_ptr<wazuh::uds_http::IUdsHttpServer> m_httpServer;

        /// Pull metrics are registered once (there is no unregister -- iManager.hpp), but the
        /// server they observe is replaced per start attempt, so the getters resolve the current
        /// one through this weak target under its own tiny mutex (never the lifecycle mutex: a
        /// metrics dump must not be able to contend with stop()).
        mutable std::mutex m_transportDiagMutex;
        std::weak_ptr<wazuh::uds_http::IUdsHttpServer> m_transportDiagTarget;
        bool m_transportPullsRegistered {false};

        /**
         * @brief What the indexer_client pull metrics read (I140, I141b): the Client WEAKLY, a copy of the
         *        RuntimeRef, and the last snapshot, refreshed at most every INDEXER_METRICS_MAX_AGE.
         *
         * Owned by the facade and by every getter (shared_ptr), so it outlives the registry's use of it; its own
         * mutex, never m_lifecycleMutex, so a scrape cannot contend with stop().
         */
        struct IndexerClientMetricsSlot final
        {
            std::mutex mutex;
            std::weak_ptr<indexer_client::IClient> client;
            std::optional<indexer_client::RuntimeRef> runtime;
            bool fresh {false};
            std::chrono::steady_clock::time_point refreshedAt;
            std::unordered_map<std::string, double> values; ///< forEachMetric(ClientMetrics), by name.
            std::uint64_t bulkRequests {0};
            std::uint64_t bulkBytes {0};
            std::uint64_t conflictRetries {0};

            void repoint(std::weak_ptr<indexer_client::IClient> target,
                         std::optional<indexer_client::RuntimeRef> runtimeRef)
            {
                std::lock_guard<std::mutex> lock {mutex};
                client = std::move(target);
                runtime = std::move(runtimeRef);
                fresh = false;
            }

            template<typename TRead>
            std::uint64_t read(TRead&& reader)
            {
                std::lock_guard<std::mutex> lock {mutex};
                refreshLocked();
                return reader(*this);
            }

        private:
            void refreshLocked()
            {
                const auto now = std::chrono::steady_clock::now();
                if (fresh && now - refreshedAt < INDEXER_METRICS_MAX_AGE)
                {
                    return;
                }
                fresh = true;
                refreshedAt = now;
                values.clear();
                bulkRequests = 0;
                bulkBytes = 0;
                conflictRetries = 0;

                // Scoped: the strong reference lives only for this one call.
                const auto metrics = [this]
                {
                    const auto live = client.lock();
                    return live ? std::optional<indexer_client::ClientMetrics> {live->metrics()} : std::nullopt;
                }();
                if (!metrics)
                {
                    return; // no live Client: everything reads 0
                }

                indexer_client::forEachMetric(*metrics,
                                              [this](std::string_view name, indexer_client::MetricKind, double value)
                                              { values[std::string(name)] = value; });
                for (const auto& bucket : metrics->buckets)
                {
                    if (bucket.bucket == invsync::indexer::INVENTORY_BUCKET)
                    {
                        bulkRequests = bucket.bulkRequests;
                        bulkBytes = bucket.bulkBytes;
                    }
                }
                if (runtime)
                {
                    conflictRetries = runtime->snapshot().queries.conflictRetries;
                }
            }
        };
        const std::shared_ptr<IndexerClientMetricsSlot> m_indexerMetricsSlot {
            std::make_shared<IndexerClientMetricsSlot>()};
        bool m_indexerClientPullsRegistered {false};
        /// The bucket-sizing WARN (bulk cap clipped to the global quota) is said once per start().
        bool m_bucketWarningLogged {false};

        /*
         * The three indexer slots, each constructed at most once per start()/stop() cycle and memoised
         * independently -- see buildAndPublish(). The session is retained so a retry of one connector
         * does not pay for another round of host health checks.
         */
        /// shared_ptr, not unique_ptr: an in-flight attempt takes a counted reference so stop()
        /// clearing this member cannot dangle a connector constructor still running on it.
        std::shared_ptr<invsync::indexer::IIndexerSession> m_indexerSession;
        /// The sync half's indexer_client Client (consumer `inventory_sync_server`, bucket `inventory`;
        /// I130, I144), shared by every sync connector. stop() closes it before the lanes stop and
        /// drops it after they are joined (I141b).
        std::shared_ptr<indexer_client::IClient> m_indexerClient;
        /// Set by stop() before requestClose(); every adapter wait returns when it flips. One per cycle.
        std::shared_ptr<std::atomic<bool>> m_indexerClosing;
        /// Worker 0's sync connector, `w0`; also the /stateful admission's isAvailable(). shared_ptr
        /// because the endpoint handlers hold it weakly. The factory returns unique_ptr; the
        /// assignment converts.
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

        /// Production: the runtime modulesd published (I130). Null, or a client() it refuses, throws, so
        /// buildAndPublish() reports the sync stage with the reason and the heartbeat retries (I131).
        IndexerClientFactory m_indexerClientFactory {
            [](const void* runtime,
               const indexer_client::BucketSpec& bucket) -> std::shared_ptr<indexer_client::IClient>
            {
                if (runtime == nullptr)
                {
                    throw std::runtime_error("no indexer_client runtime in this process");
                }
                auto client = static_cast<const indexer_client::RuntimeRef*>(runtime)->client(
                    invsync::indexer::INDEXER_CLIENT_CONSUMER, {bucket});
                if (!client.ok())
                {
                    throw std::runtime_error(std::string("the indexer client refused the consumer (") +
                                             indexer_client::toString(client.cause) + "): " + client.reason);
                }
                return client.value;
            }};

        IndexerConnectorSyncFactory m_indexerConnectorSyncFactory {
            [](std::shared_ptr<indexer_client::IClient> client,
               const invsync::indexer::AdapterOptions& options,
               std::shared_ptr<const std::atomic<bool>> closing,
               const std::string& tag) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
            {
                return std::make_unique<invsync::indexer::IndexerClientSyncAdapter>(
                    std::move(client), options, std::move(closing), tag);
            }};

        VdScannerFactory m_vdScannerFactory {[](bool vdConfiguredEnabled)
                                             { return invsync::vd::makeProductionVdScanner(vdConfiguredEnabled); }};

        /*
         * The production async factory is the only place that knows the seam it is handed wraps a
         * real IndexerSession, so the unwrapping happens here. dynamic_cast on a reference rather
         * than static_cast on purpose: a test that installs a fake session but leaves the production
         * async factory in place then gets a std::bad_cast, which buildAndPublish() catches and
         * reports as a normal gate failure, instead of undefined behaviour.
         */
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
