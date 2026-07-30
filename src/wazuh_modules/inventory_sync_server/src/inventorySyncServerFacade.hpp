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
#include <string>
#include <thread>
#include <utility>

#include "endpoints/configEndpoint.hpp"
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
#include "singleton.hpp"
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

    /**
     * @brief RocksDB store path, RESERVED for the ingestion pipeline. Nothing opens it yet.
     *
     * Declared now, with hyphens, because getting it wrong is destructive rather than merely
     * broken: inventory_sync does a recursive remove of `queue/inventory_sync` at startup, and
     * `queue/inventory_sync_server` would be matched by an `inventory_sync*` glob. The hyphenated
     * form is unambiguously outside it.
     */
    [[maybe_unused]] constexpr auto INVENTORY_SYNC_SERVER_STORE_PATH {"queue/inventory-sync-server"};

    /**
     * @brief Internal engine of the inventory_sync_server module.
     *
     * Owns the worker std::thread and implements the canonical cooperative-shutdown lifecycle
     * (atomic flag + condition_variable + join), plus the HTTP-over-UDS transport behind our own
     * IUdsHttpServer interface.
     *
     * Deliberately does NOT touch the router. inventory_sync subscribes to the `inventory-states`
     * topic, and the router's remote-subscriber map is keyed by TOPIC rather than by subscriber id
     * -- so a second subscriber to that topic in this same process throws "Subscriber already
     * exist". Since inventory_sync is registered first, the throw would land here, be swallowed by
     * the extern "C" boundary, and leave this module silently dead. Ingress is UDS only.
     */
    class InventorySyncServerFacade final : public Singleton<InventorySyncServerFacade>
    {
    public:
        void start(const std::function<void(
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
                return;
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
            ++m_startGeneration;

            LOGFN_INFO(moduleLogFn(),
                       "Starting inventory sync server (cluster='%s', node='%s').",
                       m_config.cluster_name,
                       m_config.node_name);

            // The UDS server itself is started from run() (see tryStartHttpServer()), not here:
            // that keeps start() fast and non-throwing even when the socket path is not yet
            // usable, and gives us a retry loop for free.
            //
            // m_running is set only AFTER the thread exists. Setting it first would mean that a
            // throwing std::thread constructor (EAGAIN / resource exhaustion) leaves the facade
            // claiming to run with no worker: every later start() would then hit the "already
            // started" guard above and the module would stay permanently wedged, doing nothing.
            // run() never reads m_running, and both m_stopping and m_config are already set, so
            // deferring it is safe.
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

                // Phase 2: tear down the connectors and the session, in REVERSE construction order.
                //
                // All three unconditional -- NOT gated on m_httpServer, nor on each other -- because
                // the gate can legitimately leave only some of them built: the session alone, or the
                // session plus the sync connector (valid <indexer>, unbindable socket path, or a bad
                // max_retry_delay_seconds in just one family). Each carries live background threads
                // from the moment it is constructed, so gating one reset on another's pointer would
                // leak those threads on every stop() in that scenario.
                //
                // The monitoring thread belongs to the session and is reference-counted, so it dies
                // with whichever of the three goes last.
                //
                // These resets are still DESTRUCTIVE even though the /stats and /config handlers hold
                // the async connector: they hold it WEAKLY (see their makeHandler()). That is
                // deliberate -- the handler closures live in the transport's route table, which is
                // co-owned by every outstanding responder, so a strong capture would turn this reset
                // into "drop one of two references" and move the connector's destructor (and its
                // background threads) to phase 3, or later still, onto whatever thread releases the
                // last responder. Weak captures keep the teardown ordered here, where it is written.
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

            // Join outside the lifecycle lock so a concurrent start() can't deadlock.
            if (workerToJoin.joinable())
            {
                workerToJoin.join();
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

        /// TEST-ONLY. Forces one retry attempt synchronously instead of waiting out the real 60 s
        /// heartbeat. Never called in production.
        void forceRetryForTests()
        {
            tryStartHttpServer();
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
                   std::shared_ptr<invsync::http::IHttpResponder> responder) {
                    responder->send(
                        invsync::http::HttpResponse::json(200, R"({"status":"ok","module":"inventory_sync_server"})"));
                },
                /*countAgainstBudget=*/false);

            m_httpServer->addRoute(invsync::endpoints::sync::method(),
                                   invsync::endpoints::sync::path(),
                                   invsync::endpoints::sync::makeHandler());

            // Reached through remoted's authenticated /stats and /config routes. Registered separately
            // rather than sharing one handler because their real payloads will diverge.
            //
            // Both take the async indexer connector, which they hold WEAKLY (the shared_ptr converts
            // to the weak_ptr parameter implicitly) -- see stop()'s phase 2 for why that matters. Safe
            // to read the member here: buildAndPublish() publishes each slot as soon as it succeeds,
            // and this runs afterwards, in the same attempt.
            m_httpServer->addRoute(invsync::endpoints::stats::method(),
                                   invsync::endpoints::stats::path(),
                                   invsync::endpoints::stats::makeHandler(m_indexerConnectorAsync));

            m_httpServer->addRoute(invsync::endpoints::config::method(),
                                   invsync::endpoints::config::path(),
                                   invsync::endpoints::config::makeHandler(m_indexerConnectorAsync));

            m_httpServer->start(config);

            LOGFN_INFO(moduleLogFn(),
                       "inventory sync server listening on '%s' (routes: GET /, %s, %s and %s).",
                       config.socketPath.c_str(),
                       invsync::endpoints::sync::path(),
                       invsync::endpoints::stats::path(),
                       invsync::endpoints::config::path());
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

        /// Which part of tryStartHttpServer()'s work a failure belongs to. Four stages, not two,
        /// because the ERROR must name WHICH object failed: each has its own, independently tunable
        /// option family, and pointing an operator at the wrong one costs a debugging session.
        enum class FailureStage
        {
            IndexerSession,
            SyncIndexerConnector,
            AsyncIndexerConnector,
            HttpServer
        };

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
                case FailureStage::IndexerSession:
                    return {"indexer session", "the <indexer> configuration block (hosts, ssl.*)"};
                case FailureStage::SyncIndexerConnector:
                    return {"sync indexer connector", "the 'inventory_sync_server_indexer_sync_*' settings"};
                case FailureStage::AsyncIndexerConnector:
                    return {"async indexer connector", "the 'inventory_sync_server_indexer_async_*' settings"};
                case FailureStage::HttpServer: return {"UDS socket", "the 'inventory_sync_server_socket_path' setting"};
            }
            return {"unknown stage", "the module configuration"};
        }

        /**
         * @brief Builds ONE indexer object outside the lifecycle lock, then publishes it into @p slot.
         *
         * The only try/catch around indexer construction in this class, used for all three slots.
         *
         * The gate each of them feeds is deliberately just "did construction throw", never "is the
         * indexer currently reachable": the constructors validate configuration synchronously (hosts
         * present, referenced CA files exist, max_retry_delay_seconds sane) and throw on failure,
         * while a host that is merely unreachable does NOT throw -- it only stays unavailable until
         * the monitor sees it come up. The indexer is allowed to start after modulesd.
         *
         * Publishing happens immediately on success rather than once at the end of the attempt. That
         * is load-bearing: a successful construction is a "configuration is valid" signal that cannot
         * change without a restart, so it must never be repeated -- and if the object were held as a
         * local until every stage succeeded, a persistently failing LATER stage would discard it and
         * rebuild it on the next heartbeat. For the session that would mean another full round of
         * per-host health checks every minute, which is exactly the cost sharing it removes.
         * `TheSucceedingSlotsAreNotRebuiltWhileAnotherRetries` pins this.
         *
         * Construction runs WITHOUT m_lifecycleMutex so stop() is never queued behind the health
         * checks; the lock is taken only for the publish, and the generation re-check there is what
         * keeps a stale attempt from publishing into a newer start()/stop() cycle.
         *
         * @return false if this attempt must not continue -- either the build failed (already reported
         *         via reportFailedStart()) or the cycle moved on, in which case the freshly built
         *         object is dropped here.
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
         * Three phases, so that the slow part does NOT hold the mutex stop() needs. Building the
         * session performs a synchronous `GET /_cat/health` per configured host (5 s timeout each);
         * with that inside m_lifecycleMutex, a stop() arriving from modulesd's signal handler would
         * queue behind it, and modulesd shares one 30 s budget across every module.
         *
         * Note what this does and does not buy: stop() joins the worker thread, so moving the
         * construction out of the lock does not by itself shorten the wait when the worker is already
         * inside a constructor. What it does is let stop() SET m_stopping immediately instead of
         * queueing, which is what makes the m_stopping checks in phase B able to bail early. The two
         * are complementary. Combined with the connectors sharing the session's single health-check
         * round, the worst case stays at ONE round -- adding the async connector costs nothing here.
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
            std::uint64_t generation {0};
            bool needSession {false};
            bool needSync {false};
            bool needAsync {false};

            // ---- Phase A: snapshot under the lifecycle lock. No I/O, so stop() never waits. ----
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

                sessionFactory = m_indexerSessionFactory;
                syncFactory = m_indexerConnectorSyncFactory;
                asyncFactory = m_indexerConnectorAsyncFactory;

                if (needSession || needSync || needAsync)
                {
                    logIndexerSummary();
                    rawIndexerConfig = m_indexerConfig;
                    syncConnectorConfig = invsync::indexer::buildSyncConnectorConfig(m_indexerConfig, m_config);
                    asyncConnectorConfig = invsync::indexer::buildAsyncConnectorConfig(m_indexerConfig, m_config);
                }
            }

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
                                 [&] {
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
                catch (...)
                {
                    reportFailedStart(FailureStage::HttpServer, "non-standard exception");
                    m_httpServer.reset();
                }
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
                    LOGFN_ERROR(
                        moduleLogFn(),
                        "The inventory sync server could not start on '%s': %s. Retrying every %d s. Check the "
                        "'inventory_sync_server_socket_path' setting and that the directory exists and is writable.",
                        m_resolvedSocketPath.c_str(),
                        reason,
                        INVENTORY_SYNC_SERVER_HEARTBEAT_SECS);
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
            catch (...)
            {
                LOGFN_ERROR(moduleLogFn(),
                            "The inventory sync server worker thread stopped on a non-standard exception.");
            }
        }

        void runLoop()
        {
            LOGFN_INFO(moduleLogFn(), "inventory sync server worker thread running.");

            while (true)
            {
                tryStartHttpServer();

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
        std::thread m_worker;                ///< The C++ thread launched for this module.

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
         * independently -- see buildAndPublish(). The session is retained even though the library does
         * not require it (a connector holds a counted reference to the monitor and copies the transport
         * settings, so the session could be dropped): keeping it means a retry of one connector does
         * not pay for another round of host health checks.
         */
        /// shared_ptr, not unique_ptr: an in-flight attempt takes a counted reference so it can keep
        /// building connectors on the session outside the lifecycle lock even if stop() clears this
        /// member meanwhile. With a unique_ptr that would be a dangling reference inside a running
        /// connector constructor.
        std::shared_ptr<invsync::indexer::IIndexerSession> m_indexerSession;
        std::unique_ptr<invsync::indexer::IIndexerConnectorSync> m_indexerConnectorSync;
        /// shared_ptr, not unique_ptr, for a different reason than the session above: the /stats and
        /// /config handlers need a reference to it, and the only kind that keeps stop()'s phase-2 reset
        /// destructive is a WEAK one -- which requires a shared owner here. See stop() and the
        /// endpoints' makeHandler(). The factory still returns a unique_ptr; the conversion happens on
        /// assignment in buildAndPublish().
        std::shared_ptr<invsync::indexer::IIndexerConnectorAsync> m_indexerConnectorAsync;

        IndexerSessionFactory m_indexerSessionFactory {
            [](const nlohmann::json& config, LoggingContext logging)
            {
                return std::make_unique<invsync::indexer::IndexerSessionAdapter>(config, std::move(logging));
            }};

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
