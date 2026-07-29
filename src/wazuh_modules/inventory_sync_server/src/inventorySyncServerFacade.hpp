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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "endpoints/syncEndpoint.hpp"
#include "http_server/IUdsHttpServer.hpp"
#include "http_server/udsHttpServerConfig.hpp"
#include "http_server/udsHttpServerFactory.hpp"
#include "inventory_sync_server.h"
#include "loggerHelper.h"
#include "singleton.hpp"
#include <json.hpp>

namespace invsync
{

    /// Tag used for this module's logging. A literal rather than modulesd's ARGV0, matching how
    /// inventory_sync's C++ side does it -- and deliberately distinct from `:inventory-sync` so an
    /// operator can tell the two modules apart in wazuh-manager.log while both are running.
    constexpr auto INVENTORY_SYNC_SERVER_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server"};

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
            m_stopping = false;

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

                // Phase 2: drain the ingestion pipeline. Nothing to drain yet -- this is where the
                // FlatBuffer/indexer pipeline's shutdown goes, and it must happen HERE, between the
                // two transport phases, so its in-flight responders are still deliverable.

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

    private:
        void startHttpServer(const invsync::http::UdsHttpServerConfig& config)
        {
            m_httpServer = invsync::http::makeUdsHttpServer();

            logIndexerSummary();

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

            m_httpServer->start(config);

            LOGFN_INFO(moduleLogFn(),
                       "inventory sync server listening on '%s' (routes: GET / and %s).",
                       config.socketPath.c_str(),
                       invsync::endpoints::sync::path());
        }

        /**
         * @brief Report what arrived in the <indexer> block, without its secrets.
         *
         * The indexer connector is not wired up yet, so this is the only consumer of the parsed
         * configuration. It exists so the C-ABI's `indexer` field is exercised and diagnosable from
         * day one rather than on the day the connector lands: a misconfigured <indexer> shows up
         * here as `hosts=0` instead of as a silent failure later.
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
                         "ssl.certificate=%s, ssl.key=%s. Not used yet (the indexer connector is not wired up).",
                         arraySize("hosts"),
                         caCount,
                         hasCertificate ? "<set>" : "<unset>",
                         hasKey ? "<set>" : "<unset>");
        }

        void tryStartHttpServer()
        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);

            if (m_stopping || m_httpServer)
            {
                return;
            }

            // Resolved once per attempt and kept, so the failure path can name the actual path
            // without rebuilding the configuration (and so the two can never disagree).
            const auto config = invsync::http::buildServerConfig(m_config);
            m_resolvedSocketPath = config.socketPath;

            try
            {
                startHttpServer(config);
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
                reportFailedStart(e.what());
                m_httpServer.reset();
            }
            catch (...)
            {
                reportFailedStart("non-standard exception");
                m_httpServer.reset();
            }
        }

        /**
         * @brief Escalating report for a failed server start.
         *
         * The first attempt is an ERROR naming the real reason and the setting to check, so a
         * permanent misconfiguration (an unwritable path, a leftover non-socket file, a directory
         * that does not exist) is visible immediately. The next hour of retries stays at debug so a
         * transient condition does not flood, and after that one WARN per hour keeps it visible.
         */
        void reportFailedStart(const char* reason)
        {
            ++m_failedStartAttempts;

            // 60 attempts at one per heartbeat (60 s) == roughly one hour.
            constexpr int ATTEMPTS_PER_ESCALATION {60};

            if (m_failedStartAttempts == 1)
            {
                LOGFN_ERROR(
                    moduleLogFn(),
                    "The inventory sync server could not start on '%s': %s. Retrying every %d s. Check the "
                    "'inventory_sync_server_socket_path' setting and that the directory exists and is writable.",
                    m_resolvedSocketPath.c_str(),
                    reason,
                    INVENTORY_SYNC_SERVER_HEARTBEAT_SECS);
            }
            else if (m_failedStartAttempts % ATTEMPTS_PER_ESCALATION == 0)
            {
                LOGFN_WARN(moduleLogFn(),
                           "The inventory sync server is still not running after %d attempt(s) (~%d minute(s)): %s",
                           m_failedStartAttempts,
                           m_failedStartAttempts * INVENTORY_SYNC_SERVER_HEARTBEAT_SECS / 60,
                           reason);
            }
            else
            {
                LOGFN_DEBUG1(
                    moduleLogFn(), "inventory sync server start attempt %d failed: %s", m_failedStartAttempts, reason);
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

        std::mutex m_lifecycleMutex;         ///< Serializes start()/stop().
        std::mutex m_waitMutex;              ///< Guards the heartbeat wait.
        std::condition_variable m_waitCv;    ///< Wakes the worker on stop.
        std::atomic_bool m_stopping {false}; ///< Cooperative-shutdown flag.
        bool m_running {false};              ///< Whether the worker is active.
        int m_failedStartAttempts {0};       ///< Consecutive failed server starts; drives log escalation.
        std::thread m_worker;                ///< The C++ thread launched for this module.

        inventory_sync_server_config_t m_config {}; ///< Copy of the caller's configuration.
        std::string m_resolvedSocketPath;           ///< Path of the most recent start attempt, for diagnostics.
        /// Owned copy of the <indexer> block. Reserved for the indexer connector; only
        /// logIndexerSummary() reads it today.
        nlohmann::json m_indexerConfig {nlohmann::json::object()};

        std::unique_ptr<invsync::http::IUdsHttpServer> m_httpServer; ///< HTTP-over-UDS transport.
    };

} // namespace invsync

#endif // _INVENTORY_SYNC_SERVER_FACADE_HPP
