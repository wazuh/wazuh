/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_FACADE_HPP
#define _REMOTED_MODULE_FACADE_HPP

#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "auth/keystore.hpp"
#include "downstream/asioUdsHttpClient.hpp"
#include "downstream/deferredForwarder.hpp"
#include "downstream/deferredWorkLimiter.hpp"
#include "downstream/downstreamConfig.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/statelessEndpoint.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "loggerHelper.h"
#include "remoted_module.h"
#include "singleton.hpp"

constexpr auto REMOTED_MODULE_LOGTAG {"wazuh-manager-remoted:communication"}; ///< Tag used for remoted module logging.

// Heartbeat period for the skeleton worker loop.
constexpr auto REMOTED_MODULE_HEARTBEAT_SECS {60};

// Default cap on requests parked awaiting a downstream service (used when the caller leaves
// remoted_module_config_t::max_deferred_requests <= 0).
constexpr int REMOTED_MODULE_DEFAULT_MAX_DEFERRED {256};

/**
 * @brief Internal engine of the remoted module.
 *
 * Owns the worker std::thread and implements the canonical cooperative-shutdown
 * lifecycle (atomic flag + condition_variable + join), plus the HTTPS transport
 * (our IHttpServer) and the framework-agnostic auth layer wired on top of it.
 */
class RemotedModuleFacade final : public Singleton<RemotedModuleFacade>
{
public:
    void
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction,
          const remoted_module_config_t& configuration)
    {
        std::lock_guard<std::mutex> lock(m_lifecycleMutex);

        // Route the module's LOGFN_* calls back through remoted's logger.
        Log::assignLogFunction(logFunction);

        if (m_running)
        {
            LOGFN_WARN(m_logFn, "remoted module already started, ignoring start request.");
            return;
        }

        m_config = configuration;
        m_stopping = false;
        m_running = true;

        LOGFN_INFO(m_logFn,
                   "Starting remoted module (port=%d, cluster='%s', node='%s', workerNode=%s).",
                   m_config.port,
                   m_config.cluster_name,
                   m_config.node_name,
                   m_config.worker_node ? "true" : "false");

        // The HTTPS server itself is started from run() (see tryStartHttpServer()),
        // not here: that keeps start() fast and non-throwing even when the
        // certificate/key aren't in place yet.
        m_worker = std::thread(&RemotedModuleFacade::run, this);
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

            LOGFN_INFO(m_logFn, "Stopping remoted module.");

            // Phase 1: stop ACCEPTING new connections/requests and drain the handler worker
            // pool. After this returns, no RouteHandler -- and therefore no forward() call --
            // will ever run again, but the HTTP server's I/O runtime is deliberately still
            // alive: a response to a request already forwarded before this point must still be
            // able to reach it safely (see phases 2-3).
            if (m_httpServer)
            {
                m_httpServer->stopAccepting();
            }

            // Phase 2: abort in-flight downstream UDS sessions (no new completions can arrive).
            if (m_downstreamClient)
            {
                m_downstreamClient->stop();
            }

            // Phase 3: drain the post-processing pool. Anything that was mid-flight when phase 1
            // ran completes here; its responder->send() is still safe -- the HTTP server's I/O
            // runtime hasn't been torn down yet (that's phase 4, below).
            m_forwarder.reset();
            m_downstreamClient.reset();
            m_deferredLimiter.reset();

            // Phase 4: NOW it's safe to fully tear down the transport (releases the I/O
            // runtime). Nothing can still be touching a responder: worker pool B was drained in
            // phase 1, the post-processing pool D was drained in phase 3, and phase 2 stopped
            // the downstream client so nothing new can reach D either.
            m_httpServer.reset();

            m_authGateway.reset();
            m_keystore.reset();

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

        LOGFN_INFO(m_logFn, "remoted module stopped.");
    }

private:
    void startHttpServer()
    {
        const auto config = remoted::http::buildHttpServerConfig(m_config);

        m_httpServer = remoted::http::makeHttpServer();

        // Framework-agnostic auth layer: reads agent keys from client.keys and
        // verifies the AES-CMAC of every authenticated request. Wired on top of
        // OUR transport, so swapping the HTTP library never touches it. The keystore
        // hot-reloads client.keys on its own (background watcher, see keystore.hpp) --
        const auto keystoreRefreshSeconds = m_config.keystore_refresh_interval > 0
                                                ? m_config.keystore_refresh_interval
                                                : remoted::auth::Keystore::kDefaultRefreshIntervalSeconds;
        m_keystore =
            std::make_shared<remoted::auth::Keystore>(remoted::auth::Keystore::kDefaultPath, keystoreRefreshSeconds);
        m_authGateway =
            std::make_unique<remoted::endpoints::AuthGateway>(remoted::auth::buildAuthConfig(m_config), m_keystore);

        // Deferred-work limiter: bounds requests parked awaiting a downstream service. A slot is
        // held from the moment a request enters the deferred stage until its reply is delivered;
        // when full, the forwarder sheds load with a plain 503 (the agent runs its own retry) -- the
        // second half of the two-phase backpressure (the byte budget covers receive+send, this the wait).
        const auto maxDeferred = m_config.max_deferred_requests > 0
                                     ? static_cast<std::size_t>(m_config.max_deferred_requests)
                                     : static_cast<std::size_t>(REMOTED_MODULE_DEFAULT_MAX_DEFERRED);
        m_deferredLimiter = std::make_shared<remoted::downstream::DeferredWorkLimiter>(maxDeferred);

        // Async UDS client + forwarder for the deferred stage. The client owns its own io_context
        // (RESTinio keeps its loop private); the forwarder owns a post-processing pool. Started here
        // so it is ready to forward as soon as the server accepts.
        const auto downstreamConfig = remoted::downstream::buildDownstreamConfig(m_config);
        auto downstreamClient = std::make_shared<remoted::downstream::AsioUdsHttpClient>(downstreamConfig);
        downstreamClient->start();
        m_downstreamClient = downstreamClient;
        m_forwarder = std::make_unique<remoted::downstream::DeferredForwarder>(
            downstreamClient, m_deferredLimiter, downstreamConfig.postProcessThreads);
        const std::string eventsSocketPath = downstreamConfig.eventsSocketPath;

        // Unauthenticated health probe (no request body, no auth). Exempt from the in-flight
        // byte budget (countAgainstBudget=false) so liveness stays 200 even under memory pressure.
        m_httpServer->addRoute(
            remoted::http::Method::Get,
            "/",
            [](std::shared_ptr<const remoted::http::HttpRequest>,
               std::shared_ptr<remoted::http::IHttpResponder> responder)
            { responder->send(remoted::http::HttpResponse::json(200, R"({"status":"ok","module":"remoted"})")); },
            /*countAgainstBudget=*/false);

        // /stateless: the gateway runs the full AES-CMAC validation and only calls this handler once
        // auth succeeds; makeHandler() then cross-checks the payload's claimed wazuh.agent.id against
        // the authenticated agent id (400 PayloadAgentMismatch on mismatch/malformed header), and on
        // success the forwarder acquires a deferred-work slot (plain 503 when full), forwards the H/E
        // batch to the engine's event ingress over UDS, and replies from the downstream result (202
        // accepted / 400 bad batch / 413 / 503). The payload + byte budget are freed once the send
        // completes. The 400/401/413 auth rejections are produced by the gateway.
        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/stateless",
            remoted::endpoints::stateless::makeHandler(*m_forwarder, eventsSocketPath));

        m_httpServer->start(config);
    }

    void tryStartHttpServer()
    {
        std::lock_guard<std::mutex> lock(m_lifecycleMutex);

        if (m_stopping || m_httpServer)
        {
            return;
        }

        try
        {
            startHttpServer();
            LOGFN_INFO(m_logFn, "remoted HTTP server started.");
        }
        catch (const std::exception& e)
        {
            // Most likely cause: certificate/key not in place yet (fresh
            // install). Leave everything reset and try again next heartbeat.
            LOGFN_WARN(m_logFn, "remoted HTTP server not started yet, will retry: %s", e.what());
            m_httpServer.reset();
            if (m_downstreamClient)
            {
                m_downstreamClient->stop();
            }
            m_forwarder.reset();
            m_downstreamClient.reset();
            m_deferredLimiter.reset();
            m_authGateway.reset();
            m_keystore.reset();
        }
    }

    void run()
    {
        LOGFN_INFO(m_logFn, "remoted module worker thread running.");

        while (true)
        {
            tryStartHttpServer();

            std::unique_lock<std::mutex> lock(m_waitMutex);
            if (m_stopping)
            {
                break;
            }

            LOGFN_DEBUG1(m_logFn, "remoted module heartbeat.");
            m_waitCv.wait_for(
                lock, std::chrono::seconds(REMOTED_MODULE_HEARTBEAT_SECS), [this]() { return m_stopping.load(); });

            if (m_stopping)
            {
                break;
            }
        }

        LOGFN_INFO(m_logFn, "remoted module worker thread finished.");
    }

    const LogFn m_logFn {REMOTED_MODULE_LOGTAG};
    std::mutex m_lifecycleMutex;         ///< Serializes start()/stop().
    std::mutex m_waitMutex;              ///< Guards the heartbeat wait.
    std::condition_variable m_waitCv;    ///< Wakes the worker on stop.
    std::atomic_bool m_stopping {false}; ///< Cooperative-shutdown flag.
    bool m_running {false};              ///< Whether the worker is active.
    std::thread m_worker;                ///< The C++ thread launched for remoted.
    remoted_module_config_t m_config {}; ///< Copy of the caller's configuration.

    std::unique_ptr<remoted::http::IHttpServer> m_httpServer;       ///< HTTPS transport (behind our interface).
    std::shared_ptr<remoted::auth::IAgentKeystore> m_keystore;      ///< Agent AES-key lookup (client.keys).
    std::unique_ptr<remoted::endpoints::AuthGateway> m_authGateway; ///< Auth layer wired onto m_httpServer.
    std::shared_ptr<remoted::downstream::DeferredWorkLimiter> m_deferredLimiter; ///< Bounds parked downstream work.
    std::shared_ptr<remoted::downstream::AsioUdsHttpClient> m_downstreamClient;  ///< Async UDS client (own io_context).
    std::unique_ptr<remoted::downstream::DeferredForwarder> m_forwarder; ///< Forwards to the downstream service.
};

#endif // _REMOTED_MODULE_FACADE_HPP
