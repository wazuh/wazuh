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

#include "auth/keystore.hpp"
#include "endpoints/authGateway.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "loggerHelper.h"
#include "remoted_module.h"
#include "singleton.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

constexpr auto REMOTED_MODULE_LOGTAG {"wazuh-manager-remoted:communication"}; ///< Tag used for remoted module logging.

// Heartbeat period for the skeleton worker loop.
constexpr auto REMOTED_MODULE_HEARTBEAT_SECS {60};

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
                   "Starting remoted module (workerThreads=%d, queueSize=%d, port=%d, cluster='%s', node='%s', "
                   "workerNode=%s).",
                   m_config.worker_threads,
                   m_config.queue_size,
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

            // Stop accepting/serving HTTPS before tearing down the rest.
            if (m_httpServer)
            {
                m_httpServer->stop();
                m_httpServer.reset();
            }
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
        // OUR transport, so swapping the HTTP library never touches it.
        m_keystore = std::make_shared<remoted::auth::Keystore>();
        m_authGateway = std::make_unique<remoted::endpoints::AuthGateway>(remoted::auth::AuthConfig {}, m_keystore);

        // Unauthenticated health probe (no request body, no auth).
        m_httpServer->addRoute(
            remoted::http::Method::Get,
            "/",
            [](const remoted::http::HttpRequest&, std::shared_ptr<remoted::http::IHttpResponder> responder)
            { responder->send(remoted::http::HttpResponse::json(200, R"({"status":"ok","module":"remoted"})")); });

        // Dummy /stateless: the gateway runs the full AES-CMAC validation and
        // only calls this handler once auth succeeds. It intentionally does NOT
        // parse the H/E payload or ingest anything -- it just validates and
        // returns 200. The 400/401/413 rejections are produced by the gateway.
        // TODO: parse the H/E payload's header (a JSON library is needed) and
        // check its embedded agent id against AuthenticatedRequest::agentId,
        // rejecting a mismatch with AuthError::PayloadAgentMismatch.
        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/stateless",
            [](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<remoted::http::IHttpResponder> responder)
            { responder->send(remoted::http::HttpResponse {200, "", {}}); });

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
};

#endif // _REMOTED_MODULE_FACADE_HPP
