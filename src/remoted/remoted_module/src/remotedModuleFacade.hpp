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
#include "common/vdClient.hpp"
#include "control/agentRegistry.hpp"
#include "control/controlConfig.hpp"
#include "control/controlHandler.hpp"
#include "control/hashCache.hpp"
#include "control/metrics.hpp"
#include "control/taskClient.hpp"
#include "control/wazuhDBClient.hpp"
#include "decoding/bodyDecoder.hpp"
#include "downstream/asioUdsHttpClient.hpp"
#include "downstream/deferredForwarder.hpp"
#include "downstream/deferredWorkLimiter.hpp"
#include "downstream/downstreamConfig.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/configEndpoint.hpp"
#include "endpoints/controlEndpoint.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "endpoints/scanVdEndpoint.hpp"
#include "endpoints/statefulEndpoint.hpp"
#include "endpoints/statelessEndpoint.hpp"
#include "endpoints/statsEndpoint.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "loggerHelper.h"
#include "remoted_module.h"
#include "scanvd/scanVdHandler.hpp"
#include "singleton.hpp"

constexpr auto REMOTED_MODULE_LOGTAG {"wazuh-manager-remoted:communication"}; ///< Tag used for remoted module logging.

/// Not a member: LogFn has hidden ELF visibility (loggerHelper.h wraps everything in a visibility
/// pragma), so holding one as a field of this default-visibility class trips -Wattributes. A
/// function-local static also costs one allocation ever instead of one per log call.
inline const LogFn& moduleLogFn()
{
    static const LogFn instance {REMOTED_MODULE_LOGTAG};
    return instance;
}

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
    /**
     * @brief Start the module: brings up the HTTPS transport synchronously and,
     *        only on success, launches the worker thread.
     *
     * Throws if the HTTPS transport fails to start (most commonly: the TLS
     * certificate/key are not in place, or unreadable). There is no retry: the
     * failure is logged (so the reason is visible in remoted's own log, since an
     * uncaught exception reaching secure.c/remoted.c's plain-C frames would
     * otherwise terminate the process with nothing but a bare libstdc++ message
     * on stderr) and then rethrown as-is. A missing certificate is fatal to the
     * module, and thus to remoted -- it must not start without it.
     */
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
            LOGFN_WARN(moduleLogFn(), "remoted module already started, ignoring start request.");
            return;
        }

        m_config = configuration;

        LOGFN_INFO(moduleLogFn(),
                   "Starting remoted module (port=%d, cluster='%s', workerNode=%s).",
                   m_config.port,
                   m_config.cluster_name,
                   m_config.worker_node ? "true" : "false");

        // Logged here and rethrown, NOT swallowed into a retry: a failure to start (e.g.
        // missing/unreadable certificate or key) must still reach the caller as an exception, but
        // without this log line it would otherwise crash the process with nothing but a bare
        // libstdc++ "terminate called..." on stderr -- which remoted's daemonized process
        // typically never surfaces anywhere the operator can see it.
        try
        {
            startHttpServer();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(moduleLogFn(), "remoted HTTP server failed to start: %s", e.what());
            throw;
        }
        LOGFN_INFO(moduleLogFn(), "remoted HTTP server started.");

        // m_running is set only AFTER the worker thread exists. Setting it first meant that a
        // throwing std::thread constructor (EAGAIN / resource exhaustion) left the facade claiming
        // to run with no worker: every later start() then hit the "already started" guard above and
        // the module stayed permanently wedged, doing nothing.
        m_stopping = false;
        try
        {
            m_worker = std::thread(&RemotedModuleFacade::run, this);
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(moduleLogFn(), "Could not launch the remoted module worker thread: %s.", e.what());
            resetHttpServerStack();
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

            LOGFN_INFO(moduleLogFn(), "Stopping remoted module.");

            // Phase 1: stop ACCEPTING new connections/requests and drain the handler worker
            // pool. After this returns, no RouteHandler -- and therefore no forward() call --
            // will ever run again, but the HTTP server's I/O runtime is deliberately still
            // alive: a response to a request already forwarded before this point must still be
            // able to reach it safely (see phases 2-3).
            if (m_httpServer)
            {
                m_httpServer->stopAccepting();
            }

            // Phase 1b: tear down the /control and /scan/vd state. The /control handler's dtor
            // stops the eviction thread, then drops the wdb/task async clients -- their dtors
            // join workers and fail any pending callbacks, which invoke the endpoint's
            // responder->send() with a 500 body. The HTTP server's I/O runtime is still alive
            // (phase 4 hasn't run), so those late sends are safe. This runs BEFORE the downstream
            // client stop so that its own stop() does not race with wdb-worker joins that touch
            // the same io_context runtime via the response send path.
            m_controlHandler.reset();
            m_scanVdHandler.reset();

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

        LOGFN_INFO(moduleLogFn(), "remoted module stopped.");
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
        // The Content-Encoding contract is composed in here rather than built into the gateway, so
        // the auth layer stays about authentication only. Configured once on the gateway (not per
        // route), so every authenticated endpoint gets it and none can accidentally opt out.
        const auto authConfig = remoted::auth::buildAuthConfig(m_config);
        m_authGateway = std::make_unique<remoted::endpoints::AuthGateway>(
            authConfig,
            m_keystore,
            std::make_shared<const remoted::decoding::BodyDecoder>(*m_httpServer,
                                                                   m_config.http_content_encoding_enabled));

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
        const std::string inventorySyncSocketPath = downstreamConfig.inventorySyncSocketPath;

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

        // /download: streams merged.mg and WPK packages with chunked transfer encoding. Registered
        // ResponseMode::Streamable because the transport fixes a response's output mode when the
        // request is dispatched -- a Buffered registration would make every download answer 500.
        //
        // resource_id is the group (or WPK filename) the agent requests and the manager serves
        // exactly that; there is no group lookup and no membership check (protocol decision on
        // #38022). Containment therefore rests on the resource-id grammars plus O_NOFOLLOW.
        m_authGateway->addAuthenticatedRoute(*m_httpServer,
                                             remoted::http::Method::Post,
                                             "/download",
                                             remoted::endpoints::download::makeHandler(),
                                             remoted::http::ResponseMode::Streamable);

        // /stateless takes the client's default response deadline (its target leaves the override
        // at 0), so that is what gets checked against the transport's request cap.
        warnIfDownstreamBudgetExceedsRequestTimeout(
            "/stateless", downstreamConfig, config, remoted::endpoints::stateless::target(eventsSocketPath));

        // /stats and /config: same authenticated pipeline as /stateless, but forwarded to modulesd's
        // inventory sync server instead of the engine.
        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/stats",
            remoted::endpoints::stats::makeHandler(*m_forwarder, inventorySyncSocketPath));

        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/config",
            remoted::endpoints::config::makeHandler(*m_forwarder, inventorySyncSocketPath));

        // Both leave the per-endpoint response override at 0 as well, so they are checked against the
        // same cap. The agent id passed here is irrelevant to the check -- only the timeouts matter --
        // so a placeholder keeps this from needing a real request.
        warnIfDownstreamBudgetExceedsRequestTimeout(
            "/stats", downstreamConfig, config, remoted::endpoints::stats::target(inventorySyncSocketPath, "0"));
        warnIfDownstreamBudgetExceedsRequestTimeout(
            "/config", downstreamConfig, config, remoted::endpoints::config::target(inventorySyncSocketPath, "0"));

        // /stateful: inventory synchronization sessions (FlatBuffer FullSession, opaque to
        // remoted). Same authenticated pipeline, forwarded to the sync server with the
        // authenticated agent id as X-Wazuh-Agent-Id; the downstream result is passed through to
        // the agent (status + body + Retry-After) -- it IS the session result, unlike the
        // enqueue-style endpoints above. Sessions index within the request, so the route carries
        // its own, longer response deadline (remoted.downstream_stateful_response_timeout).
        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/stateful",
            remoted::endpoints::stateful::makeHandler(
                *m_forwarder, inventorySyncSocketPath, downstreamConfig.statefulResponseTimeoutMs));

        warnIfDownstreamBudgetExceedsRequestTimeout(
            "/stateful",
            downstreamConfig,
            config,
            remoted::endpoints::stateful::target(
                inventorySyncSocketPath, "0", downstreamConfig.statefulResponseTimeoutMs));

        // /control: agent lifecycle (startup / notify / shutdown). Same auth path as /stateless
        // -- the gateway runs the full AES-CMAC validation and only calls this handler once auth
        // succeeds. controlEndpoint::makeHandler() parses the JSON body's "type" field and
        // dispatches to ControlHandler::handleStartup/handleNotify/handleShutdown; ControlHandler
        // then talks to wazuh-db and the task manager over UDS (its own async clients, NOT the
        // /stateless forwarder), so this endpoint's replies do not compete with H/E ingestion for
        // deferred-work slots. Registered AFTER /stateless so a startup failure here (e.g. bad
        // control_ define) unwinds via resetHttpServerStack() with the same state discipline.
        //
        // Lifetime: m_controlHandler outlives the route (see stop()/resetHttpServerStack()):
        // stopAccepting() drains the HTTP worker pool BEFORE m_controlHandler.reset(), so no
        // in-flight endpoint lambda can touch a destroyed handler. ControlMetrics is a value
        // member on this facade, so its address stays stable across HTTP-server retries and
        // counters carry over -- desirable for observability.
        const auto controlConfig = remoted::control::buildControlConfig(m_config);
        auto vdClient = std::make_shared<remoted::common::VdClient>();
        m_controlHandler = std::make_unique<remoted::control::ControlHandler>(
            std::make_shared<remoted::control::AgentRegistry>(),
            std::make_shared<remoted::control::WazuhDBClient>(controlConfig.wdbSocketPath,
                                                              controlConfig.wdbRequestConnections,
                                                              controlConfig.wdbRoundtripDeadlineMs,
                                                              controlConfig.wdbMaxQueueSize,
                                                              m_controlMetrics),
            std::make_shared<remoted::control::TaskClient>(controlConfig.taskSocketPath,
                                                           controlConfig.tmConcurrency,
                                                           controlConfig.tmDeadlineMs,
                                                           controlConfig.tmMaxQueueSize,
                                                           m_controlMetrics),
            std::make_shared<remoted::control::HashCache>(controlConfig),
            vdClient,
            m_controlMetrics,
            controlConfig);

        m_authGateway->addAuthenticatedRoute(*m_httpServer,
                                             remoted::http::Method::Post,
                                             "/control",
                                             remoted::endpoints::control::makeHandler(*m_controlHandler));

        // /scan/vd: agent-initiated VD scans. Uses the same vdClient as /control for offset
        // queries (queue/sockets/modulesd), but triggers the scan itself over VD's separate,
        // dedicated scan socket (queue/sockets/modulesd-vdscan -- see ScanVdHandlerImpl's default
        // argument) so a burst of long-running scans can never starve /offset queries.
        m_scanVdHandler = std::make_unique<remoted::scanvd::ScanVdHandlerImpl>(vdClient, m_scanVdMetrics);

        m_authGateway->addAuthenticatedRoute(*m_httpServer,
                                             remoted::http::Method::Post,
                                             "/scan/vd",
                                             remoted::endpoints::scanvd::makeHandler(*m_scanVdHandler));

        m_httpServer->start(config);
    }

    /**
     * @brief Warns when an endpoint's downstream deadlines cannot actually be honored.
     *
     * RESTinio's handle_request_timeout (http_request_timeout) bounds the WHOLE request, and its
     * clock starts before the downstream call, so what matters is the sum of the three sequential
     * downstream phases -- connect, then write, then response. If that sum exceeds the cap, the HTTP
     * server tears the request down first and the downstream deadline never gets to fire, which
     * looks like an unexplained failure rather than a misconfiguration. Silent with the defaults
     * (2 + 5 + 5 = 12 s against a 30 s cap).
     */
    void warnIfDownstreamBudgetExceedsRequestTimeout(const char* path,
                                                     const remoted::downstream::DownstreamConfig& downstreamConfig,
                                                     const remoted::http::HttpServerConfig& serverConfig,
                                                     const remoted::downstream::DownstreamTarget& target)
    {
        const int responseTimeoutMs =
            target.responseTimeoutMs > 0 ? target.responseTimeoutMs : downstreamConfig.responseTimeoutMs;
        const long long budgetMs = static_cast<long long>(downstreamConfig.connectTimeoutMs) +
                                   downstreamConfig.writeTimeoutMs + responseTimeoutMs;
        const long long requestCapMs = static_cast<long long>(serverConfig.requestTimeoutSec) * 1000;

        if (budgetMs > requestCapMs)
        {
            LOGFN_WARN(moduleLogFn(),
                       "Endpoint '%s': the downstream timeouts add up to %lld ms, which exceeds "
                       "'http_request_timeout' (%lld ms); the HTTP server will cut a slow request off before the "
                       "downstream deadline is reached. Consider increasing the value of 'http_request_timeout', or "
                       "reducing 'downstream_connect_timeout'/'downstream_write_timeout'/"
                       "'downstream_response_timeout'.",
                       path,
                       budgetMs,
                       requestCapMs);
        }
    }

    /// Unwinds a partially-built HTTPS stack after a failed/incomplete start().
    void resetHttpServerStack()
    {
        m_httpServer.reset();
        // The control handler may have been partially built (its ctor spins up an eviction
        // thread and the wdb/task client workers) before startHttpServer() threw further down.
        // Reset it here so those threads join before the next retry constructs a fresh one.
        m_controlHandler.reset();
        // Same lifecycle concern as m_controlHandler above: ScanVdHandlerImpl's ctor spins up
        // its own worker thread pool, which must be joined before the next retry replaces it.
        m_scanVdHandler.reset();
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

    void run()
    {
        // Exception barrier for the worker thread body: a throw escaping a bare std::thread
        // terminates the whole remoted daemon. The HTTPS transport is already up by the time this
        // thread starts (start() brought it up synchronously), so this really only covers
        // condition-variable and logging failures in the heartbeat loop.
        try
        {
            runLoop();
        }
        catch (const std::exception& e)
        {
            // Deliberately does NOT re-enter the loop: an exception that repeats every iteration
            // would spin forever writing to wazuh-manager.log, which is worse than a dead worker. The
            // module keeps serving whatever the HTTP server already started.
            LOGFN_ERROR(
                moduleLogFn(), "The remoted module worker thread stopped on an unexpected exception: %s.", e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(moduleLogFn(), "The remoted module worker thread stopped on a non-standard exception.");
        }
    }

    void runLoop()
    {
        LOGFN_INFO(moduleLogFn(), "remoted module worker thread running.");

        while (true)
        {
            std::unique_lock<std::mutex> lock(m_waitMutex);
            if (m_stopping)
            {
                break;
            }

            LOGFN_DEBUG1(moduleLogFn(), "remoted module heartbeat.");
            m_waitCv.wait_for(
                lock, std::chrono::seconds(REMOTED_MODULE_HEARTBEAT_SECS), [this]() { return m_stopping.load(); });

            if (m_stopping)
            {
                break;
            }
        }

        LOGFN_INFO(moduleLogFn(), "remoted module worker thread finished.");
    }

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

    // /control lifecycle: counters live on the facade (stable address across HTTP-server
    // retries; ControlHandler holds a reference). m_controlHandler owns the AgentRegistry,
    // HashCache, WazuhDBClient and TaskClient it was constructed with; resetting it joins
    // their threads in the right order (see ControlHandler::Impl's dtor).
    remoted::control::ControlMetrics m_controlMetrics {};               ///< /control counters.
    std::unique_ptr<remoted::control::ControlHandler> m_controlHandler; ///< Startup/notify/shutdown pipeline.

    // /scan/vd lifecycle: handles VD scan requests from agents. Counters live on the facade for
    // the same reason as m_controlMetrics: a stable address across HTTP-server retries.
    remoted::scanvd::ScanVdMetrics m_scanVdMetrics {};                   ///< /scan/vd counters.
    std::unique_ptr<remoted::scanvd::ScanVdHandlerImpl> m_scanVdHandler; ///< VD scan handler.
};

#endif // _REMOTED_MODULE_FACADE_HPP
