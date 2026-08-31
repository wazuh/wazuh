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
#include "common/requestOutcomeMetrics.hpp"
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
#include "downstream/forwarderMetrics.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/configEndpoint.hpp"
#include "endpoints/controlEndpoint.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "endpoints/endpoint.hpp"
#include "endpoints/scanVdEndpoint.hpp"
#include "endpoints/statefulEndpoint.hpp"
#include "endpoints/statelessEndpoint.hpp"
#include "endpoints/statsEndpoint.hpp"
#include "enrollment/authdClient.hpp"
#include "enrollment/enrollmentAuthenticator.hpp"
#include "enrollment/enrollmentConfig.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "enrollment/metrics.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "loggerHelper.h"
#include "remoted_module.h"
#include "scanvd/scanVdHandler.hpp"
#include "singleton.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>
#include <wazuh_metrics/jsonDump.hpp>
#include <wazuh_metrics/manager.hpp>

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

// Fixed path of the module's LOCAL admin socket (GET / + GET /metrics). RELATIVE on purpose:
// remoted chroot()s into the install dir, so the bind lands at $WAZUH_HOME/queue/sockets/.
// Named "-admin" (not "-http"/"-stats"): remoted's HTTP identity is the public listener, this is
// a management plane, and it must not collide with remcom's legacy "queue/sockets/remote.sock". No
// config knob -- internal options only carry ints, the same criterion that fixed inventory
// sync's socket path.
constexpr auto REMOTED_MODULE_ADMIN_SOCKET_PATH {"queue/sockets/remote-admin-http.sock"};

/**
 * @brief Internal engine of the remoted module.
 *
 * Owns the worker std::thread and implements the canonical cooperative-shutdown
 * lifecycle (atomic flag + condition_variable + join), plus the HTTPS transport
 * (our IHttpServer) and the framework-agnostic auth layer wired on top of it, and
 * the optional local admin socket (shared uds_http_server) serving the module's
 * metrics.
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

        // The local admin socket comes up AFTER the public HTTPS server on purpose: the HTTPS
        // listener is what remoted exists for, the admin plane is optional observability.
        // startAdminServer() never throws -- a failure there is a WARN and the module continues.
        startAdminServer();

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

            // Same phase-1 contract for the local admin socket: after this, no admin handler
            // will ever run again. Its handlers only read m_metricsManager -- which is never
            // reset -- but the discipline of closing accepts before ANY teardown is kept
            // uniform so the admin plane can never depend on teardown order by accident.
            if (m_adminServer)
            {
                m_adminServer->stopAccepting();
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
            // /enroll has no async callback machinery of its own to race with a wdb-worker join
            // (unlike ControlHandler above) -- reset here anyway, alongside every other
            // per-request handler object, once stopAccepting() guarantees nothing can still call in.
            m_enrollmentAuthenticator.reset();

            // Phase 2: abort in-flight downstream UDS sessions (no new completions can arrive).
            // m_authdClient->stop() belongs in this phase for the same reason: it fails any
            // queued/in-flight /enroll->authd request right away rather than let it linger, and
            // the resulting responder->send() calls are still safe here (phase 4 hasn't run).
            if (m_downstreamClient)
            {
                m_downstreamClient->stop();
            }
            if (m_authdClient)
            {
                m_authdClient->stop();
            }

            // Phase 3: drain the post-processing pool. Anything that was mid-flight when phase 1
            // ran completes here; its responder->send() is still safe -- the HTTP server's I/O
            // runtime hasn't been torn down yet (that's phase 4, below).
            m_forwarder.reset();
            m_downstreamClient.reset();
            m_deferredLimiter.reset();
            m_authdClient.reset();

            // Phase 4: NOW it's safe to fully tear down the transport (releases the I/O
            // runtime). Nothing can still be touching a responder: worker pool B was drained in
            // phase 1, the post-processing pool D was drained in phase 3, and phase 2 stopped
            // the downstream client so nothing new can reach D either. This reset (like the
            // limiter's in phase 3) also expires the public transport-diagnostics weak targets,
            // so those pulls read 0 from here on.
            m_httpServer.reset();

            // The admin server is torn down in the same phase: accepts were already closed in
            // phase 1, nothing its handlers reach was destroyed in between (their only
            // dependency, m_metricsManager, outlives every stop()), so this stop() just drains
            // and releases its I/O runtime and unlinks the socket. After the reset, the
            // transport-diagnostics pulls read through an expired weak_ptr as 0 -- the
            // documented quiesced values -- so the final dump below can never touch a dead
            // server.
            if (m_adminServer)
            {
                m_adminServer->stop();
            }
            m_adminServer.reset();

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

        // Final counter totals. The runtime exposure is GET /metrics on the local admin socket
        // (never the public HTTPS endpoint -- it is agent-facing, not an admin plane), but the
        // admin server is already down by this point (and is optional to begin with), so this
        // debug line is how the LAST totals are observed. The macro skips the dump entirely
        // when debug logging is inactive.
        LOGFN_DEBUG1(moduleLogFn(),
                     "remoted module metrics at stop: %s",
                     wazuh::metrics::dumpJson(*m_metricsManager, {"remoted"}).c_str());

        LOGFN_INFO(moduleLogFn(), "remoted module stopped.");
    }

private:
    void startHttpServer()
    {
        const auto config = remoted::http::buildHttpServerConfig(m_config);

        // The auth-rejection counters live behind errorResponseFor()'s process-wide funnel, so
        // they are installed rather than threaded through the gateway/endpoints. Under the
        // lifecycle lock, before any route serves; idempotent across restarts (the counters
        // dedupe by name on the never-reset manager, so totals carry over).
        remoted::endpoints::installAuthRejectMetrics(remoted::endpoints::makeAuthRejectMetrics(*m_metricsManager));

        m_httpServer = remoted::http::makeHttpServer();

        // Framework-agnostic auth layer: reads agent keys from client.keys and
        // verifies the bearer token of every authenticated request. Wired on top of
        // OUR transport, so swapping the HTTP library never touches it. The keystore
        // hot-reloads client.keys on its own (background watcher, see keystore.hpp) --
        const auto keystoreRefreshSeconds = m_config.keystore_refresh_interval > 0
                                                ? m_config.keystore_refresh_interval
                                                : remoted::auth::Keystore::kDefaultRefreshIntervalSeconds;
        // Held as the CONCRETE type in a local so the health pulls can weak-point at it (the
        // health accessors are Keystore's, not IAgentKeystore's); m_keystore keeps only the
        // interface, and its reset in stop() expires the pulls to 0.
        auto keystore =
            std::make_shared<remoted::auth::Keystore>(remoted::auth::Keystore::kDefaultPath, keystoreRefreshSeconds);
        m_keystore = keystore;
        registerKeystoreDiagnostics(keystore);
        // The Content-Encoding contract is composed in here rather than built into the gateway, so
        // the auth layer stays about authentication only. Built ONCE and shared (BodyDecoder is
        // stateless -- see its own class comment) across every AuthGateway route, so they all get
        // the same policy and none can accidentally opt out or drift out of sync with each other.
        const auto authConfig = remoted::auth::buildAuthConfig(m_config);
        const auto bodyDecoder = std::make_shared<const remoted::decoding::BodyDecoder>(
            *m_httpServer, m_config.http_content_encoding_enabled);
        m_authGateway = std::make_unique<remoted::endpoints::AuthGateway>(authConfig, m_keystore, bodyDecoder);

        // /enroll gets its OWN BodyDecoder instance, not the shared one above: every AuthGateway
        // route requires a verified credential before decode() ever runs, which closes the
        // amplification lever a decoded-size cap exists for -- but /enroll's Open mode has NO
        // credential check at all by design, so an unauthenticated peer CAN reach decode() there.
        // Capped at kMaxEnrollBodySize (the same cap parseAndValidateBody() applies post-decode,
        // enrollmentEndpoint.hpp) so a small, highly-compressed frame can't hold much of the
        // shared in-flight byte budget (the same one /stateless and friends draw from) even
        // briefly while decompressing -- see makeHandler()'s and BodyDecoder's own doc comments.
        const auto enrollBodyDecoder = std::make_shared<const remoted::decoding::BodyDecoder>(
            *m_httpServer, m_config.http_content_encoding_enabled, remoted::enrollment::kMaxEnrollBodySize);

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
            downstreamClient, m_deferredLimiter, downstreamConfig.postProcessThreads, m_forwarderMetrics);
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

        // /stateless: the gateway runs the full bearer-token validation and only calls this handler once
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
            remoted::endpoints::stateless::makeHandler(*m_forwarder, eventsSocketPath, &m_statelessHttpMetrics));

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
                                             remoted::endpoints::download::makeHandler({}, m_downloadMetrics),
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
            remoted::endpoints::stats::makeHandler(*m_forwarder, inventorySyncSocketPath, &m_statsHttpMetrics));

        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/config",
            remoted::endpoints::config::makeHandler(*m_forwarder, inventorySyncSocketPath, &m_configHttpMetrics));

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
            remoted::endpoints::stateful::makeHandler(*m_forwarder,
                                                      inventorySyncSocketPath,
                                                      downstreamConfig.statefulResponseTimeoutMs,
                                                      &m_statefulHttpMetrics));

        warnIfDownstreamBudgetExceedsRequestTimeout(
            "/stateful",
            downstreamConfig,
            config,
            remoted::endpoints::stateful::target(
                inventorySyncSocketPath, "0", downstreamConfig.statefulResponseTimeoutMs));

        // /control: agent lifecycle (startup / notify / shutdown). Same auth path as /stateless
        // -- the gateway runs the full bearer-token validation and only calls this handler once auth
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
        // member on this facade, so its address stays stable across HTTP-server retries; the
        // counters it caches live in m_metricsManager (created once, never reset), so totals
        // carry over too -- desirable for observability.
        const auto controlConfig = remoted::control::buildControlConfig(m_config);
        auto vdClient = std::make_shared<remoted::common::VdClient>();
        // Held in a local (not passed inline) so the registry-size pull metric can weak-point at
        // it; the ControlHandler owns it, so the weak_ptr expires when stop() phase 1b resets
        // the handler.
        auto agentRegistry = std::make_shared<remoted::control::AgentRegistry>();
        m_controlHandler = std::make_unique<remoted::control::ControlHandler>(
            agentRegistry,
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

        m_authGateway->addAuthenticatedRoute(
            *m_httpServer,
            remoted::http::Method::Post,
            "/control",
            remoted::endpoints::control::makeHandler(*m_controlHandler, m_controlMetrics));

        // Not a DeferredForwarder, so it takes the shape-agnostic check. The two deadlines add
        // up rather than overlap: past the group-refresh window getAgentGroups() runs first and
        // gates the response. The wazuh-db write is fire-and-forget and is not in the budget.
        warnIfBudgetExceedsRequestTimeout("/control",
                                          "control_wdb_roundtrip_deadline'/'control_tm_deadline",
                                          static_cast<long long>(controlConfig.wdbRoundtripDeadlineMs) +
                                              controlConfig.tmDeadlineMs,
                                          static_cast<long long>(config.requestTimeoutSec) * 1000);

        // /scan/vd: agent-initiated VD scans. Offset queries and scan triggers both travel to
        // VD's socket (queue/sockets/vd-http.sock -- see ScanVdHandlerImpl's and VdClient's default
        // arguments): since the socket unification, /offset starvation is prevented by the
        // server's route classes (offset is Liveness; scans are Control, deferred to a bounded
        // lane that never occupies a server thread), not by socket separation.
        m_scanVdHandler = std::make_unique<remoted::scanvd::ScanVdHandlerImpl>(vdClient, m_scanVdMetrics);

        m_authGateway->addAuthenticatedRoute(*m_httpServer,
                                             remoted::http::Method::Post,
                                             "/scan/vd",
                                             remoted::endpoints::scanvd::makeHandler(*m_scanVdHandler));

        // Deadlines fixed at compile time: nothing to reduce, so the check names only the cap.
        warnIfBudgetExceedsRequestTimeout("/scan/vd",
                                          nullptr,
                                          remoted::scanvd::ScanVdHandlerImpl::VD_SCAN_BUDGET_MS,
                                          static_cast<long long>(config.requestTimeoutSec) * 1000);

        // /enroll: bridges to authd's local socket (see the Agent enrollment chapter of this
        // module's README). Registered directly on m_httpServer -- NOT through m_authGateway --
        // because an enrolling agent has no client.keys entry yet, so the agent<->manager
        // bearer-token profile cannot authenticate it. Always registered, regardless of
        // enrollment_enabled: the handler itself answers 403 when enrollment is administratively
        // disabled, so the route is never a bare 404.
        //
        // The listener's own client-certificate requirement (config.verificationMode, set below
        // via buildHttpServerConfig()) and authd's <use_password> are independent gates -- exactly
        // like legacy authd, which already enforces its own <ssl_verify_host> at the TLS handshake
        // and <use_password> while parsing the enrollment message as two separate checks on the
        // same connection (main-server.c). So EnrollmentAuthenticator only ever needs to know
        // whether it must additionally require the `wazuh-enroll+jwt` bearer; it has no notion of "mTLS
        // mode" at all, because a client certificate is never its concern -- the TLS listener
        // enforces (or doesn't) that entirely on its own, before any handler runs. PasswordKeySource
        // (constructed only when required) is owned by m_enrollmentAuthenticator from here on -- its
        // background watcher thread's lifetime is tied to the authenticator's.
        const auto enrollConfig = remoted::enrollment::buildEnrollmentConfig(m_config);

        std::shared_ptr<remoted::auth::PasswordKeySource> enrollPasswordKeySource;
        if (enrollConfig.usePassword)
        {
            enrollPasswordKeySource = std::make_shared<remoted::auth::PasswordKeySource>(
                remoted::auth::PasswordKeySource::kDefaultPath, enrollConfig.passwordRefreshIntervalSec);
        }

        m_enrollmentAuthenticator = std::make_unique<remoted::enrollment::EnrollmentAuthenticator>(
            remoted::enrollment::EnrollmentAuthConfig {
                enrollConfig.usePassword, enrollConfig.timePolicy, enrollConfig.maxBodySize},
            enrollPasswordKeySource);

        m_authdClient =
            std::make_shared<remoted::enrollment::AuthdClient>(remoted::enrollment::AuthdClient::kDefaultSocketPath,
                                                               m_config.worker_node,
                                                               enrollConfig.authdConnectTimeoutMs,
                                                               enrollConfig.authdResponseTimeoutMs,
                                                               enrollConfig.authdMaxQueueSize,
                                                               enrollConfig.authdWorkerThreads);

        registerAuthdQueueDiagnostics(m_authdClient);

        m_httpServer->addRoute(remoted::http::Method::Post,
                               "/enroll",
                               remoted::enrollment::makeHandler(*m_enrollmentAuthenticator,
                                                                *m_authdClient,
                                                                enrollConfig,
                                                                m_enrollmentMetrics,
                                                                enrollBodyDecoder,
                                                                m_enrollHttpMetrics));

        // Same sanity check the other four endpoints get (see warnIfDownstreamBudgetExceedsRequestTimeout's
        // own comment) -- /enroll's downstream is AuthdClient, not the DeferredForwarder pair those
        // use, so it needs its own budget computed from AuthdClient's own (already worker-aware-
        // resolved) timeouts rather than DownstreamConfig's. At MAXIMUM configured values
        // (authd_connect_timeout=60s, authd_response_timeout=120s) this reaches 180s against a 30s
        // http_request_timeout default -- silent with the defaults (2s + 5s/15s), so this only fires
        // when an operator has pushed these up without also raising http_request_timeout.
        const auto resolvedAuthdConnectTimeoutMs =
            enrollConfig.authdConnectTimeoutMs != 0
                ? static_cast<long long>(enrollConfig.authdConnectTimeoutMs)
                : static_cast<long long>(remoted::enrollment::AuthdClient::kDefaultConnectTimeoutMs);
        const auto resolvedAuthdResponseTimeoutMs =
            static_cast<long long>(remoted::enrollment::AuthdClient::resolveResponseTimeoutMs(
                enrollConfig.authdResponseTimeoutMs, enrollConfig.isWorkerNode));
        warnIfBudgetExceedsRequestTimeout("/enroll",
                                          "authd_connect_timeout'/'authd_response_timeout",
                                          resolvedAuthdConnectTimeoutMs + resolvedAuthdResponseTimeoutMs,
                                          static_cast<long long>(config.requestTimeoutSec) * 1000);

        m_httpServer->start(config);

        registerPublicTransportDiagnostics();
        registerControlRegistryDiagnostics(agentRegistry);
    }

    /**
     * @brief Publish the keystore's health as pull metrics (remoted.auth.keystore.*).
     *
     * Same wiring as the other diagnostics: weak target repointed per start, registered once,
     * quiesced to 0 after stop() resets m_keystore. Answers: how many keys are loaded (did the
     * hot-reload pick up my re-enrolls?), and is client.keys unreadable/unstable in production
     * (reload_failures moving). The Keystore itself stays metrics-library-free -- it only
     * maintains plain atomics these getters read.
     */
    /**
     * @brief Publishes the /enroll -> authd queue as remoted.enroll.authd.queue.* pulls.
     *
     * Registered once, re-targeted on every start (the client is rebuilt per attempt), exactly
     * like the keystore/registry pulls below. The counter is what makes
     * remoted.enroll.authd_unavailable actionable: that counter fires for a full queue, an
     * unreachable authd and a shutdown alike, so the difference against this one is the share
     * that raising 'remoted.authd_max_queue_size' / 'remoted.authd_worker_threads' could fix.
     */
    void registerAuthdQueueDiagnostics(const std::shared_ptr<remoted::enrollment::AuthdClient>& client)
    {
        {
            std::lock_guard<std::mutex> lock {m_authdDiagMutex};
            m_authdDiagTarget = client;
        }
        if (m_authdPullsRegistered)
        {
            return;
        }
        m_authdPullsRegistered = true;

        const auto snapshot = [this]
        {
            std::lock_guard<std::mutex> lock {m_authdDiagMutex};
            const auto target = m_authdDiagTarget.lock();
            return target ? target->queueDiagnostics() : remoted::enrollment::AuthdClient::QueueDiagnostics {};
        };

        m_metricsManager->registerPullMetric(
            "remoted.enroll.authd.queue.depth",
            [snapshot] { return static_cast<uint64_t>(snapshot().depth); },
            "Enrollment requests waiting for an authd worker",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.enroll.authd.queue.capacity",
            [snapshot] { return static_cast<uint64_t>(snapshot().capacity); },
            "Configured depth of the authd request queue ('remoted.authd_max_queue_size')",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.enroll.authd.queue.rejected.total",
            [snapshot] { return snapshot().rejectedTotal; },
            "Enrollment requests refused because the authd queue was full (the saturation share of "
            "remoted.enroll.authd_unavailable)",
            "requests");
    }

    void registerKeystoreDiagnostics(const std::shared_ptr<remoted::auth::Keystore>& keystore)
    {
        {
            std::lock_guard<std::mutex> lock {m_keystoreDiagMutex};
            m_keystoreDiagTarget = keystore;
        }
        if (m_keystorePullsRegistered)
        {
            return;
        }
        m_keystorePullsRegistered = true;

        const auto target = [this]() -> std::shared_ptr<remoted::auth::Keystore>
        {
            std::lock_guard<std::mutex> lock {m_keystoreDiagMutex};
            return m_keystoreDiagTarget.lock();
        };

        m_metricsManager->registerPullMetric(
            "remoted.auth.keystore.agents",
            [target]
            {
                const auto keystore = target();
                return keystore ? static_cast<uint64_t>(keystore->agentsLoaded()) : 0U;
            },
            "Agents with a usable key after the last successful client.keys load",
            "agents");
        m_metricsManager->registerPullMetric(
            "remoted.auth.keystore.entries_skipped",
            [target]
            {
                const auto keystore = target();
                return keystore ? static_cast<uint64_t>(keystore->entriesSkipped()) : 0U;
            },
            "client.keys lines the last successful load could not use (bad field count, non-numeric id, "
            "unparseable ip column, or undecodable key); comments and removed entries excluded",
            "entries");
        m_metricsManager->registerPullMetric(
            "remoted.auth.keystore.reloads.total",
            [target]
            {
                const auto keystore = target();
                return keystore ? keystore->reloadsTotal() : 0U;
            },
            "Successful client.keys loads (startup load included)",
            "count");
        m_metricsManager->registerPullMetric(
            "remoted.auth.keystore.reload_failures.total",
            [target]
            {
                const auto keystore = target();
                return keystore ? keystore->reloadFailuresTotal() : 0U;
            },
            "Failed client.keys loads: unreadable file, or torn reads on every attempt",
            "count");
    }

    /**
     * @brief Publish the agent registry's live size as a pull metric
     *        (remoted.control.registry.agents).
     *
     * Same wiring as the transport diagnostics: weak target repointed per start, registered
     * once. The registry is OWNED by m_controlHandler (reset in stop() phase 1b), so the pull
     * quiesces to 0 as soon as the control plane is torn down. size() sums the shards under
     * shared locks -- dump-cadence only. Purely diagnostic: it answers "how many agents does
     * this node currently track"; there is no knob behind it (the registry TTL and eviction
     * cadence are compile-time constants -- see controlConfig.hpp).
     */
    void registerControlRegistryDiagnostics(const std::shared_ptr<remoted::control::AgentRegistry>& registry)
    {
        {
            std::lock_guard<std::mutex> lock {m_controlDiagMutex};
            m_registryDiagTarget = registry;
        }
        if (m_controlPullsRegistered)
        {
            return;
        }
        m_controlPullsRegistered = true;

        m_metricsManager->registerPullMetric(
            "remoted.control.registry.agents",
            [this]
            {
                std::lock_guard<std::mutex> lock {m_controlDiagMutex};
                const auto target = m_registryDiagTarget.lock();
                return target ? static_cast<uint64_t>(target->size()) : 0U;
            },
            "Agents currently tracked by the /control registry",
            "agents");
    }

    /**
     * @brief Bring up the LOCAL admin socket (GET / + GET /metrics) -- best effort.
     *
     * Sibling of startHttpServer(), called after it: this is the module's management plane
     * (shared_modules/uds_http_server over REMOTED_MODULE_ADMIN_SOCKET_PATH), reachable only
     * from the local host -- agents can never reach it, and the public HTTPS server must never
     * grow these routes (it is agent-facing, not an admin plane). Both routes are Liveness
     * class: answered inline from resident state, exempt from the byte budget, so they respond
     * under any pressure.
     *
     * Never throws. The admin plane is optional observability, so ANY failure here (most
     * commonly: queue/sockets/ missing outside an installed manager, or the path occupied by a
     * non-socket file the library rightly refuses to unlink) is a WARN and the module keeps
     * running without it -- remoted must never die for its metrics.
     */
    void startAdminServer()
    {
        try
        {
            m_adminServer = wazuh::uds_http::makeUdsHttpServer();

            // Unauthenticated liveness probe, mirroring the public server's GET / (which stays:
            // agents probe THAT one; this one answers operators on the local socket).
            m_adminServer->addRoute(
                wazuh::uds_http::Method::Get,
                "/",
                [](std::shared_ptr<const wazuh::uds_http::HttpRequest>,
                   std::shared_ptr<wazuh::uds_http::IHttpResponder> responder) {
                    responder->send(
                        wazuh::uds_http::HttpResponse::json(200, R"({"status":"ok","module":"remoted_module"})"));
                },
                wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness});

            // GET /metrics: dump the module's whole registry (remoted.control.*, remoted.scanvd.*,
            // remoted.admin.server.*...), same envelope as the stop() debug dump. The manager is
            // captured weakly for consistency with inventory sync's metricsEndpoint (503 when
            // gone), even though this facade never resets its manager -- totals survive restart
            // retries on purpose.
            m_adminServer->addRoute(
                wazuh::uds_http::Method::Get,
                "/metrics",
                [weakManager = std::weak_ptr<wazuh::metrics::IManager>(m_metricsManager)](
                    std::shared_ptr<const wazuh::uds_http::HttpRequest>,
                    std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
                {
                    const auto manager = weakManager.lock();
                    if (!manager)
                    {
                        responder->send(
                            wazuh::uds_http::HttpResponse::json(503, R"({"error":"Service unavailable","code":503})"));
                        return;
                    }
                    responder->send(
                        wazuh::uds_http::HttpResponse::json(200, wazuh::metrics::dumpJson(*manager, {"remoted"})));
                },
                wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness});

            wazuh::uds_http::UdsHttpServerConfig config;
            config.socketPath = REMOTED_MODULE_ADMIN_SOCKET_PATH;
            // Identity: a NEW server with no prior wire contract, so the Server: header carries
            // remoted's own daemon name (unlike inventory sync, which kept its historical value).
            config.logTag = "wazuh-manager-remoted:remoted-module:admin";
            config.serverName = "remoted admin";
            config.serverHeader = "wazuh-remoted";
            // Two liveness routes serving one local operator: sized far below the library's
            // data-plane defaults, everything else left at them.
            config.ioThreads = 2;
            config.maxConnections = 64;
            config.reservedControlConnections = 16;
            m_adminServer->start(config);

            registerAdminTransportDiagnostics();

            LOGFN_INFO(moduleLogFn(),
                       "remoted admin server listening on '%s' (routes: GET / and GET /metrics).",
                       REMOTED_MODULE_ADMIN_SOCKET_PATH);
        }
        catch (const std::exception& e)
        {
            LOGFN_WARN(moduleLogFn(),
                       "remoted admin server failed to start on '%s': %s. Continuing without it; the "
                       "metrics dump stays reachable through the stop() debug log.",
                       REMOTED_MODULE_ADMIN_SOCKET_PATH,
                       e.what());
            m_adminServer.reset();
        }
    }

    /**
     * @brief Publish the admin server's bounded resources as pull metrics (remoted.admin.server.*).
     *
     * Same wiring as inventory sync's registerTransportDiagnostics() (U10): the weak target is
     * repointed at the new server after every successful start, while the pulls themselves are
     * registered exactly once -- IManager has no unregister. After stop() resets m_adminServer
     * the weak_ptr expires and every metric reads 0, the documented quiesced value, so a dump
     * can never touch a dead server. The budget and data/control lanes are structurally idle
     * today (both routes are Liveness class), but the full set is published anyway so every
     * uds_http_server consumer reports the same vocabulary.
     */
    void registerAdminTransportDiagnostics()
    {
        {
            std::lock_guard<std::mutex> lock {m_adminDiagMutex};
            m_adminDiagTarget = m_adminServer;
        }
        if (m_adminPullsRegistered)
        {
            return;
        }
        m_adminPullsRegistered = true;

        // Safe to capture this: the facade is a process-lifetime singleton, and diagnostics()
        // itself is lock-free relaxed loads -- callable from a dump at any time.
        const auto snapshot = [this]() -> wazuh::uds_http::TransportDiagnostics
        {
            std::lock_guard<std::mutex> lock {m_adminDiagMutex};
            if (const auto server = m_adminDiagTarget.lock())
            {
                return server->diagnostics();
            }
            return {};
        };

        m_metricsManager->registerPullMetric(
            "remoted.admin.server.budget.available.bytes",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetAvailableBytes); },
            "Bytes the admin server's in-flight payload budget can still admit",
            "bytes");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.budget.inflight.bytes",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightBytes); },
            "Bytes currently reserved by admitted admin requests",
            "bytes");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.budget.inflight.requests",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightCount); },
            "Admin requests currently holding a budget reservation",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.sessions.live",
            [snapshot] { return static_cast<uint64_t>(snapshot().liveSessions); },
            "Open admin socket connections, deferred replies included",
            "connections");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.sessions.data",
            [snapshot]
            {
                return static_cast<uint64_t>(
                    snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Data)]);
            },
            "Admin sessions classified on data-class routes",
            "connections");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.sessions.control",
            [snapshot]
            {
                return static_cast<uint64_t>(
                    snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Control)]);
            },
            "Admin sessions classified on control-class routes",
            "connections");
        m_metricsManager->registerPullMetric(
            "remoted.admin.server.sessions.liveness",
            [snapshot]
            {
                return static_cast<uint64_t>(
                    snapshot().sessionsByClass[static_cast<std::size_t>(wazuh::uds_http::RouteClass::Liveness)]);
            },
            "Admin sessions classified on liveness-class routes",
            "connections");
    }

    /**
     * @brief Publish the PUBLIC transport's backpressure state as pull metrics
     *        (remoted.server.budget.* and remoted.forwarder.deferred.*).
     *
     * Sibling of registerAdminTransportDiagnostics(), same wiring: the weak targets are
     * repointed at the new server/limiter after every successful startHttpServer(), while the
     * pulls themselves are registered exactly once -- IManager has no unregister. After stop()
     * resets m_httpServer / m_deferredLimiter the weak_ptrs expire and every metric reads 0,
     * the documented quiesced value.
     *
     * Together these answer the sizing questions the two-phase backpressure raises: how close
     * the byte budget ('max_inflight_bytes') and the deferred-work limiter
     * ('max_deferred_requests') run to their ceilings, and how much each has shed. A budget
     * shed never appears in the per-endpoint remoted.http.*.responses.* cells (it is refused
     * before any route runs), so budget.rejected.total is its only record; a limiter shed
     * counts both here and as that endpoint's 503.
     */
    void registerPublicTransportDiagnostics()
    {
        {
            std::lock_guard<std::mutex> lock {m_publicDiagMutex};
            m_publicDiagTarget = m_httpServer;
            m_limiterDiagTarget = m_deferredLimiter;
        }
        if (m_publicPullsRegistered)
        {
            return;
        }
        m_publicPullsRegistered = true;

        // Safe to capture this: the facade is a process-lifetime singleton. The server snapshot
        // may take the transport's own lock -- fine at dump cadence.
        const auto snapshot = [this]() -> remoted::http::TransportDiagnostics
        {
            std::lock_guard<std::mutex> lock {m_publicDiagMutex};
            if (const auto server = m_publicDiagTarget.lock())
            {
                return server->diagnostics();
            }
            return {};
        };
        // Locks the weak limiter under the same mutex; the returned shared_ptr keeps it alive
        // for the duration of one metric read even if stop() races the dump.
        const auto limiter = [this]() -> std::shared_ptr<remoted::downstream::DeferredWorkLimiter>
        {
            std::lock_guard<std::mutex> lock {m_publicDiagMutex};
            return m_limiterDiagTarget.lock();
        };

        m_metricsManager->registerPullMetric(
            "remoted.server.budget.available.bytes",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetAvailableBytes); },
            "Bytes the public server's in-flight payload budget can still admit",
            "bytes");
        m_metricsManager->registerPullMetric(
            "remoted.server.budget.inflight.bytes",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightBytes); },
            "Bytes currently reserved by admitted public requests (payloads plus zstd decode scratch)",
            "bytes");
        m_metricsManager->registerPullMetric(
            "remoted.server.budget.inflight.requests",
            [snapshot] { return static_cast<uint64_t>(snapshot().budgetInFlightCount); },
            "Admitted public requests currently resident (one per request, compressed or not)",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.server.budget.rejected.total",
            [snapshot] { return snapshot().budgetRejectedTotal; },
            "Requests the byte budget refused to admit (503, before any route ran)",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.forwarder.deferred.inflight",
            [limiter]
            {
                const auto l = limiter();
                return l ? static_cast<uint64_t>(l->inFlight()) : 0U;
            },
            "Requests currently parked awaiting a downstream service",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.forwarder.deferred.capacity",
            [limiter]
            {
                const auto l = limiter();
                return l ? static_cast<uint64_t>(l->capacity()) : 0U;
            },
            "Configured deferred-work slot cap, 'remoted.max_deferred_requests' (reads 0 only while the module is "
            "stopped)",
            "requests");
        m_metricsManager->registerPullMetric(
            "remoted.forwarder.deferred.rejected.total",
            [limiter]
            {
                const auto l = limiter();
                return l ? l->rejectedTotal() : 0U;
            },
            "Requests shed with 503 because every deferred-work slot was taken",
            "requests");
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

        warnIfBudgetExceedsRequestTimeout(
            path,
            "downstream_connect_timeout'/'downstream_write_timeout'/'downstream_response_timeout",
            budgetMs,
            requestCapMs);
    }

    /// Shared core of warnIfDownstreamBudgetExceedsRequestTimeout(): pulled out so /enroll, whose
    /// downstream is AuthdClient (a completely different config shape -- authd_connect_timeout +
    /// authd_response_timeout, no write phase) rather than the DeferredForwarder/DownstreamConfig
    /// pair every other endpoint here shares, can run the same sanity check without forcing that
    /// shape onto it.
    /// @param tunablesToReduce Options the operator could lower instead of raising the cap, or
    /// nullptr when the budget is fixed at compile time and only the cap can move.
    void warnIfBudgetExceedsRequestTimeout(const char* path,
                                           const char* tunablesToReduce,
                                           long long budgetMs,
                                           long long requestCapMs)
    {
        if (budgetMs <= requestCapMs)
        {
            return;
        }

        const std::string advice =
            tunablesToReduce
                ? "Consider increasing the value of 'http_request_timeout', or reducing '" +
                      std::string {tunablesToReduce} + "'."
                : std::string {"These deadlines are fixed, so only 'http_request_timeout' can be increased."};

        LOGFN_WARN(moduleLogFn(),
                   "Endpoint '%s': the downstream timeouts add up to %lld ms, which exceeds "
                   "'http_request_timeout' (%lld ms); the HTTP server will cut a slow request off before the "
                   "downstream deadline is reached. %s",
                   path,
                   budgetMs,
                   requestCapMs,
                   advice.c_str());
    }

    /// Unwinds a partially-built HTTPS stack after a failed/incomplete start().
    void resetHttpServerStack()
    {
        m_httpServer.reset();
        // The admin server (when it came up) goes with the stack; its dtor runs the two-phase
        // stop, and its handlers only reach m_metricsManager, which is never reset.
        m_adminServer.reset();
        // The control handler may have been partially built (its ctor spins up an eviction
        // thread and the wdb/task client workers) before startHttpServer() threw further down.
        // Reset it here so those threads join before the next retry constructs a fresh one.
        m_controlHandler.reset();
        // ScanVdHandlerImpl is stateless (a synchronous passthrough of VD's admission), but the
        // next retry constructs a fresh one, so drop the old instance alongside its siblings.
        m_scanVdHandler.reset();
        m_enrollmentAuthenticator.reset();
        if (m_downstreamClient)
        {
            m_downstreamClient->stop();
        }
        if (m_authdClient)
        {
            m_authdClient->stop();
        }
        m_forwarder.reset();
        m_downstreamClient.reset();
        m_deferredLimiter.reset();
        m_authdClient.reset();
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

    /// HTTPS transport (behind our interface). shared_ptr (not unique_ptr) solely so the
    /// transport-diagnostics pulls can hold a weak_ptr that expires when stop() resets it --
    /// nothing else shares ownership.
    std::shared_ptr<remoted::http::IHttpServer> m_httpServer;
    /// Local admin plane (fixed UDS socket, GET / + GET /metrics). OPTIONAL by policy: a failed
    /// start leaves it null and the module keeps running (see startAdminServer()).
    std::shared_ptr<wazuh::uds_http::IUdsHttpServer> m_adminServer;
    /// Pull-metric plumbing for the admin server's TransportDiagnostics: the weak target is
    /// repointed under its own mutex on every start; the pulls are registered exactly once per
    /// process because IManager has no unregister (see registerAdminTransportDiagnostics()).
    std::mutex m_adminDiagMutex;
    std::weak_ptr<wazuh::uds_http::IUdsHttpServer> m_adminDiagTarget;
    bool m_adminPullsRegistered {false};
    /// Same plumbing for the PUBLIC transport's backpressure state (the byte budget) and the
    /// deferred-work limiter (see registerPublicTransportDiagnostics()).
    std::mutex m_publicDiagMutex;
    std::weak_ptr<remoted::http::IHttpServer> m_publicDiagTarget;
    std::weak_ptr<remoted::downstream::DeferredWorkLimiter> m_limiterDiagTarget;
    bool m_publicPullsRegistered {false};
    /// Same plumbing for the /control agent registry (see registerControlRegistryDiagnostics()).
    std::mutex m_controlDiagMutex;
    std::weak_ptr<remoted::control::AgentRegistry> m_registryDiagTarget;
    bool m_controlPullsRegistered {false};
    /// Same plumbing for the keystore's health (see registerKeystoreDiagnostics()).
    /// Weak target + guard for the authd queue pulls (same shape as the keystore ones below).
    std::mutex m_authdDiagMutex;
    std::weak_ptr<remoted::enrollment::AuthdClient> m_authdDiagTarget;
    bool m_authdPullsRegistered {false};

    std::mutex m_keystoreDiagMutex;
    std::weak_ptr<remoted::auth::Keystore> m_keystoreDiagTarget;
    bool m_keystorePullsRegistered {false};
    std::shared_ptr<remoted::auth::IAgentKeystore> m_keystore;      ///< Agent key lookup (client.keys).
    std::unique_ptr<remoted::endpoints::AuthGateway> m_authGateway; ///< Auth layer wired onto m_httpServer.
    std::shared_ptr<remoted::downstream::DeferredWorkLimiter> m_deferredLimiter; ///< Bounds parked downstream work.
    std::shared_ptr<remoted::downstream::AsioUdsHttpClient> m_downstreamClient;  ///< Async UDS client (own io_context).
    std::unique_ptr<remoted::downstream::DeferredForwarder> m_forwarder; ///< Forwards to the downstream service.

    // The module's metric registry (shared_modules/metrics). Created ONCE and NEVER reset in
    // stop(): counters must survive the HTTP server's restart retries (an operator reading a
    // dump after a retry wants totals, not a fresh zeroed registry). Declared BEFORE the metric
    // structs below -- their default member initializers resolve counters from it, and members
    // initialize in declaration order. NEVER exposed through the public HTTPS endpoint (it is
    // agent-facing, not an admin plane); the dump is served by GET /metrics on the local admin
    // socket (see startAdminServer()) and reaches the debug log on stop().
    const std::shared_ptr<wazuh::metrics::IManager> m_metricsManager {std::make_shared<wazuh::metrics::Manager>()};

    // /control lifecycle: the metric struct is a value member on the facade (stable address
    // across HTTP-server retries; ControlHandler holds a reference), caching counters that live
    // in m_metricsManager. m_controlHandler owns the AgentRegistry, HashCache, WazuhDBClient and
    // TaskClient it was constructed with; resetting it joins their threads in the right order
    // (see ControlHandler::Impl's dtor).
    remoted::control::ControlMetrics m_controlMetrics {
        remoted::control::makeControlMetrics(*m_metricsManager)};       ///< /control counters.
    std::unique_ptr<remoted::control::ControlHandler> m_controlHandler; ///< Startup/notify/shutdown pipeline.

    // /scan/vd lifecycle: handles VD scan requests from agents. Metric struct on the facade for
    // the same reason as m_controlMetrics: a stable address across HTTP-server retries.
    remoted::scanvd::ScanVdMetrics m_scanVdMetrics {
        remoted::scanvd::makeScanVdMetrics(*m_metricsManager)};          ///< /scan/vd counters.
    std::unique_ptr<remoted::scanvd::ScanVdHandlerImpl> m_scanVdHandler; ///< VD scan handler.

    // /enroll lifecycle: bridges agent self-enrollment to authd's local socket. Metric struct on
    // the facade for the same reason as m_controlMetrics/m_scanVdMetrics. m_enrollmentAuthenticator
    // owns the PasswordKeySource (Password mode only; null otherwise) constructed for it in
    // startHttpServer() -- its background watcher thread's lifetime is tied to the authenticator's.
    remoted::enrollment::EnrollmentMetrics m_enrollmentMetrics {
        remoted::enrollment::makeEnrollmentMetrics(*m_metricsManager)};                      ///< /enroll counters.
    std::unique_ptr<remoted::enrollment::EnrollmentAuthenticator> m_enrollmentAuthenticator; ///< /enroll auth.
    /// shared_ptr, not unique_ptr, for the same reason as m_httpServer: the queue pulls hold a
    /// weak_ptr to it, so a dump that races the shutdown reset() sees a dead target and
    /// quiesces to 0 instead of touching freed state.
    std::shared_ptr<remoted::enrollment::AuthdClient> m_authdClient; ///< Bridge to authd.

    // Downstream failure taxonomy (remoted.forwarder.error.* / downstream_5xx / route_mismatch):
    // copied into the DeferredForwarder at construction (cold), so a fresh forwarder after a
    // restart retry keeps counting on the same registry totals.
    remoted::downstream::ForwarderMetrics m_forwarderMetrics {
        remoted::downstream::makeForwarderMetrics(*m_metricsManager)};

    // /download admission outcomes + started-transfer bytes (remoted.download.*): copied into
    // the handler at route registration, same restart-retry rationale.
    remoted::endpoints::download::DownloadMetrics m_downloadMetrics {
        remoted::endpoints::download::makeDownloadMetrics(*m_metricsManager)};

    // Per-endpoint HTTP outcome sets (remoted.http.<endpoint>.*). Value members for the same
    // reason as m_controlMetrics: the endpoints' handlers and forwarded targets hold RAW
    // POINTERS to these (see DownstreamTarget::httpMetrics), so their addresses must stay
    // stable across HTTP-server restart retries. Latency histograms only where they answer a
    // tuning question: /stateless (the hot path; ioThreads/worker/budget sizing) and /stateful
    // (sessions index in-request; downstream_stateful_response_timeout sizing). /stats and
    // /config share the stateful downstream and add no new answer -- counters only.
    remoted::metrics::EndpointHttpMetrics m_statelessHttpMetrics {
        remoted::metrics::makeEndpointHttpMetrics(*m_metricsManager, "stateless", /*withLatency=*/true)};
    remoted::metrics::EndpointHttpMetrics m_statefulHttpMetrics {
        remoted::metrics::makeEndpointHttpMetrics(*m_metricsManager, "stateful", /*withLatency=*/true)};
    remoted::metrics::EndpointHttpMetrics m_statsHttpMetrics {
        remoted::metrics::makeEndpointHttpMetrics(*m_metricsManager, "stats", /*withLatency=*/false)};
    remoted::metrics::EndpointHttpMetrics m_configHttpMetrics {
        remoted::metrics::makeEndpointHttpMetrics(*m_metricsManager, "config", /*withLatency=*/false)};
    // /enroll DOES get a latency histogram: it is the only endpoint whose downstream is authd
    // (not the DeferredForwarder pair), and it is the sole evidence for sizing
    // 'remoted.authd_connect_timeout' / 'remoted.authd_response_timeout'. Unlike the four above,
    // the value is COPIED into the handler (see enrollment::makeHandler) rather than referenced,
    // so this member's address does not have to outlive a restart retry -- but it lives here for
    // the same reason as the rest: one resolution against the never-reset manager.
    remoted::metrics::EndpointHttpMetrics m_enrollHttpMetrics {
        remoted::metrics::makeEndpointHttpMetrics(*m_metricsManager, "enroll", /*withLatency=*/true)};
};

#endif // _REMOTED_MODULE_FACADE_HPP
