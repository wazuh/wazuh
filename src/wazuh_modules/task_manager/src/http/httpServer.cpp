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

#include "httpServer.hpp"

#include "taskManagerLog.hpp"

#include <uds_http_server/udsHttpServerFactory.hpp>
#include <wazuh_metrics/jsonDump.hpp>

#include <algorithm>
#include <memory>
#include <utility>

namespace
{
    using namespace wazuh::uds_http;

    constexpr auto SERVER_NAME {"task manager"};
    constexpr auto SERVER_HEADER {"wazuh-task-manager"};

    /// @brief Concurrent connections `POST /v1/manager-tasks` may hold.
    ///
    /// A MEMORY bound, not a quality-of-service one, and it exists because that route's body cap is
    /// raised to `max_payload_bytes` while Control stays budget-exempt: the class's own protection
    /// is a small body cap AND a session cap together, so raising one without the other would leave
    /// nothing bounding what the route can hold resident. Set far above what the two producers ever
    /// generate -- authd creates deletion rows from one thread and the vulnerability scanner from a
    /// single callback -- so it should never shed real traffic.
    constexpr std::size_t CREATE_MAX_SESSIONS {128};

    /// @brief Concurrent connections the two upgrade routes may hold, over and above the class cap.
    ///        Comfortably above the pool's queue depth, so shedding is decided by the module -- with
    ///        a per-agent answer the Server API can retry -- rather than by the transport's 503.
    constexpr std::size_t UPGRADE_MAX_SESSIONS {32};
} // namespace

namespace task_manager::http
{
    HttpServer::HttpServer(ApiHandlers& handlers, Options options)
        : m_handlers {handlers}
        , m_options {std::move(options)}
    {
    }

    HttpServer::~HttpServer()
    {
        stop();
    }

    void HttpServer::start()
    {
        m_server = makeUdsHttpServer();

        // One adapter for every JSON route: parse, dispatch, answer. The try/catch is the barrier
        // that keeps a handler bug from taking the I/O thread with it -- and therefore from
        // silently stopping every other route.
        const auto route {
            [this](Method method,
                   const std::string& path,
                   RouteClass cls,
                   ApiResponse (ApiHandlers::*fn)(const nlohmann::json&),
                   const std::size_t maxBodyBytes = 0,
                   const std::size_t maxSessions = 0)
            {
                m_server->addRoute(
                    method,
                    path,
                    [this, fn, path](std::shared_ptr<const HttpRequest> request,
                                     std::shared_ptr<IHttpResponder> responder)
                    {
                        try
                        {
                            if (!request)
                            {
                                responder->send(
                                    HttpResponse::json(400, R"({"error":"invalid_json","message":"empty request"})"));
                                return;
                            }

                            auto body = nlohmann::json::parse(request->body, nullptr, false);
                            if (body.is_discarded())
                            {
                                responder->send(HttpResponse::json(
                                    400, R"({"error":"invalid_json","message":"body is not valid JSON"})"));
                                return;
                            }

                            if (!body.is_object())
                            {
                                body = nlohmann::json::object();
                            }

                            const auto result {(m_handlers.*fn)(body)};
                            responder->send(HttpResponse::json(result.status, result.body.dump()));
                        }
                        catch (const std::exception& exception)
                        {
                            LOGFN_ERROR(httpLogFn(), "Unhandled error serving %s: %s", path.c_str(), exception.what());
                            responder->send(HttpResponse::json(
                                500, R"({"error":"internal_error","message":"see the manager log"})"));
                        }
                        catch (...)
                        {
                            responder->send(HttpResponse::json(
                                500, R"({"error":"internal_error","message":"see the manager log"})"));
                        }
                    },
                    RouteOptions {cls, maxBodyBytes, maxSessions});
            }};

        // Agent tasks. Data class: these carry producer-authored payloads and are the only routes
        // whose volume can be driven by something outside the manager, so they are the ones that
        // should shed first under memory pressure.
        route(Method::Post, "/v1/tasks", RouteClass::Data, &ApiHandlers::createAgentTask);
        route(Method::Post, "/v1/tasks/bulk", RouteClass::Data, &ApiHandlers::createAgentTasksBulk);
        route(Method::Post, "/v1/tasks/pending", RouteClass::Data, &ApiHandlers::takePendingAgentTasks);

        // Manager tasks. Control class: other daemons depend on these -- authd's deletion record
        // is created here -- so they must never be shed by agent-task pressure.
        //
        // The CREATE route alone carries a producer-authored payload, so it alone gets the body cap
        // raised to one `max_payload_bytes`; without that, configuring the option above the Control
        // class default of 64 KB would silently do nothing, refused by the transport with a 413
        // before the handler that owns the limit ever saw the body.
        //
        // Raised PER ROUTE rather than on the class, and that is the whole point of doing it here:
        // Control is budget-exempt by design, so moving the class cap would have made 256 exempt
        // sessions worth up to a megabyte each -- swapping a 16 MB worst case for a 280 MB one, on
        // every Control route including the four that only ever carry a task id. The paired session
        // cap bounds what this one route can hold resident.
        route(Method::Post,
              "/v1/manager-tasks",
              RouteClass::Control,
              &ApiHandlers::createManagerTask,
              m_options.createMaxBodyBytes,
              CREATE_MAX_SESSIONS);
        route(Method::Post, "/v1/manager-tasks/get", RouteClass::Control, &ApiHandlers::getManagerTask);
        route(Method::Post, "/v1/manager-tasks/by-agent", RouteClass::Control, &ApiHandlers::getManagerTaskByAgent);
        route(Method::Post, "/v1/manager-tasks/list", RouteClass::Control, &ApiHandlers::listManagerTasks);
        route(Method::Post, "/v1/manager-tasks/count", RouteClass::Control, &ApiHandlers::countManagerTasks);

        // Agent upgrades. Control class, and registered directly rather than through route()
        // above: these are the only ASYNCHRONOUS routes on this socket -- the handler parses, hands
        // the batch to a worker pool and returns without answering, and the reply is sent from that
        // pool through the retained responder. route() cannot express that, and its error envelope
        // is the wrong one besides: the Server API reads the retired module's per-agent shape.
        //
        // maxSessions bounds how many upgrade requests can hold a connection open at once,
        // independently of the pool's own queue. Without it a client could park far more
        // connections than there is work capacity, and they would all be waiting on the same
        // handful of workers.
        if (m_upgradeApi != nullptr)
        {
            m_server->addRoute(
                Method::Post,
                upgrade::UPGRADE_ROUTE,
                [this](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                { m_upgradeApi->handleUpgrade(std::move(request), std::move(responder)); },
                RouteOptions {RouteClass::Control, 0, UPGRADE_MAX_SESSIONS});

            m_server->addRoute(
                Method::Post,
                upgrade::UPGRADE_CUSTOM_ROUTE,
                [this](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                { m_upgradeApi->handleUpgradeCustom(std::move(request), std::move(responder)); },
                RouteOptions {RouteClass::Control, 0, UPGRADE_MAX_SESSIONS});
        }

        // Answered from resident state, so it stays available under any pressure -- which is the
        // whole point of a liveness probe.
        m_server->addRoute(
            Method::Get,
            "/v1/health",
            [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); },
            RouteOptions {RouteClass::Liveness});

        // GET, and one of only two on this socket. Every other route is a POST because the C
        // clients that call them speak POST only; this one has no C client and no body, so the verb
        // that describes it is the one it gets -- the same choice inventory-sync's `GET /metrics`
        // makes, which keeps one operator vocabulary across the two modules.
        //
        // Registered only when a registry was attached. Without this route the whole of
        // metrics/taskMetrics.cpp writes into an object nothing can read: queue depth per type,
        // executor occupancy, handler-duration histograms, outcome counters and the transport's own
        // diagnostics were all collected and then unobservable, which was the ONE gap the C
        // implementation could not close and therefore the one this module must.
        if (const auto metrics {m_metricsManager.lock()}; metrics)
        {
            m_server->addRoute(
                Method::Get,
                "/v1/metrics",
                [weak = m_metricsManager](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                {
                    const auto manager {weak.lock()};
                    if (!manager)
                    {
                        // Only reachable if the registry outlives its own teardown ordering. See
                        // setMetricsManager().
                        responder->send(
                            HttpResponse::json(503, R"({"error":"unavailable","message":"metrics registry is gone"})"));
                        return;
                    }

                    wazuh::metrics::DumpOptions options;
                    options.daemonName = "task_manager";
                    responder->send(HttpResponse::json(200, wazuh::metrics::dumpJson(*manager, options)));
                },
                RouteOptions {RouteClass::Control});
        }

        UdsHttpServerConfig config;
        config.socketPath = m_options.socketPath;
        config.ioThreads = static_cast<std::size_t>(m_options.ioThreads);
        // Never below the largest single body any route admits: the server-wide cap is checked as
        // well as the per-route one, so the smaller of the two wins and a per-route override above
        // this value would achieve nothing.
        config.maxBodySize = std::max(m_options.maxBodyBytes, m_options.createMaxBodyBytes);
        config.logTag = TASK_MANAGER_HTTP_LOGTAG;
        config.serverName = SERVER_NAME;
        config.serverHeader = SERVER_HEADER;

        m_server->start(config);

        LOGFN_INFO(httpLogFn(), "Listening on '%s'", m_options.socketPath.c_str());
    }

    void HttpServer::stopAccepting() noexcept
    {
        if (m_server)
        {
            m_server->stopAccepting();
        }
    }

    void HttpServer::stop() noexcept
    {
        if (m_server)
        {
            m_server->stop();
            m_server.reset();
        }
    }

    void HttpServer::registerDiagnostics(metrics::TaskMetrics& metrics)
    {
        // Pull metrics rather than gauges: the transport already tracks these as relaxed atomics,
        // so reading them on demand costs nothing and keeps the library free of a metrics
        // dependency. The lambdas capture `this`, which outlives the metrics manager.
        metrics.registerPull(
            "task_manager.http.live_sessions",
            [this] { return m_server ? m_server->diagnostics().liveSessions : 0; },
            "Open connections on the task manager socket",
            "connections");

        metrics.registerPull(
            "task_manager.http.inflight_requests",
            [this] { return m_server ? m_server->diagnostics().budgetInFlightCount : 0; },
            "Requests currently holding a budget reservation",
            "requests");

        metrics.registerPull(
            "task_manager.http.inflight_bytes",
            [this] { return m_server ? m_server->diagnostics().budgetInFlightBytes : 0; },
            "Bytes reserved from the in-flight budget",
            "bytes");
    }
} // namespace task_manager::http
