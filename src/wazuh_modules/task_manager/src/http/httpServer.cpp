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

#include <utility>

namespace
{
    using namespace wazuh::uds_http;

    constexpr auto SERVER_NAME {"task manager"};
    constexpr auto SERVER_HEADER {"wazuh-task-manager"};
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
        const auto route {[this](Method method,
                                 const std::string& path,
                                 RouteClass cls,
                                 ApiResponse (ApiHandlers::*fn)(const nlohmann::json&))
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
                                              responder->send(HttpResponse::json(
                                                  400, R"({"error":"invalid_json","message":"empty request"})"));
                                              return;
                                          }

                                          auto body = nlohmann::json::parse(request->body, nullptr, false);
                                          if (body.is_discarded())
                                          {
                                              responder->send(HttpResponse::json(
                                                  400,
                                                  R"({"error":"invalid_json","message":"body is not valid JSON"})"));
                                              return;
                                          }

                                          if (!body.is_object())
                                          {
                                              body = nlohmann::json::object();
                                          }

                                          const auto result {(m_handlers.*fn)(body)};
                                          responder->send(
                                              HttpResponse::json(result.status, result.body.dump()));
                                      }
                                      catch (const std::exception& exception)
                                      {
                                          LOGFN_ERROR(httpLogFn(),
                                                      "Unhandled error serving %s: %s",
                                                      path.c_str(),
                                                      exception.what());
                                          responder->send(HttpResponse::json(
                                              500, R"({"error":"internal_error","message":"see the manager log"})"));
                                      }
                                      catch (...)
                                      {
                                          responder->send(HttpResponse::json(
                                              500, R"({"error":"internal_error","message":"see the manager log"})"));
                                      }
                                  },
                                  RouteOptions {cls});
                          }};

        // Agent tasks. Data class: these carry producer-authored payloads and are the only routes
        // whose volume can be driven by something outside the manager, so they are the ones that
        // should shed first under memory pressure.
        route(Method::Post, "/v1/tasks", RouteClass::Data, &ApiHandlers::createAgentTask);
        route(Method::Post, "/v1/tasks/bulk", RouteClass::Data, &ApiHandlers::createAgentTasksBulk);
        route(Method::Post, "/v1/tasks/pending", RouteClass::Data, &ApiHandlers::takePendingAgentTasks);

        // Manager tasks. Control class: other daemons depend on these -- authd's deletion record
        // is created here -- so they must never be shed by agent-task pressure.
        route(Method::Post, "/v1/manager-tasks", RouteClass::Control, &ApiHandlers::createManagerTask);
        route(Method::Post, "/v1/manager-tasks/get", RouteClass::Control, &ApiHandlers::getManagerTask);
        route(Method::Post,
              "/v1/manager-tasks/by-agent",
              RouteClass::Control,
              &ApiHandlers::getManagerTaskByAgent);
        route(Method::Post, "/v1/manager-tasks/list", RouteClass::Control, &ApiHandlers::listManagerTasks);
        route(Method::Post, "/v1/manager-tasks/count", RouteClass::Control, &ApiHandlers::countManagerTasks);

        // Answered from resident state, so it stays available under any pressure -- which is the
        // whole point of a liveness probe.
        m_server->addRoute(
            Method::Get,
            "/v1/health",
            [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); },
            RouteOptions {RouteClass::Liveness});

        UdsHttpServerConfig config;
        config.socketPath = m_options.socketPath;
        config.ioThreads = static_cast<std::size_t>(m_options.ioThreads);
        config.maxBodySize = m_options.maxBodyBytes;
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
