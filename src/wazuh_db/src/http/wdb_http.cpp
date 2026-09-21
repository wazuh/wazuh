/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * August 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb_http.h"

#include <exception>
#include <memory>

#include "external/sqlite/sqlite3.h"
#include <defer.hpp>
#include <loggerHelper.h>
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include "endpointGetV1AgentsAll.hpp"
#include "endpointGetV1AgentsParamGroups.hpp"
#include "endpointGetV1AgentsSync.hpp"
#include "endpointGetV1Status.hpp"
#include "endpointPostV1AgentsSummary.hpp"
#include "endpointPostV1AgentsSync.hpp"
#include "sqlite3Wrapper.hpp"

extern "C"
{
    sqlite3* wdb_global_pre(void** wdb_ctx);
    void wdb_global_post(void* wdb_ctx);
}

namespace Log
{
    // Storage for the `extern` declared in loggerHelper.h. Each binary/DSO that pulls in that
    // header needs its own definition -- it's deliberately not declared `inline` there, so
    // GLOBAL_LOG_FUNCTION stays private per-DSO instead of being merged/interposed across them.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

namespace
{
    std::unique_ptr<wazuh::uds_http::IUdsHttpServer> g_server;

    // The response is always built by the endpoint and sent inline here: every TEndpoint::call()
    // runs a synchronous SQLite query, so there is never a reason to defer send() to another
    // thread. uds_http_server's handler contract forbids blocking the I/O thread; this socket is
    // low-traffic (cluster + REST API, not agent-facing), so that tradeoff is accepted rather than
    // adding a worker-thread dispatch layer.
    template<typename Endpoint>
    void registerRoute(wazuh::uds_http::IUdsHttpServer& server,
                       wazuh::uds_http::Method method,
                       const std::string& route,
                       wazuh::uds_http::RouteClass routeClass)
    {
        server.addRoute(
            method,
            route,
            [](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
               std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
            {
                if (!request)
                {
                    responder->send({400, "Empty request", {{"Content-Type", "text/plain"}}});
                    return;
                }

                void* ctx = nullptr;
                auto* db = wdb_global_pre(&ctx);
                DEFER([ctx]() { wdb_global_post(ctx); });

                if (!db)
                {
                    responder->send({500, "Database connection failed", {{"Content-Type", "text/plain"}}});
                    return;
                }

                // uds_http_server has no process-wide exception-to-500 fallback (e.g.
                // EndpointPostV1AgentsSync throws on malformed JSON) -- this is the one place
                // that has to provide it.
                try
                {
                    SQLite3Wrapper::Connection connection(db);
                    responder->send(Endpoint::call(connection, *request));
                }
                catch (const std::exception& e)
                {
                    logError("wazuh-manager-db", "HTTP endpoint handler failed: %s", e.what());
                    responder->send({500, "Internal server error", {{"Content-Type", "text/plain"}}});
                }
            },
            wazuh::uds_http::RouteOptions {routeClass});
    }

    // The status route cannot share registerRoute(): that wrapper answers 500 when the database
    // is unreachable, and for this route being unable to serve IS the answer, not an internal
    // fault. A caller asking "can you serve?" needs 503, which tells it to route elsewhere; a 500
    // reads as "this endpoint is broken" and says nothing about the daemon's ability to work.
    //
    // It is registered as Liveness so back-pressure on the data plane never sheds it: a status
    // route that gets dropped exactly when the daemon is struggling answers the wrong question.
    // The class is about shedding policy and body caps, not semantics -- liveness and readiness
    // remain distinct routes with distinct answers (issue #39429).
    void registerStatusRoute(wazuh::uds_http::IUdsHttpServer& server)
    {
        server.addRoute(
            wazuh::uds_http::Method::Get,
            "/v1/status",
            [](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
               std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
            {
                static constexpr auto UNAVAILABLE_BODY =
                    R"({"status":"unavailable","module":"wazuh-db","global":{"available":false,"missing_tables":[]}})";

                if (!request)
                {
                    responder->send({400, "Empty request", {{"Content-Type", "text/plain"}}});
                    return;
                }

                void* ctx = nullptr;
                auto* db = wdb_global_pre(&ctx);
                DEFER([ctx]() { wdb_global_post(ctx); });

                if (!db)
                {
                    responder->send(wazuh::uds_http::HttpResponse::json(503, UNAVAILABLE_BODY));
                    return;
                }

                try
                {
                    SQLite3Wrapper::Connection connection(db);
                    responder->send(EndpointGetV1Status::call(connection, *request));
                }
                catch (const std::exception& e)
                {
                    // A throw here means the query could not run at all, which is the same verdict
                    // as a failed connection: report it, do not hide it behind a 500.
                    logError("wazuh-manager-db", "Status endpoint could not query the database: %s", e.what());
                    responder->send(wazuh::uds_http::HttpResponse::json(503, UNAVAILABLE_BODY));
                }
            },
            wazuh::uds_http::RouteOptions {wazuh::uds_http::RouteClass::Liveness});
    }
} // namespace

void wdb_http_start(full_log_fnc_t callbackLog, const char* socket_path)
{
    Log::assignLogFunction(callbackLog);

    // Any failure here (bad socket path, bind error, etc.) must not escape as a C++ exception:
    // this function is called from main.c across an extern "C" boundary, where there is no
    // handler to catch it and the process would std::terminate.
    try
    {
        auto server = wazuh::uds_http::makeUdsHttpServer();

        // Control: empty body, tiny response -- must not be shed by Data-plane pressure, same
        // reasoning as inventory_sync_server's header-carried agent routes.
        registerRoute<EndpointGetV1AgentsParamGroups>(
            *server, wazuh::uds_http::Method::Get, "/v1/agents/groups", wazuh::uds_http::RouteClass::Control);
        // Data: bulk/unbounded payloads.
        registerRoute<EndpointGetV1AgentsAll>(
            *server, wazuh::uds_http::Method::Get, "/v1/agents/all", wazuh::uds_http::RouteClass::Data);
        registerRoute<EndpointPostV1AgentsSummary>(
            *server, wazuh::uds_http::Method::Post, "/v1/agents/summary", wazuh::uds_http::RouteClass::Data);
        registerRoute<EndpointGetV1AgentsSync>(
            *server, wazuh::uds_http::Method::Get, "/v1/agents/sync", wazuh::uds_http::RouteClass::Data);
        registerRoute<EndpointPostV1AgentsSync>(
            *server, wazuh::uds_http::Method::Post, "/v1/agents/sync", wazuh::uds_http::RouteClass::Data);
        // Readiness: can this daemon serve at all? Answered without reading agent data.
        registerStatusRoute(*server);

        wazuh::uds_http::UdsHttpServerConfig config;
        config.socketPath = socket_path;
        config.logTag = "wazuh-manager-db";
        config.serverName = "wazuh-db HTTP";
        config.serverHeader = "wazuh-manager-db";

        server->start(config);
        g_server = std::move(server);
    }
    catch (const std::exception& e)
    {
        logError("wazuh-manager-db", "Failed to start HTTP API server: %s", e.what());
    }
}

void wdb_http_stop(void)
{
    if (g_server)
    {
        g_server->stopAccepting();
        g_server->stop();
        g_server.reset();
    }
}
