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

#include <memory>

#include "external/sqlite/sqlite3.h"
#include <defer.hpp>
#include <httpsrv/server.hpp>
#include <loggerHelper.h>

#include "endpointGetV1AgentsAll.hpp"
#include "endpointGetV1AgentsParamGroups.hpp"
#include "endpointGetV1AgentsSync.hpp"
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
    std::unique_ptr<httpsrv::Server> g_server;

    template<typename Endpoint>
    void registerRoute(httpsrv::Server& server, httpsrv::Method method, const std::string& route)
    {
        server.addRoute(method,
                        route,
                        [](const httplib::Request& req, httplib::Response& res)
                        {
                            void* ctx = nullptr;
                            auto* db = wdb_global_pre(&ctx);
                            DEFER([ctx]() { wdb_global_post(ctx); });

                            if (!db)
                            {
                                res.status = 500;
                                res.set_content("Database connection failed", "text/plain");
                                return;
                            }

                            SQLite3Wrapper::Connection connection(db);
                            Endpoint::call(connection, req, res);
                        });
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
        auto server = std::make_unique<httpsrv::Server>("wazuh-manager-db");

        registerRoute<EndpointGetV1AgentsParamGroups>(*server, httpsrv::Method::GET, "/v1/agents/:agent_id/groups");
        registerRoute<EndpointGetV1AgentsAll>(*server, httpsrv::Method::GET, "/v1/agents/all");
        registerRoute<EndpointPostV1AgentsSummary>(*server, httpsrv::Method::POST, "/v1/agents/summary");
        registerRoute<EndpointGetV1AgentsSync>(*server, httpsrv::Method::GET, "/v1/agents/sync");
        registerRoute<EndpointPostV1AgentsSync>(*server, httpsrv::Method::POST, "/v1/agents/sync");

        server->start(socket_path);
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
        g_server->stop();
        g_server.reset();
    }
}
