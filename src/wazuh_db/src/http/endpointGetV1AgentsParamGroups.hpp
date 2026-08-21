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

#ifndef _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP
#define _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP

#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"
#include <loggerHelper.h>
#include <uds_http_server/IUdsHttpServer.hpp>

/**
 * @brief TEndpointGetV1AgentsParamGroups class.
 *
 */
template<typename DBConnection = SQLite3Wrapper::Connection, typename DBStatement = SQLite3Wrapper::Statement>
class TEndpointGetV1AgentsParamGroups final
{
    static constexpr auto LOGTAG = "wazuh-db-http";
    // uds_http_server routes exact-match only, so the agent id can't travel as a path segment
    // (see wdb_http.cpp) -- it travels in this header instead, the same convention
    // inventory_sync_server's DELETE /agents uses. Header names are lower-cased by the transport.
    static constexpr auto AGENT_ID_HEADER = "x-wazuh-agent-id";

    struct Response final
    {
        std::vector<std::string> agentGroups;

        REFLECTABLE(MAKE_FIELD("agent_groups", &Response::agentGroups))
    };

public:
    virtual ~TEndpointGetV1AgentsParamGroups() = default; // LCOV_EXCL_LINE
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns the groups for a specific agent.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @return The HTTP response.
     */
    static wazuh::uds_http::HttpResponse call(const DBConnection& db, const wazuh::uds_http::HttpRequest& req)
    {
        auto it = req.headers.find(AGENT_ID_HEADER);
        if (it == req.headers.end())
        {
            logWarn(LOGTAG, "Missing header: agent id");
            return {400, "Missing header: X-Wazuh-Agent-Id", {{"Content-Type", "text/plain"}}};
        }

        DBStatement stmt( // LCOV_EXCL_LINE
            db,
            "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

        stmt.bind(1, std::stoi(it->second));

        Response resObj;
        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentGroups.push_back(stmt.template value<std::string>(0));
        }

        return wazuh::uds_http::HttpResponse::json(200, serializeToJSON(resObj));
    }
};

// LCOV_EXCL_START
using EndpointGetV1AgentsParamGroups = TEndpointGetV1AgentsParamGroups<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP */
