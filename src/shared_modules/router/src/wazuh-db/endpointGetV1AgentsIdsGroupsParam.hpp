/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 30, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_PARAM_HPP
#define _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_PARAM_HPP

#include "external/cpp-httplib/httplib.h"
#include "logging_helper.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief EndpointGetV1AgentsIdsGroupsParam class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointGetV1AgentsIdsGroupsParam final
{
    struct Response final
    {
        std::vector<int> agentIds;

        REFLECTABLE(MAKE_FIELD("agent_ids", &Response::agentIds))
    };

public:
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns the agent ids
     * for a specific group.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, const httplib::Request& req, httplib::Response& res)
    {
        auto it = req.path_params.find("name");
        if (it == req.path_params.end())
        {
            logMessage(modules_log_level_t::LOG_INFO, "Missing parameter: name");
            res.status = 400;
            res.set_content("Missing parameter: name", "text/plain");
            return;
        }

        DBStatement stmt(
            db,
            "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;");
        stmt.bind(1, it->second);

        Response resObj;
        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentIds.push_back(stmt.template value<int64_t>(0));
        }

        res.set_content(serializeToJSON(resObj), "application/json");
    }
};

using EndpointGetV1AgentsIdsGroupsParam = TEndpointGetV1AgentsIdsGroupsParam<>;

#endif /* _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_PARAM_HPP */
