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

#ifndef _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP
#define _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP

#include "external/cpp-httplib/httplib.h"
#include "logging_helper.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief TEndpointGetV1AgentsParamGroups class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointGetV1AgentsParamGroups final
{
    struct Response final
    {
        std::vector<std::string> agentGroups;

        REFLECTABLE(MAKE_FIELD("agent_groups", &Response::agentGroups))
    };

public:
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns the groups for a specific agent.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, const httplib::Request& req, httplib::Response& res)
    {
        auto it = req.path_params.find("agent_id");
        if (it == req.path_params.end())
        {
            logMessage(modules_log_level_t::LOG_INFO, "Missing parameter: agent id");
            res.status = 400;
            res.set_content("Missing parameter: id", "text/plain");
            return;
        }

        DBStatement stmt(db,
                         "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

        stmt.bind(1, std::stoi(it->second));

        Response resObj;
        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentGroups.push_back(stmt.template value<std::string>(0));
        }

        res.set_content(serializeToJSON(resObj), "application/json");
    }
};

using EndpointGetV1AgentsParamGroups = TEndpointGetV1AgentsParamGroups<>;

#endif /* _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP */
