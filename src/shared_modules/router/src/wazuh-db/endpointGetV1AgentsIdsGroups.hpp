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

#ifndef _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_HPP
#define _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_HPP

#include "external/cpp-httplib/httplib.h"
#include "logging_helper.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief EndpointGetV1AgentsIdsGroups class.
 *
 */
template<typename DBConnection = SQLite3Wrapper::Connection, typename DBStatement = SQLite3Wrapper::Statement>
class TEndpointGetV1AgentsIdsGroups final
{
    struct Response final
    {
        std::map<std::string, std::vector<std::string>, std::less<>> agentIds;

        REFLECTABLE(MAKE_FIELD("data", &Response::agentIds))
    };

public:
    virtual ~TEndpointGetV1AgentsIdsGroups() = default; // LCOV_EXCL_LINE
    /**
     * @brief Call the endpoint implementation, this functions populates a Response object with the
     * data from the database. This particular implementation returns the agent ids and the
     * groups they belong to.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, [[maybe_unused]] const httplib::Request& req, httplib::Response& res)
    {
        DBStatement stmt(db, // LCOV_EXCL_LINE
                         "SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON "
                         "b.id_group=g.id WHERE b.id_agent > 0;");

        Response resObj;
        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentIds[std::to_string(stmt.template value<int64_t>(0))].push_back(
                stmt.template value<std::string>(1));
        }
        std::string jsonResponse;
        serializeToJSON(resObj, jsonResponse);
        res.set_content(jsonResponse, "application/json");
    }
};

// LCOV_EXCL_START
using EndpointGetV1AgentsIdsGroups = TEndpointGetV1AgentsIdsGroups<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_GET_V1_AGENTS_IDS_GROUPS_HPP */
