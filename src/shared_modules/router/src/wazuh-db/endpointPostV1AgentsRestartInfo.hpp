/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 5, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_POST_V1_AGENTS_RESTART_INFO_HPP
#define _ENDPOINT_POST_V1_AGENTS_RESTART_INFO_HPP

#include "external/cpp-httplib/httplib.h"
#include "external/nlohmann/json.hpp"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

/**
 * @brief TEndpointPostV1AgentsRestartInfo class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointPostV1AgentsRestartInfo final
{
    struct AgentRestartInfo final
    {

        int64_t id {};
        std::string version;

        REFLECTABLE(MAKE_FIELD("id", &AgentRestartInfo::id), MAKE_FIELD("version", &AgentRestartInfo::version))
    };
    struct Response final
    {
        std::vector<AgentRestartInfo> agentRestartInfo;
        REFLECTABLE(MAKE_FIELD("items", &Response::agentRestartInfo))
    };

public:
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns valuable information to restart agents
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, [[maybe_unused]] const httplib::Request& req, httplib::Response& res)
    {

        Response response;

        nlohmann::json jsonBody;

        if (req.body.empty())
        {
            jsonBody = nlohmann::json::object();
        }
        else
        {
            jsonBody = nlohmann::json::parse(req.body);
        }

        std::string sqlQuery = "SELECT id, version FROM agent WHERE connection_status = 'active'";
        bool isFiltered {false};

        if (jsonBody.contains("ids") && jsonBody.at("ids").is_array() && !jsonBody.at("ids").empty())
        {
            isFiltered = true;
            std::string selectIds;
            bool negateFilter {false};

            for (size_t i = 0; i < jsonBody.at("ids").size(); ++i)
            {
                selectIds.empty() ? selectIds.append("?") : selectIds.append(",?");
            }

            if (jsonBody.contains("negate") && jsonBody.at("negate").is_boolean())
            {
                negateFilter = jsonBody.at("negate").get<bool>();
            }

            sqlQuery.append(" AND id ");
            if (negateFilter)
            {
                sqlQuery.append("NOT ");
            }

            sqlQuery.append("IN (" + selectIds + ")");
        }

        sqlQuery.append(";");

        DBStatement stmtAgentsRestartInfo(db, sqlQuery);

        if (isFiltered)
        {
            int bindIndex = 1;
            for (const auto& id : jsonBody.at("ids"))
            {
                stmtAgentsRestartInfo.bind(bindIndex++, id.get<int64_t>());
            }
        }

        while (stmtAgentsRestartInfo.step() == SQLITE_ROW)
        {

            response.agentRestartInfo.push_back({.id = stmtAgentsRestartInfo.template value<int64_t>(0),
                                                 .version = stmtAgentsRestartInfo.template value<std::string>(1)});
        }

        std::string jsonResponse;
        serializeToJSON<Response, false>(response, jsonResponse);
        res.body = std::move(jsonResponse);
        res.set_header("Content-Type", "application/json");
    }
};

using EndpointPostV1AgentsRestartInfo = TEndpointPostV1AgentsRestartInfo<>;

#endif /* _ENDPOINT_POST_V1_AGENTS_RESTART_INFO_HPP */
