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

#ifndef _ENDPOINT_POST_V1_AGENTS_SYNC_HPP
#define _ENDPOINT_POST_V1_AGENTS_SYNC_HPP

#include "external/cpp-httplib/httplib.h"
#include "external/nlohmann/json.hpp"
#include "logging_helper.h"
#include "sqlite3Wrapper.hpp"

void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief EndpointPostV1AgentsSync class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointPostV1AgentsSync final
{
    template<typename T>
    static T value(const nlohmann::json& json, std::string_view key)
    {
        if (json.contains(key))
        {
            return json.at(key).get<T>();
        }

        if constexpr (std::is_same_v<T, std::string_view>)
        {
            return std::string_view {""};
        }
        else
        {
            return T {};
        }
    }

public:
    /**
     * @brief Call the endpoint implementation. This function write the data to the database with the received
     * request body. Basically this function is used to update the agent status.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, const httplib::Request& req, [[maybe_unused]] const httplib::Response& res)
    {
        nlohmann::json jsonBody = nlohmann::json::parse(req.body);

        {
            if (jsonBody.contains("syncreq"))
            {
                DBStatement stmt(db,
                                 "UPDATE agent SET config_sum = ?, ip = ?, manager_host = ?, merged_sum = "
                                 "?, name = ?, node_name = ?, os_arch = ?, os_build = ?, "
                                 "os_codename = ?, os_major = ?, os_minor = ?, os_name = ?, "
                                 "os_platform = ?, os_uname = ?, os_version = ?, version = ?, "
                                 "last_keepalive = ?, connection_status = ?, disconnection_time = "
                                 "?, group_config_status = ?, status_code= ?, "
                                 "sync_status = 'synced' WHERE id = ?;");

                const auto& syncReq = jsonBody.at("syncreq");
                for (const auto& agent : syncReq)
                {
                    stmt.bind(1, value<std::string_view>(agent, "config_sum"));
                    stmt.bind(2, value<std::string_view>(agent, "ip"));
                    stmt.bind(3, value<std::string_view>(agent, "manager_host"));
                    stmt.bind(4, value<std::string_view>(agent, "merged_sum"));
                    stmt.bind(5, value<std::string_view>(agent, "name"));
                    stmt.bind(6, value<std::string_view>(agent, "node_name"));
                    stmt.bind(7, value<std::string_view>(agent, "os_arch"));
                    stmt.bind(8, value<std::string_view>(agent, "os_build"));
                    stmt.bind(9, value<std::string_view>(agent, "os_codename"));
                    stmt.bind(10, value<std::string_view>(agent, "os_major"));
                    stmt.bind(11, value<std::string_view>(agent, "os_minor"));
                    stmt.bind(12, value<std::string_view>(agent, "os_name"));
                    stmt.bind(13, value<std::string_view>(agent, "os_platform"));
                    stmt.bind(14, value<std::string_view>(agent, "os_uname"));
                    stmt.bind(15, value<std::string_view>(agent, "os_version"));
                    stmt.bind(16, value<std::string_view>(agent, "version"));
                    stmt.bind(17, value<int64_t>(agent, "last_keepalive"));
                    stmt.bind(18, value<std::string_view>(agent, "connection_status"));
                    stmt.bind(19, value<int64_t>(agent, "disconnection_time"));
                    stmt.bind(20, value<std::string_view>(agent, "group_config_status"));
                    stmt.bind(21, value<int64_t>(agent, "status_code"));
                    stmt.bind(22, value<int64_t>(agent, "id"));
                    stmt.step();
                    stmt.reset();
                }
            }
        }

        {
            if (jsonBody.contains("syncreq_keepalive"))
            {
                DBStatement stmt(db,
                                 "UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'),sync_status = 'synced',"
                                 "connection_status = 'active',disconnection_time = 0,"
                                 "status_code = 0 WHERE id = ?;");

                for (const auto& agent : jsonBody.at("syncreq_keepalive"))
                {
                    stmt.bind(1, agent.get<int64_t>());
                    stmt.step();
                    stmt.reset();
                }
            }
        }

        {
            if (jsonBody.contains("syncreq_status"))
            {
                DBStatement stmt(
                    db,
                    "UPDATE agent SET connection_status = ?, sync_status = 'synced', disconnection_time = ?, "
                    "status_code = ? WHERE id = ?;");

                for (const auto& agent : jsonBody.at("syncreq_status"))
                {
                    stmt.bind(1, value<std::string_view>(agent, "connection_status"));
                    stmt.bind(2, value<int64_t>(agent, "disconnection_time"));
                    stmt.bind(3, value<int64_t>(agent, "status_code"));
                    stmt.bind(4, agent.at("id").get<int64_t>());
                    stmt.step();
                    stmt.reset();
                }
            }
        }
    }
};

using EndpointPostV1AgentsSync = TEndpointPostV1AgentsSync<>;

#endif /* _ENDPOINT_POST_V1_AGENTS_SYNC_HPP */
