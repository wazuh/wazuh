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

#ifndef _ENDPOINT_POST_V1_AGENTS_SUMMARY_HPP
#define _ENDPOINT_POST_V1_AGENTS_SUMMARY_HPP

#include "external/cpp-httplib/httplib.h"
#include "logging_helper.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

void logMessage(modules_log_level_t level, const std::string& msg);

/**
 * @brief EndpointPostV1AgentsSummary class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointPostV1AgentsSummary final
{
public:
    virtual ~TEndpointPostV1AgentsSummary() = default; // LCOV_EXCL_LINE
    /**
     * @brief Response structure.
     */
    struct Response final
    {
        std::map<std::string, int64_t, std::less<>> agentsByStatus; ///< Agents by status
        std::map<std::string, int64_t, std::less<>> agentsByGroups; ///< Agents by groups
        std::map<std::string, int64_t, std::less<>> agentsByOs;     ///< Agents by OS

        REFLECTABLE(MAKE_FIELD("agents_by_status", &Response::agentsByStatus),
                    MAKE_FIELD("agents_by_groups", &Response::agentsByGroups),
                    MAKE_FIELD("agents_by_os", &Response::agentsByOs))
    };
    /**
     * @brief Call the endpoint implementation. This function is used to populate a Response object with the
     * data from the database. This particular implementation returns the agent summary. The agent summary
     * is a summary of the agents status, groups and OS.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, const httplib::Request& req, httplib::Response& res)
    {
        // Queries for connections
        constexpr std::string_view queryConnection = // LCOV_EXCL_LINE
            "SELECT id, connection_status AS status FROM agent WHERE id > 0;";
        constexpr std::string_view queryOs = // LCOV_EXCL_LINE
            "SELECT id, os_platform AS platform FROM agent WHERE id > 0 AND "
            "os_platform IS NOT NULL AND os_platform <> '';";
        constexpr std::string_view queryGroup = // LCOV_EXCL_LINE
            "SELECT b.id_agent, g.name AS group_name FROM belongs b JOIN 'group' g "
            "ON b.id_group=g.id WHERE b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '';";

        constexpr std::string_view queryConnectionNoFilter = // LCOV_EXCL_LINE
            "SELECT COUNT(*) as quantity, connection_status AS status FROM agent "
            "WHERE id > 0 GROUP BY status ORDER BY status ASC limit 5;";

        constexpr std::string_view queryOsNoFilter = // LCOV_EXCL_LINE
            "SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 "
            "AND os_platform IS NOT NULL AND os_platform <> '' GROUP BY platform ORDER BY quantity DESC limit 5;";

        constexpr std::string_view queryGroupsNoFilter = // LCOV_EXCL_LINE
            "SELECT COUNT(*) as q, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE "
            "b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '' GROUP BY b.id_group ORDER BY q DESC LIMIT 5;";

        Response response;

        if (req.body.empty())
        {
            DBStatement stmtConnections(db, queryConnectionNoFilter); // LCOV_EXCL_LINE

            while (stmtConnections.step() == SQLITE_ROW)
            {
                const auto quantity = stmtConnections.template value<std::int64_t>(0);
                const auto status = stmtConnections.template value<std::string>(1);
                response.agentsByStatus[status] = quantity;
            }

            DBStatement stmtGroups(db, queryGroupsNoFilter); // LCOV_EXCL_LINE

            while (stmtGroups.step() == SQLITE_ROW)
            {
                const auto quantity = stmtGroups.template value<std::int64_t>(0);
                const auto status = stmtGroups.template value<std::string>(1);
                response.agentsByGroups[status] = quantity;
            }

            DBStatement stmtOS(db, queryOsNoFilter); // LCOV_EXCL_LINE

            while (stmtOS.step() == SQLITE_ROW)
            {
                const auto quantity = stmtOS.template value<std::int64_t>(0);
                const auto status = stmtOS.template value<std::string>(1);
                response.agentsByOs[status] = quantity;
            }
        }
        else
        {
            std::vector<std::int64_t> body;
            // count commas in the body
            const size_t count = std::count(req.body.begin(), req.body.end(), ',');
            body.reserve(count + 1);

            std::string_view view = req.body;
            size_t pos = 0;

            while (pos < view.size())
            {
                // Skip characters that are not part of the number
                pos = view.find_first_of("0123456789-", pos);
                if (pos == std::string_view::npos)
                {
                    break;
                }

                // Find the end of the number
                size_t end = pos;
                while (end < view.size() && (std::isdigit(view[end]) || view[end] == '-'))
                {
                    ++end;
                }

                int value;
                auto [ptr, ec] = std::from_chars(view.data() + pos, view.data() + end, value);
                if (ec == std::errc())
                {
                    body.push_back(value);
                }

                pos = end;
            }

            std::sort(body.begin(), body.end());

            DBStatement stmtConnections(db, queryConnection); // LCOV_EXCL_LINE

            while (stmtConnections.step() == SQLITE_ROW)
            {
                const auto id = stmtConnections.template value<std::int64_t>(0);
                const auto status = stmtConnections.template value<std::string>(1);

                if (std::binary_search(body.begin(), body.end(), id))
                {
                    ++response.agentsByStatus[status];
                }
            }

            DBStatement stmtGroups(db, queryGroup); // LCOV_EXCL_LINE

            while (stmtGroups.step() == SQLITE_ROW)
            {
                const auto id = stmtGroups.template value<std::int64_t>(0);
                const auto status = stmtGroups.template value<std::string>(1);

                if (std::binary_search(body.begin(), body.end(), id))
                {
                    ++response.agentsByGroups[status];
                }
            }

            DBStatement stmtOS(db, queryOs); // LCOV_EXCL_LINE

            while (stmtOS.step() == SQLITE_ROW)
            {
                const auto id = stmtOS.template value<std::int64_t>(0);
                const auto status = stmtOS.template value<std::string>(1);

                if (std::binary_search(body.begin(), body.end(), id))
                {
                    ++response.agentsByOs[status];
                }
            }
        }

        std::string jsonResponse;
        serializeToJSON(response, jsonResponse);
        res.body = std::move(jsonResponse);
        res.set_header("Content-Type", "application/json");
    }
};

// LCOV_EXCL_START
using EndpointPostV1AgentsSummary = TEndpointPostV1AgentsSummary<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_POST_V1_AGENTS_SUMMARY_HPP */
