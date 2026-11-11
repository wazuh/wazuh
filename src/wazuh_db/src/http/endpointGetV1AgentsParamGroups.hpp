/*
 * Wazuh Database Daemon
 * Copyright (C) Wazuh Inc.
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
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <limits>
#include <loggerHelper.h>
#include <optional>
#include <string_view>
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/logThrottle.hpp>

/**
 * @brief TEndpointGetV1AgentsParamGroups class.
 *
 */
template<typename DBConnection = SQLite3Wrapper::Connection, typename DBStatement = SQLite3Wrapper::Statement>
class TEndpointGetV1AgentsParamGroups final
{
    // The daemon's own tag, like every other line wazuh-manager-db writes.
    static constexpr auto LOGTAG = "wazuh-manager-db";
    // uds_http_server routes exact-match only, so the agent id can't travel as a path segment
    // (see wdb_http.cpp) -- it travels in this header instead, the same convention
    // inventory_sync_server's sync routes use. Header names are lower-cased by the transport.
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
        // A caller bug, not an operational event, and the caller controls the rate: one line per
        // window, carrying the count, instead of one per request. One slot per condition.
        static wazuh::uds_http::LogThrottle missingThrottle;
        static wazuh::uds_http::LogThrottle invalidThrottle;

        auto it = req.headers.find(AGENT_ID_HEADER);
        if (it == req.headers.end())
        {
            if (const auto decision = missingThrottle.record())
            {
                logWarn(LOGTAG,
                        "Rejected %llu agent groups request(s) %s: missing the agent id header.",
                        static_cast<unsigned long long>(decision.total),
                        decision.period().c_str());
            }
            return {400, "Missing header: X-Wazuh-Agent-Id", {{"Content-Type", "text/plain"}}};
        }

        const auto agentId = parseAgentId(it->second);
        if (!agentId)
        {
            if (const auto decision = invalidThrottle.record())
            {
                logWarn(LOGTAG,
                        "Rejected %llu agent groups request(s) %s: the agent id header is not a "
                        "numeric agent id.",
                        static_cast<unsigned long long>(decision.total),
                        decision.period().c_str());
            }
            return {
                400, "Invalid header: X-Wazuh-Agent-Id must be a numeric agent id", {{"Content-Type", "text/plain"}}};
        }

        DBStatement stmt( // LCOV_EXCL_LINE
            db,
            "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

        stmt.bind(1, *agentId);

        Response resObj;
        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentGroups.push_back(stmt.template value<std::string>(0));
        }

        return wazuh::uds_http::HttpResponse::json(200, serializeToJSON(resObj));
    }

private:
    /**
     * @brief Parse an agent id strictly: decimal digits only (leading zeros allowed, as in "001"),
     * within the 32-bit signed range. Anything else -- empty, a sign, spaces, a trailing suffix such
     * as "1abc", or an overflow -- is rejected rather than truncated onto another agent's id.
     *
     * @param text Header value.
     * @return The id, or nullopt when the value is not an agent id.
     */
    static std::optional<std::int32_t> parseAgentId(std::string_view text)
    {
        if (text.empty() ||
            !std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        {
            return std::nullopt;
        }

        std::int64_t value {0};
        const auto* end = text.data() + text.size();
        const auto [ptr, ec] = std::from_chars(text.data(), end, value);
        if (ec != std::errc {} || ptr != end || value > std::numeric_limits<std::int32_t>::max())
        {
            return std::nullopt;
        }

        return static_cast<std::int32_t>(value);
    }
};

// LCOV_EXCL_START
using EndpointGetV1AgentsParamGroups = TEndpointGetV1AgentsParamGroups<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_GET_V1_AGENTS_PARAM_GROUPS_HPP */
