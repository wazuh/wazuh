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

#ifndef _ENDPOINT_GET_V1_AGENT_IDS_HPP
#define _ENDPOINT_GET_V1_AGENT_IDS_HPP

#include "external/cpp-httplib/httplib.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

/**
 * @brief EndpointGetV1AgentsIds class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointGetV1AgentsIds final
{
    struct Response final
    {
        std::vector<int64_t> agentIds;

        REFLECTABLE(MAKE_FIELD("agent_ids", &Response::agentIds))
    };

public:
    /**
     * @brief
     *

     */
    static void call(const DBConnection& db, [[maybe_unused]] const httplib::Request& req, httplib::Response& res)
    {
        Response resObj;
        DBStatement stmt(db, "SELECT id FROM agent WHERE id > 0");

        while (stmt.step() == SQLITE_ROW)
        {
            resObj.agentIds.push_back(stmt.template value<int64_t>(0));
        }

        res.set_content(serializeToJSON(resObj), "application/json");
    }
};

using EndpointGetV1AgentsIds = TEndpointGetV1AgentsIds<>;

#endif /* _ENDPOINT_GET_V1_AGENT_IDS_HPP */
