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

#ifndef _WDB_GATEWAY_HPP
#define _WDB_GATEWAY_HPP

#include "endpointGetV1AgentsIds.hpp"
#include "endpointGetV1AgentsIdsGroups.hpp"
#include "endpointGetV1AgentsIdsGroupsParam.hpp"
#include "endpointGetV1AgentsParamGroups.hpp"
#include "endpointGetV1AgentsSync.hpp"
#include "endpointPostV1AgentsSummary.hpp"
#include "endpointPostV1AgentsSync.hpp"
#include "external/cpp-httplib/httplib.h"
#include "external/sqlite/sqlite3.h"
#include "sqlite3Wrapper.hpp"
#include <defer.hpp>
#include <string_view>

/**
 * @brief RouterModule class.
 *
 */
class WDB final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief
     *

     */
    static void redirect(void* callbackPre,
                         void* callbackPost,
                         std::string_view endpoint,
                         std::string_view method,
                         const httplib::Request& req,
                         httplib::Response& res)
    {
        if (!callbackPre || !callbackPost)
        {
            throw std::runtime_error("CallbackPre and post are required");
        }
        auto cbPre = reinterpret_cast<sqlite3* (*)(void**)>(callbackPre);
        auto cbPost = reinterpret_cast<void (*)(void*)>(callbackPost);
        void* data = nullptr;
        auto db = cbPre(&data);

        DEFER([cbPost, data]() { cbPost(data); });

        if (!db)
        {
            throw std::runtime_error("Database connection failed");
        }

        SQLite::Connection connection(db);

        if (method.compare("GET") == 0)
        {
            // Handle GET request
            if (endpoint.compare("/v1/agents/ids") == 0)
            {
                EndpointGetV1AgentsIds::call(connection, req, res);
            }
            else if (endpoint.compare("/v1/agents/ids/groups/:name") == 0)
            {
                EndpointGetV1AgentsIdsGroupsParam::call(connection, req, res);
            }
            else if (endpoint.compare("/v1/agents/ids/groups") == 0)
            {
                EndpointGetV1AgentsIdsGroups::call(connection, req, res);
            }
            else if (endpoint.compare("/v1/agents/:agent_id/groups") == 0)
            {
                EndpointGetV1AgentsParamGroups::call(connection, req, res);
            }
            else if (endpoint.compare("/v1/agents/sync") == 0)
            {
                EndpointGetV1AgentsSync::call(connection, req, res);
            }
            else
            {
                throw std::invalid_argument("Endpoint not implemented");
            }
        }
        else if (method.compare("POST") == 0)
        {
            if (endpoint.compare("/v1/agents/summary") == 0)
            {
                EndpointPostV1AgentsSummary::call(connection, req, res);
            }
            else if (endpoint.compare("/v1/agents/sync") == 0)
            {
                EndpointPostV1AgentsSync::call(connection, req, res);
            }
            else
            {
                throw std::invalid_argument("Endpoint not implemented");
            }
        }
        else
        {
            throw std::invalid_argument("Method not implemented");
        }
    }
};

#endif /* _WDB_GATEWAY_HPP */
