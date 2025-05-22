/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_GET_V1_AGENT_LASTID_HPP
#define _ENDPOINT_GET_V1_AGENT_LASTID_HPP

#include "external/cpp-httplib/httplib.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

/**
 * @brief EndpointGetV1AgentsIds class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointGetV1AgentsLastId final
{
    struct Response final
    {
        int64_t id;

        REFLECTABLE(MAKE_FIELD("last_id", &Response::id))
    };

public:
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns the last agent id.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, [[maybe_unused]] const httplib::Request& req, httplib::Response& res)
    {
        Response resObj;
        DBStatement stmt(db, "SELECT id FROM agent WHERE id > 0 ORDER BY id DESC LIMIT 1");

        if (stmt.step() == SQLITE_ROW)
        {
            resObj.id = stmt.template value<int64_t>(0);
            res.set_content(serializeToJSON(resObj), "application/json");
        }
        else
        {
            res.status = 204;
        }
    }
};

using EndpointGetV1AgentsLastId = TEndpointGetV1AgentsLastId<>;

#endif /* _ENDPOINT_GET_V1_AGENT_LASTID_HPP */
