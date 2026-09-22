/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * September 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_GET_V1_STATUS_HPP
#define _ENDPOINT_GET_V1_STATUS_HPP

#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"
#include <loggerHelper.h>
#include <string>
#include <uds_http_server/IUdsHttpServer.hpp>

/**
 * @brief TEndpointGetV1Status class.
 *
 * Reports whether this daemon can actually serve queries, so that a caller can know it BEFORE
 * issuing one.
 *
 * The case this exists for: `remoted`'s `POST /control` answers `500 database_error` when it
 * cannot read an agent's groups from here, and until now that failure was only ever observable
 * one request at a time, after an agent had already been served badly. A node in that state kept
 * answering its own liveness probe with `200` and stayed in a load balancer's rotation
 * indefinitely (issue #39429).
 *
 * Liveness is not enough to detect it, and that is the distinction this route draws. The process
 * being up says nothing about the database being usable: `wazuh-manager-db` can be running,
 * accepting connections on this socket, and still be unable to open or query `global.db`. This
 * route answers the second question.
 *
 * It is deliberately cheap and read-only. It reads `sqlite_master`, which is small and always
 * resident, rather than counting rows in `agent` or running an integrity check: a status route
 * that is expensive stops being safe to poll, and a load balancer polls.
 */
template<typename DBConnection = SQLite3Wrapper::Connection, typename DBStatement = SQLite3Wrapper::Statement>
class TEndpointGetV1Status final
{
    static constexpr auto LOGTAG = "wazuh-db-http";

    struct GlobalDatabase final
    {
        bool available {false};
        /// The tables this daemon must be able to reach for remoted's /control to answer. Empty
        /// when the query itself failed, which `available` already reports.
        std::vector<std::string> missingTables;

        REFLECTABLE(MAKE_FIELD("available", &GlobalDatabase::available),
                    MAKE_FIELD("missing_tables", &GlobalDatabase::missingTables))
    };

    struct Response final
    {
        std::string status;
        std::string module;
        GlobalDatabase global;

        REFLECTABLE(MAKE_FIELD("status", &Response::status),
                    MAKE_FIELD("module", &Response::module),
                    MAKE_FIELD("global", &Response::global))
    };

public:
    virtual ~TEndpointGetV1Status() = default; // LCOV_EXCL_LINE

    /**
     * @brief Report whether the global database can serve the queries this daemon exists to serve.
     *
     * @param db The database connection.
     * @param req The HTTP request (unused: this route takes no input).
     * @return `200` when the database answers and carries the expected schema, `503` otherwise.
     */
    static wazuh::uds_http::HttpResponse call(const DBConnection& db, const wazuh::uds_http::HttpRequest& req)
    {
        (void)req;

        Response resObj;
        resObj.module = "wazuh-db";

        // `agent`, `belongs` and `group` are what an agent-groups lookup joins over -- the query
        // whose failure surfaces as remoted's `500 database_error`. Asking sqlite_master for them
        // proves the connection works AND that the schema behind that lookup is present, without
        // reading a single agent row.
        static const std::vector<std::string> REQUIRED_TABLES {"agent", "belongs", "group"};

        for (const auto& table : REQUIRED_TABLES)
        {
            DBStatement stmt(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1");
            stmt.bind(1, table);

            if (stmt.step() != SQLITE_ROW)
            {
                resObj.global.missingTables.push_back(table);
            }
        }

        resObj.global.available = resObj.global.missingTables.empty();

        if (!resObj.global.available)
        {
            // Not an error of the caller's making, and not an internal fault either: the daemon is
            // answering correctly that it cannot serve. 503 is what tells a caller to route
            // elsewhere, which is the whole point of asking.
            logWarn(LOGTAG, "Status: the global database is missing expected tables");
            resObj.status = "unavailable";
            return wazuh::uds_http::HttpResponse::json(503, serializeToJSON(resObj));
        }

        resObj.status = "ok";
        return wazuh::uds_http::HttpResponse::json(200, serializeToJSON(resObj));
    }
};

// LCOV_EXCL_START
using EndpointGetV1Status = TEndpointGetV1Status<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_GET_V1_STATUS_HPP */
