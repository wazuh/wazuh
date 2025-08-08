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

#ifndef _ENDPOINT_GET_V1_AGENTS_SYNC_HPP
#define _ENDPOINT_GET_V1_AGENTS_SYNC_HPP

#include "external/cpp-httplib/httplib.h"
#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"

/**
 * @brief TEndpointGetV1AgentsSync class.
 *
 */
template<typename DBConnection = SQLite::Connection, typename DBStatement = SQLite::Statement>
class TEndpointGetV1AgentsSync final
{
    virtual ~TEndpointGetV1AgentsSync() = default; // LCOV_EXCL_LINE
    struct SyncReq final
    {
        /**
         * @brief Label structure to hold key-value pairs for agent labels.
         */
        struct Label final
        {
            std::string key;   ///< The key of the label.
            std::string value; ///< The value of the label.

            REFLECTABLE(MAKE_FIELD("key", &Label::key), MAKE_FIELD("value", &Label::value))
        };

        int64_t id {};
        std::string name;
        std::string ip;
        std::string osName;
        std::string osVersion;
        std::string osMajor;
        std::string osMinor;
        std::string osCodename;
        std::string osBuild;
        std::string osPlatform;
        std::string osUname;
        std::string osArch;
        std::string version;
        std::string configSum;
        std::string mergedSum;
        std::string managerHost;
        std::string nodeName;
        int64_t lastKeepalive = DEFAULT_INT_VALUE;
        std::string connectionStatus;
        int64_t disconnectionTime = DEFAULT_INT_VALUE;
        std::string groupConfigStatus;
        int64_t statusCode = DEFAULT_INT_VALUE;
        std::vector<Label> labels;

        REFLECTABLE(MAKE_FIELD("id", &SyncReq::id),
                    MAKE_FIELD("name", &SyncReq::name),
                    MAKE_FIELD("ip", &SyncReq::ip),
                    MAKE_FIELD("os_name", &SyncReq::osName),
                    MAKE_FIELD("os_version", &SyncReq::osVersion),
                    MAKE_FIELD("os_major", &SyncReq::osMajor),
                    MAKE_FIELD("os_minor", &SyncReq::osMinor),
                    MAKE_FIELD("os_codename", &SyncReq::osCodename),
                    MAKE_FIELD("os_build", &SyncReq::osBuild),
                    MAKE_FIELD("os_platform", &SyncReq::osPlatform),
                    MAKE_FIELD("os_uname", &SyncReq::osUname),
                    MAKE_FIELD("os_arch", &SyncReq::osArch),
                    MAKE_FIELD("version", &SyncReq::version),
                    MAKE_FIELD("config_sum", &SyncReq::configSum),
                    MAKE_FIELD("merged_sum", &SyncReq::mergedSum),
                    MAKE_FIELD("manager_host", &SyncReq::managerHost),
                    MAKE_FIELD("node_name", &SyncReq::nodeName),
                    MAKE_FIELD("last_keepalive", &SyncReq::lastKeepalive),
                    MAKE_FIELD("connection_status", &SyncReq::connectionStatus),
                    MAKE_FIELD("disconnection_time", &SyncReq::disconnectionTime),
                    MAKE_FIELD("group_config_status", &SyncReq::groupConfigStatus),
                    MAKE_FIELD("status_code", &SyncReq::statusCode),
                    MAKE_FIELD("labels", &SyncReq::labels))
    };
    struct Response final
    {
        std::vector<SyncReq> agentsSyncReq;
        std::vector<int64_t> agentsSyncKeepAlive;
        std::vector<SyncReq> agentsSyncStatus;

        REFLECTABLE(MAKE_FIELD("syncreq", &Response::agentsSyncReq),
                    MAKE_FIELD("syncreq_keepalive", &Response::agentsSyncKeepAlive),
                    MAKE_FIELD("syncreq_status", &Response::agentsSyncStatus))
    };

public:
    /**
     * @brief Call the endpoint implementation. This function populates a Response object with the
     * data from the database. This particular implementation returns the agents that have a different status than
     * synced.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, [[maybe_unused]] const httplib::Request& req, httplib::Response& res)
    {
        constexpr size_t RESERVE_SIZE = 32 * 1024 * 1024; // Size to avoid reallocation/fragmentation.

        Response resObj;
        DBStatement stmtCount(db, "SELECT COUNT(*) FROM agent WHERE id > 0 AND sync_status = ?;"); // LCOV_EXCL_LINE

        {
            stmtCount.bind(1, std::string_view("syncreq"));
            while (stmtCount.step() == SQLITE_ROW)
            {
                resObj.agentsSyncReq.reserve(stmtCount.template value<int64_t>(0));
            }

            DBStatement stmtSyncReq( // LCOV_EXCL_LINE
                db,
                "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, "
                "os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, "
                "connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > 0 AND "
                "sync_status = 'syncreq';");

            DBStatement stmtGetLabels(db, "SELECT key, value FROM labels WHERE id = ?;"); // LCOV_EXCL_LINE

            while (stmtSyncReq.step() == SQLITE_ROW)
            {
                const auto idAgent = stmtSyncReq.template value<int64_t>(0);

                resObj.agentsSyncReq.push_back({.id = idAgent,
                                                .name = stmtSyncReq.template value<std::string>(1),
                                                .ip = stmtSyncReq.template value<std::string>(2),
                                                .osName = stmtSyncReq.template value<std::string>(3),
                                                .osVersion = stmtSyncReq.template value<std::string>(4),
                                                .osMajor = stmtSyncReq.template value<std::string>(5),
                                                .osMinor = stmtSyncReq.template value<std::string>(6),
                                                .osCodename = stmtSyncReq.template value<std::string>(7),
                                                .osBuild = stmtSyncReq.template value<std::string>(8),
                                                .osPlatform = stmtSyncReq.template value<std::string>(9),
                                                .osUname = stmtSyncReq.template value<std::string>(10),
                                                .osArch = stmtSyncReq.template value<std::string>(11),
                                                .version = stmtSyncReq.template value<std::string>(12),
                                                .configSum = stmtSyncReq.template value<std::string>(13),
                                                .mergedSum = stmtSyncReq.template value<std::string>(14),
                                                .managerHost = stmtSyncReq.template value<std::string>(15),
                                                .nodeName = stmtSyncReq.template value<std::string>(16),
                                                .lastKeepalive = stmtSyncReq.template value<int64_t>(17),
                                                .connectionStatus = stmtSyncReq.template value<std::string>(18),
                                                .disconnectionTime = stmtSyncReq.template value<int64_t>(19),
                                                .groupConfigStatus = stmtSyncReq.template value<std::string>(20),
                                                .statusCode = stmtSyncReq.template value<int64_t>(21)});

                stmtGetLabels.reset();
                stmtGetLabels.bind(1, idAgent);

                while (stmtGetLabels.step() == SQLITE_ROW)
                {
                    resObj.agentsSyncReq.back().labels.push_back(
                        {.key = stmtGetLabels.template value<std::string>(0),
                         .value = stmtGetLabels.template value<std::string>(1)});
                }
            }
        }

        {
            stmtCount.reset();
            stmtCount.bind(1, std::string_view("syncreq_keepalive"));
            while (stmtCount.step() == SQLITE_ROW)
            {
                resObj.agentsSyncKeepAlive.reserve(stmtCount.template value<int64_t>(0));
            }

            DBStatement stmtSyncKeepAlive( // LCOV_EXCL_LINE
                db,
                "SELECT id FROM agent WHERE id > 0 AND sync_status = 'syncreq_keepalive';");

            while (stmtSyncKeepAlive.step() == SQLITE_ROW)
            {
                const auto idAgent = stmtSyncKeepAlive.template value<int64_t>(0);
                resObj.agentsSyncKeepAlive.push_back(idAgent);
            }
        }

        {
            stmtCount.reset();
            stmtCount.bind(1, std::string_view("syncreq_status"));
            while (stmtCount.step() == SQLITE_ROW)
            {
                resObj.agentsSyncStatus.reserve(stmtCount.template value<int64_t>(0));
            }

            DBStatement stmtSyncStatus(db, // LCOV_EXCL_LINE
                                       "SELECT id, connection_status, disconnection_time, status_code FROM agent "
                                       "WHERE id > 0 AND sync_status = 'syncreq_status';");
            while (stmtSyncStatus.step() == SQLITE_ROW)
            {
                const auto idAgent = stmtSyncStatus.template value<int64_t>(0);
                resObj.agentsSyncStatus.push_back({.id = idAgent,
                                                   .connectionStatus = stmtSyncStatus.template value<std::string>(1),
                                                   .disconnectionTime = stmtSyncStatus.template value<int64_t>(2),
                                                   .statusCode = stmtSyncStatus.template value<int64_t>(3)});
            }
        }

        {
            DBStatement stmtSynced(db, "UPDATE agent SET sync_status = 'synced' WHERE id > 0;"); // LCOV_EXCL_LINE
            stmtSynced.step();
        }

        res.body.reserve(RESERVE_SIZE);
        serializeToJSON(resObj, res.body);
        res.set_header("Content-Type", "application/json");
    }
};

// LCOV_EXCL_START
using EndpointGetV1AgentsSync = TEndpointGetV1AgentsSync<>;
// LCOV_EXCL_STOP

#endif /* _ENDPOINT_GET_V1_AGENTS_SYNC_HPP */
