/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * August 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENDPOINT_GET_V1_AGENTS_ALL_HPP
#define _ENDPOINT_GET_V1_AGENTS_ALL_HPP

#include "reflectiveJson.hpp"
#include "sqlite3Wrapper.hpp"
#include <httplib.h>

/**
 * @brief TEndpointGetV1AgentsAll class.
 *
 * Returns all agents with all fields - optimized for bulk operations like metrics snapshot.
 */
template<typename DBConnection = SQLite3Wrapper::Connection, typename DBStatement = SQLite3Wrapper::Statement>
class TEndpointGetV1AgentsAll final
{
    struct AgentData final
    {
        int64_t id;
        std::string name;
        std::string ip;
        std::string status;
        std::string os_name;
        std::string os_version;
        std::string os_type;
        std::string os_platform;
        std::string version;
        std::string date_add;
        std::string os_major;
        std::string os_minor;
        std::string os_arch;
        std::string last_keepalive;
        std::string register_ip;
        std::string disconnection_time;
        int64_t status_code;

        REFLECTABLE(MAKE_FIELD("id", &AgentData::id),
                    MAKE_FIELD("name", &AgentData::name),
                    MAKE_FIELD("ip", &AgentData::ip),
                    MAKE_FIELD("status", &AgentData::status),
                    MAKE_FIELD("os.name", &AgentData::os_name),
                    MAKE_FIELD("os.version", &AgentData::os_version),
                    MAKE_FIELD("os.type", &AgentData::os_type),
                    MAKE_FIELD("os.platform", &AgentData::os_platform),
                    MAKE_FIELD("version", &AgentData::version),
                    MAKE_FIELD("dateAdd", &AgentData::date_add),
                    MAKE_FIELD("os.major", &AgentData::os_major),
                    MAKE_FIELD("os.minor", &AgentData::os_minor),
                    MAKE_FIELD("os.arch", &AgentData::os_arch),
                    MAKE_FIELD("lastKeepAlive", &AgentData::last_keepalive),
                    MAKE_FIELD("registerIP", &AgentData::register_ip),
                    MAKE_FIELD("disconnection_time", &AgentData::disconnection_time),
                    MAKE_FIELD("status_code", &AgentData::status_code))
    };

public:
    virtual ~TEndpointGetV1AgentsAll() = default;

    /**
     * @brief Get all agents with all fields in a single request.
     *
     * This endpoint is optimized for bulk operations that need complete agent data,
     * such as metrics snapshots and indexer synchronization.
     *
     * @param db The database connection.
     * @param req The HTTP request.
     * @param res The HTTP response.
     */
    static void call(const DBConnection& db, const httplib::Request& req, httplib::Response& res)
    {
        constexpr std::string_view query =
            "SELECT id, name, coalesce(ip, register_ip) as ip, connection_status as status, "
            "os_name, os_version, os_type, os_platform, version, date_add, "
            "os_major, os_minor, os_arch, last_keepalive, register_ip, "
            "disconnection_time, status_code "
            "FROM agent WHERE id > 0 ORDER BY id ASC;";

        DBStatement stmt(db, query);
        std::vector<AgentData> agents;
        agents.reserve(1000);

        while (stmt.step() == SQLITE_ROW)
        {
            AgentData agent;
            agent.id = stmt.template value<std::int64_t>(0);
            agent.name = stmt.template value<std::string>(1);
            agent.ip = stmt.template value<std::string>(2);
            agent.status = stmt.template value<std::string>(3);
            agent.os_name = stmt.template value<std::string>(4);
            agent.os_version = stmt.template value<std::string>(5);
            agent.os_type = stmt.template value<std::string>(6);
            agent.os_platform = stmt.template value<std::string>(7);
            agent.version = stmt.template value<std::string>(8);
            agent.date_add = stmt.template value<std::string>(9);
            agent.os_major = stmt.template value<std::string>(10);
            agent.os_minor = stmt.template value<std::string>(11);
            agent.os_arch = stmt.template value<std::string>(12);
            agent.last_keepalive = stmt.template value<std::string>(13);
            agent.register_ip = stmt.template value<std::string>(14);
            agent.disconnection_time = stmt.template value<std::string>(15);
            agent.status_code = stmt.template value<std::int64_t>(16);

            agents.push_back(std::move(agent));
        }

        std::string jsonResponse;
        serializeToJSON<std::vector<AgentData>, true, true>(agents, jsonResponse);
        res.body = std::move(jsonResponse);
        res.set_header("Content-Type", "application/json");
    }
};

using EndpointGetV1AgentsAll = TEndpointGetV1AgentsAll<>;

#endif /* _ENDPOINT_GET_V1_AGENTS_ALL_HPP */
