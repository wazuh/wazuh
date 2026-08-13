/*
 * Wazuh remoted module - WazuhDB client
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_WAZUHDB_CLIENT_HPP
#define _REMOTED_CONTROL_WAZUHDB_CLIENT_HPP

#include "controlTypes.hpp"
#include "metrics.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace remoted::control
{
    class WazuhDBClient
    {
    public:
        WazuhDBClient(const std::string& wdbSocketPath,
                      uint32_t poolSize,
                      uint32_t deadlineMs,
                      uint32_t maxQueueSize,
                      ControlMetrics& metrics);
        ~WazuhDBClient();

        void query(const std::string& command, std::function<void(SocketError, const std::string&)> callback);

        void getAgentGroups(AgentId id, std::function<void(SocketError, std::vector<std::string>)> callback);

        void updateAgentData(AgentId id,
                             const std::string& version,
                             const std::string& connectionStatus,
                             const std::string& syncStatus,
                             const HostInfo* host,
                             std::function<void(SocketError)> callback);

        void updateKeepalive(AgentId id,
                             const std::string& connectionStatus,
                             const std::string& syncStatus,
                             std::function<void(SocketError)> callback);

        void updateStatusCode(AgentId id,
                              AgentStatusCode statusCode,
                              const std::string& version,
                              const std::string& syncStatus,
                              std::function<void(SocketError)> callback);

        void updateConnectionStatus(AgentId id,
                                    AgentStatusCode statusCode,
                                    const std::string& connectionStatus,
                                    const std::string& syncStatus,
                                    std::function<void(SocketError)> callback);

        static bool isOk(const std::string& response);
        static std::string getPayload(const std::string& response);

    private:
        void globalQuery(const std::string& queryName,
                         const nlohmann::json& params,
                         std::function<void(SocketError)> callback);

        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_WAZUHDB_CLIENT_HPP
