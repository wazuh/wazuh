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

#include "controlConfig.hpp"
#include "controlTypes.hpp"
#include "metrics.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace remoted::control
{
    /**
     * @brief Pooled, queued client to the local wazuh-db socket.
     *
     * Every request completes exactly once, and never later than `requestDeadlineMs` after it was
     * queued: whatever is still queued at that point -- because every connection is down, or
     * because the pool is busy -- is failed with SocketError::Timeout and is never sent afterwards.
     * `deadlineMs` bounds only the round trip once a request has been sent.
     */
    class WazuhDBClient
    {
    public:
        WazuhDBClient(const std::string& wdbSocketPath,
                      uint32_t poolSize,
                      uint32_t deadlineMs,
                      uint32_t maxQueueSize,
                      ControlMetrics& metrics,
                      uint32_t requestDeadlineMs = kWdbRequestDeadlineMs);
        ~WazuhDBClient();

        void query(const std::string& command, std::function<void(SocketError, const std::string&)> callback);

        /// `global select-agent-group <id>`. A reply that is not the documented array shape is a
        /// SocketError::ProtocolError, never an empty membership.
        void getAgentGroups(AgentId id, std::function<void(SocketError, AgentGroupsResult)> callback);

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

        /// When connectionStatus is non-empty, the same write also updates the connection
        /// status, stamps the last keepalive and resets the disconnection time.
        void updateStatusCode(AgentId id,
                              AgentStatusCode statusCode,
                              const std::string& version,
                              const std::string& connectionStatus,
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
