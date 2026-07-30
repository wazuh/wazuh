/*
 * Wazuh remoted module - Control endpoint types
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_TYPES_HPP
#define _REMOTED_CONTROL_TYPES_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace remoted::control
{
    using AgentId = std::uint32_t;

    enum class SocketError
    {
        None,
        Timeout,
        ClosedByPeer,
        ProtocolError,
        ConnectRefused,
        Io
    };

    struct HostInfo
    {
        std::string hostname;
        std::string architecture;
        std::string ip;
        std::string osName;
        std::string osVersion;
        std::string osPlatform;
        std::string osType;
    };

    struct StartupData
    {
        std::string version;
    };

    struct NotifyData
    {
        std::optional<HostInfo> host;
    };

    struct ShutdownData
    {
    };

    struct Task
    {
        std::string id;
        std::string type;
        nlohmann::json payload;
    };

    enum class AgentStatusCode : int
    {
        InvalidVersion = 1,
        ErrVersionRecv = 2,
        HcShutdownRecv = 3,
        NoKeepalive = 4,
        ResetByManager = 5,
    };

    struct HttpResponse
    {
        int status;
        std::string body;
    };

    using ResponseCallback = std::function<void(const HttpResponse&)>;

    class SocketConnection
    {
    public:
        virtual ~SocketConnection() = default;

        virtual void roundTripFramed(const std::string& payload,
                                      std::function<void(SocketError, const std::string&)> cb) = 0;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_TYPES_HPP
