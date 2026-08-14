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

#include "json.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace remoted::control
{
    using AgentId = std::uint32_t;

    inline constexpr size_t kMaxHostnameLength = 255;
    inline constexpr size_t kMaxIpLength = 45; // IPv6 max
    inline constexpr size_t kMaxOsFieldLength = 128;
    inline constexpr size_t kMaxVersionLength = 64;

    enum class SocketError
    {
        None,
        Timeout,
        ClosedByPeer,
        ProtocolError,
        ConnectRefused,
        Io,
        QueueFull
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
        std::string version;
        std::optional<HostInfo> host;
    };

    struct ShutdownData
    {
    };

    inline bool isValidHostInfo(const HostInfo& h)
    {
        return h.hostname.size() <= kMaxHostnameLength && h.ip.size() <= kMaxIpLength &&
               h.osName.size() <= kMaxOsFieldLength && h.osVersion.size() <= kMaxOsFieldLength &&
               h.architecture.size() <= kMaxOsFieldLength && h.osPlatform.size() <= kMaxOsFieldLength &&
               h.osType.size() <= kMaxOsFieldLength;
    }

    inline bool isValidVersion(const std::string& version)
    {
        if (version.empty() || version.size() > kMaxVersionLength)
        {
            return false;
        }

        static const std::regex versionRegex(R"(^[vV]?\d+(\.\d+){0,3}([+\-][A-Za-z0-9.\-]+)?$)");
        return std::regex_match(version, versionRegex);
    }

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
    };

    struct HttpResponse
    {
        int status;
        std::string body;
    };

    using ResponseCallback = std::function<void(const HttpResponse&)>;

} // namespace remoted::control

#endif // _REMOTED_CONTROL_TYPES_HPP
