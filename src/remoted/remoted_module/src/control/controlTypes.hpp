/*
 * Wazuh remoted module - Control endpoint types
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_TYPES_HPP
#define _REMOTED_CONTROL_TYPES_HPP

#include "json.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <regex>
#include <sstream>
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
        QueueFull,
        Stopping ///< The client is draining/shutting down. Distinct from Io so a caller can
                 ///< recognise a clean-shutdown drain instead of a genuine transport failure.
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

    /**
     * @brief Parses MAJOR.MINOR.PATCH[.EXTRA] into four integers.
     *
     * A leading 'v'/'V' is stripped and everything after '-'/'+' (stage or build suffix) is
     * discarded; each unparsed or missing part is 0.
     */
    inline std::array<int, 4> parseVersionParts(const std::string& v)
    {
        std::array<int, 4> parts {0, 0, 0, 0};
        // Strip leading 'v' or 'V' if present
        std::string version = v;
        if (!version.empty() && (version[0] == 'v' || version[0] == 'V'))
        {
            version = version.substr(1);
        }

        size_t pos = version.find_first_of("+-");
        std::string numericPart = (pos != std::string::npos) ? version.substr(0, pos) : version;

        std::istringstream iss(numericPart);
        std::string token;
        int i = 0;
        while (std::getline(iss, token, '.') && i < static_cast<int>(parts.size()))
        {
            try
            {
                parts[i++] = std::stoi(token);
            }
            catch (...)
            {
                break;
            }
        }
        return parts;
    }

    /**
     * @brief Generic numeric comparison of MAJOR.MINOR.PATCH[.EXTRA] version strings.
     *
     * Compares all four numeric parts; the suffix after '-'/'+' is ignored. This is an ordering,
     * not the allow_higher_versions policy -- use isAgentVersionTooNew() for that.
     *
     * @return -1 if v1 < v2, 1 if v1 > v2, 0 if equal (each unparsed/missing part treated as 0).
     */
    inline int compareVersions(const std::string& v1, const std::string& v2)
    {
        const auto p1 = parseVersionParts(v1);
        const auto p2 = parseVersionParts(v2);

        for (size_t i = 0; i < p1.size(); ++i)
        {
            if (p1[i] < p2[i])
                return -1;
            if (p1[i] > p2[i])
                return 1;
        }
        return 0;
    }

    /**
     * @brief The allow_higher_versions policy: is the agent newer than the manager?
     *
     * "Newer" means a higher MAJOR or MINOR only -- an agent one patch release ahead is not too
     * new. This is the rule of the legacy paths (port 1515 enrollment and the 1514 HC_STARTUP),
     * which call compare_wazuh_versions(manager, agent, false) with compare_patch=false. Shared by
     * /control and /enroll so one manager applies one rule whatever port the agent arrives on.
     */
    inline bool isAgentVersionTooNew(const std::string& managerVersion, const std::string& agentVersion)
    {
        const auto manager = parseVersionParts(managerVersion);
        const auto agent = parseVersionParts(agentVersion);

        if (agent[0] != manager[0])
        {
            return agent[0] > manager[0];
        }
        return agent[1] > manager[1];
    }

    struct Task
    {
        std::string id;
        std::string type;
        nlohmann::json payload;
    };

    enum class AgentStatusCode : int
    {
        Ok = 0,
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
