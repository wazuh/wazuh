/*
 * Wazuh remoted module - Control endpoint configuration
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_CONFIG_HPP
#define _REMOTED_CONTROL_CONFIG_HPP

#include "json.hpp"
#include "remoted_module.h"
#include <cstdint>
#include <string>

namespace remoted::control
{
    inline constexpr uint32_t kRegistryEvictionTtlSec = 21'600; // 6 hours
    inline constexpr uint32_t kRegistryEvictionIntervalSec = 300;
    inline constexpr uint32_t kKeepaliveThrottleSec = 60;
    inline constexpr uint32_t kWdbRequestConnections = 4;
    inline constexpr uint32_t kWdbRoundtripDeadlineMs = 2000;
    inline constexpr uint32_t kWdbMaxQueueSize = 10'000;
    inline constexpr uint32_t kGroupsRefreshIntervalSec = 60;
    inline constexpr uint32_t kTmConcurrency = 4;
    inline constexpr uint32_t kTaskMaxQueueSize = 10'000;
    inline constexpr uint32_t kTmDeadlineMs = 2000;
    inline constexpr size_t kFileHashBufferSize = 8192;
    inline constexpr size_t kInotifyBufferSize = 4096;

    inline constexpr const char* kTaskSocketPath = "/queue/tasks/task";
    inline constexpr const char* kWdbSocketPath = "/queue/db/wdb";
    inline constexpr const char* kSharedGroupsRoot = "/etc/shared";
    inline constexpr const char* kMultiGroupsRoot = "/var/multigroups";

    struct Config
    {
        std::string clusterName;
        bool isWorkerNode;
        std::string managerVersion;
        bool allowHigherVersions;

        nlohmann::json limits;

        std::string wdbSocketPath = kWdbSocketPath;
        std::string taskSocketPath = kTaskSocketPath;
        std::string sharedGroupsRoot = kSharedGroupsRoot;
        std::string multiGroupsRoot = kMultiGroupsRoot;

        uint32_t wdbRequestConnections = kWdbRequestConnections;
        uint32_t wdbRoundtripDeadlineMs = kWdbRoundtripDeadlineMs;
        uint32_t wdbMaxQueueSize = kWdbMaxQueueSize;
        uint32_t groupsRefreshIntervalSec = kGroupsRefreshIntervalSec;
        uint32_t tmConcurrency = kTmConcurrency;
        uint32_t tmDeadlineMs = kTmDeadlineMs;
        uint32_t tmMaxQueueSize = kTaskMaxQueueSize;
        uint32_t keepaliveThrottleSec = kKeepaliveThrottleSec;
        uint32_t registryEvictionTtlSec = kRegistryEvictionTtlSec;
    };

    Config buildControlConfig(const remoted_module_config_t& c);

} // namespace remoted::control

#endif // _REMOTED_CONTROL_CONFIG_HPP
