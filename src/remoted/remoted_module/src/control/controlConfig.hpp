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

#include "remoted_module.h"
#include <cstdint>
#include <string>
#include "json.hpp"

namespace remoted::control
{
    inline constexpr uint32_t kRegistryEvictionTtlSec = 86'400;
    inline constexpr uint32_t kRegistryEvictionIntervalSec = 300;
    inline constexpr uint32_t kLogWindowSec = 60;
    inline constexpr uint32_t kLogInfoThreshold = 5;
    inline constexpr uint32_t kLogWarnThreshold = 100;

    inline constexpr const char* kTaskSocketPath = "/queue/tasks/task";
    inline constexpr const char* kWdbSocketPath = "/queue/db/wdb";
    inline constexpr const char* kSharedGroupsRoot = "/etc/shared";
    inline constexpr const char* kMultiGroupsRoot = "/var/multigroups";

    struct Config
    {
        std::string nodeName;
        std::string clusterName;
        bool isWorkerNode;
        std::string managerVersion;
        bool allowHigherVersions;

        nlohmann::json limits;

        std::string wdbSocketPath = kWdbSocketPath;
        std::string taskSocketPath = kTaskSocketPath;
        std::string sharedGroupsRoot = kSharedGroupsRoot;
        std::string multiGroupsRoot = kMultiGroupsRoot;

        uint32_t wdbRequestConnections = 4;
        uint32_t wdbRoundtripDeadlineMs = 2000;
        uint32_t groupsRefreshIntervalSec = 60;
        uint32_t tmConcurrency = 10;
        uint32_t keepaliveBatchCap = 1000;
    };

    Config buildControlConfig(const remoted_module_config_t& c);

} // namespace remoted::control

#endif // _REMOTED_CONTROL_CONFIG_HPP
