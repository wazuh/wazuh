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

#include "controlConfig.hpp"
#include <cstring>

namespace remoted::control
{
    Config buildControlConfig(const remoted_module_config_t& c)
    {
        Config cfg;

        cfg.clusterName = c.cluster_name;
        cfg.isWorkerNode = c.worker_node;
        cfg.managerVersion = c.manager_version;
        cfg.allowHigherVersions = c.allow_higher_versions;

        if (c.groups_refresh_interval_sec > 0)
        {
            cfg.groupsRefreshIntervalSec = c.groups_refresh_interval_sec;
        }

        if (c.wdb_request_connections > 0)
        {
            cfg.wdbRequestConnections = c.wdb_request_connections;
        }

        if (c.wdb_roundtrip_deadline_ms > 0)
        {
            cfg.wdbRoundtripDeadlineMs = c.wdb_roundtrip_deadline_ms;
        }

        if (c.wdb_max_queue_size > 0)
        {
            cfg.wdbMaxQueueSize = static_cast<uint32_t>(c.wdb_max_queue_size);
        }

        if (c.tm_concurrency > 0)
        {
            cfg.tmConcurrency = c.tm_concurrency;
        }

        if (c.tm_deadline_ms > 0)
        {
            cfg.tmDeadlineMs = static_cast<uint32_t>(c.tm_deadline_ms);
        }

        if (c.tm_max_queue_size > 0)
        {
            cfg.tmMaxQueueSize = static_cast<uint32_t>(c.tm_max_queue_size);
        }

        if (std::strlen(c.limits_json) > 0)
        {
            try
            {
                cfg.limits = nlohmann::json::parse(c.limits_json);
                if (cfg.limits.is_discarded())
                {
                    cfg.limits = nlohmann::json::object();
                }
            }
            catch (...)
            {
                cfg.limits = nlohmann::json::object();
            }
        }
        else
        {
            cfg.limits = nlohmann::json::object();
        }

        return cfg;
    }

} // namespace remoted::control
