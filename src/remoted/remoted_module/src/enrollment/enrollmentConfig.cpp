/*
 * Wazuh remoted module - Enrollment endpoint configuration
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollmentConfig.hpp"

namespace remoted::enrollment
{
    Config buildEnrollmentConfig(const remoted_module_config_t& c)
    {
        Config cfg;

        cfg.enrollmentEnabled = c.enrollment_enabled;
        cfg.usePassword = c.enroll_use_password;
        cfg.useSourceIp = c.enroll_use_source_ip;
        cfg.allowHigherVersions = c.enroll_allow_higher_versions;
        cfg.managerVersion = c.manager_version;
        cfg.isWorkerNode = c.worker_node;

        cfg.passwordRefreshIntervalSec = c.enroll_password_refresh_interval;

        cfg.authdConnectTimeoutMs =
            c.authd_connect_timeout > 0 ? static_cast<std::uint32_t>(c.authd_connect_timeout) * 1000U : 0U;
        cfg.authdResponseTimeoutMs =
            c.authd_response_timeout > 0 ? static_cast<std::uint32_t>(c.authd_response_timeout) * 1000U : 0U;
        cfg.authdMaxQueueSize = c.authd_max_queue_size > 0 ? static_cast<std::uint32_t>(c.authd_max_queue_size) : 0U;
        cfg.authdWorkerThreads = c.authd_worker_threads > 0 ? static_cast<std::uint32_t>(c.authd_worker_threads) : 0U;

        return cfg;
    }

} // namespace remoted::enrollment
