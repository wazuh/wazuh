/*
 * Wazuh remoted module - Enrollment config unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollment/enrollmentConfig.hpp"

#include <gtest/gtest.h>

#include <cstring>

using namespace remoted::enrollment;

namespace
{
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t c;
        std::memset(&c, 0, sizeof(c));
        return c;
    }
} // namespace

TEST(EnrollmentConfigTest, ZeroedAbiMeansEverythingOffAndTimeoutsAtSentinel)
{
    const auto cfg = buildEnrollmentConfig(zeroedConfig());

    EXPECT_FALSE(cfg.enrollmentEnabled);
    EXPECT_FALSE(cfg.usePassword);
    EXPECT_FALSE(cfg.useSourceIp);
    EXPECT_FALSE(cfg.allowHigherVersions);
    EXPECT_FALSE(cfg.isWorkerNode);
    EXPECT_EQ(cfg.managerVersion, "");

    // 0 in seconds (ABI) round-trips to 0 in ms -- both PasswordKeySource and AuthdClient treat 0
    // as "apply your own built-in default", so no resolution happens here.
    EXPECT_EQ(cfg.passwordRefreshIntervalSec, 0);
    EXPECT_EQ(cfg.authdConnectTimeoutMs, 0u);
    EXPECT_EQ(cfg.authdResponseTimeoutMs, 0u);
    EXPECT_EQ(cfg.authdMaxQueueSize, 0u);
    EXPECT_EQ(cfg.authdWorkerThreads, 0u);
}

TEST(EnrollmentConfigTest, BooleanAndStringFieldsCopiedVerbatim)
{
    auto c = zeroedConfig();
    c.enrollment_enabled = true;
    c.enroll_use_password = true;
    c.enroll_use_source_ip = true;
    c.enroll_allow_higher_versions = true;
    c.worker_node = true;
    std::strncpy(c.manager_version, "5.0.0", sizeof(c.manager_version) - 1);

    const auto cfg = buildEnrollmentConfig(c);

    EXPECT_TRUE(cfg.enrollmentEnabled);
    EXPECT_TRUE(cfg.usePassword);
    EXPECT_TRUE(cfg.useSourceIp);
    EXPECT_TRUE(cfg.allowHigherVersions);
    EXPECT_TRUE(cfg.isWorkerNode);
    EXPECT_EQ(cfg.managerVersion, "5.0.0");
}

TEST(EnrollmentConfigTest, PasswordRefreshIntervalPassedThroughUnconverted)
{
    // Seconds in the ABI, seconds in Config -- PasswordKeySource's own constructor resolves <=0,
    // so buildEnrollmentConfig must not apply any resolution of its own.
    auto c = zeroedConfig();
    c.enroll_password_refresh_interval = 42;

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.passwordRefreshIntervalSec, 42);
}

TEST(EnrollmentConfigTest, AuthdTimeoutsConvertedFromSecondsToMilliseconds)
{
    auto c = zeroedConfig();
    c.authd_connect_timeout = 3;
    c.authd_response_timeout = 7;
    c.authd_max_queue_size = 128;
    c.authd_worker_threads = 6;

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.authdConnectTimeoutMs, 3000u);
    EXPECT_EQ(cfg.authdResponseTimeoutMs, 7000u);
    EXPECT_EQ(cfg.authdMaxQueueSize, 128u);
    EXPECT_EQ(cfg.authdWorkerThreads, 6u); // seconds/ms conversion does NOT apply here -- a plain count
}

TEST(EnrollmentConfigTest, NegativeAuthdKnobsFallBackToZeroSentinel)
{
    auto c = zeroedConfig();
    c.authd_connect_timeout = -1;
    c.authd_response_timeout = -1;
    c.authd_max_queue_size = -1;
    c.authd_worker_threads = -1;

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.authdConnectTimeoutMs, 0u);
    EXPECT_EQ(cfg.authdResponseTimeoutMs, 0u);
    EXPECT_EQ(cfg.authdMaxQueueSize, 0u);
    EXPECT_EQ(cfg.authdWorkerThreads, 0u);
}
