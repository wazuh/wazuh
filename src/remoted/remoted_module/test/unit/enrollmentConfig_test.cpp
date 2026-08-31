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

#include <stdexcept>

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

    // Same time policy authTypes.cpp resolves for the agent<->manager scheme's AuthConfig --
    // /enroll's freshness-window check must not silently diverge from it (profile maxima when unset).
    EXPECT_EQ(cfg.timePolicy.maxAgeSec(), 60);
    EXPECT_EQ(cfg.timePolicy.skewSec(), 30);
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

TEST(EnrollmentConfigTest, ConfiguredTimePolicyIsPassedThrough)
{
    // Regression guard: buildEnrollmentConfig() once dropped the window knobs entirely -- remoted's
    // internal options had no effect on /enroll at all, silently contradicting send_enroll.py and
    // https-events-api.md, which document them as applying here too. Same ABI fields, same
    // resolution as AuthConfig -- zero skew included as a valid, configured value.
    auto c = zeroedConfig();
    c.jwt_max_age = 45;
    c.jwt_clock_skew = 20;
    c.jwt_clock_skew_set = 1;

    auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.timePolicy.maxAgeSec(), 45);
    EXPECT_EQ(cfg.timePolicy.skewSec(), 20);

    c.jwt_clock_skew = 0;
    cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.timePolicy.skewSec(), 0);
}

TEST(EnrollmentConfigTest, UnsetTimePolicyValuesFallBackToTheProfileMaxima)
{
    auto c = zeroedConfig();
    c.jwt_max_age = -1;
    c.jwt_clock_skew = 0; // without jwt_clock_skew_set this is "unset", not "zero tolerance"

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.timePolicy.maxAgeSec(), 60);
    EXPECT_EQ(cfg.timePolicy.skewSec(), 30);
}

TEST(EnrollmentConfigTest, TimePolicyAboveTheProfileMaximaThrows)
{
    auto c = zeroedConfig();
    c.jwt_max_age = 43201;
    EXPECT_THROW(buildEnrollmentConfig(c), std::invalid_argument);
}

TEST(EnrollmentConfigTest, ConfiguredMaxBodySizeIsPassedThrough)
{
    // Regression guard: EnrollmentAuthConfig used to have no body-size cap counterpart to
    // AuthConfig's at all, so /enroll never honored auth_max_body_size.
    auto c = zeroedConfig();
    c.auth_max_body_size = 1024 * 1024;

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.maxBodySize, 1024u * 1024u);
}

TEST(EnrollmentConfigTest, NonPositiveMaxBodySizeFallsBackToTenMebibytes)
{
    auto c = zeroedConfig();
    c.auth_max_body_size = 0;

    const auto cfg = buildEnrollmentConfig(c);
    EXPECT_EQ(cfg.maxBodySize, 10u * 1024u * 1024u);
}
