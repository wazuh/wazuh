/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth/authTypes.hpp"

#include <gtest/gtest.h>

#include <cstring>

using namespace remoted::auth;

namespace
{
    // Zero-initialized C-ABI config, like remoted's `= {0}`.
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t config;
        std::memset(&config, 0, sizeof(config));
        return config;
    }
} // namespace

TEST(AuthConfigTest, DefaultsWhenEmpty)
{
    const auto config = buildAuthConfig(zeroedConfig());

    EXPECT_EQ(config.supportedProtocolVersion, "1");
    EXPECT_EQ(config.maxRequestAgeSeconds, 300);
    EXPECT_EQ(config.maxFutureSkewSeconds, 30);
    EXPECT_EQ(config.maxBodySize, 10U * 1024U * 1024U);
}

TEST(AuthConfigTest, StructValuesWin)
{
    auto raw = zeroedConfig();
    raw.auth_max_request_age = 600;
    raw.auth_max_future_skew = 60;
    raw.auth_max_body_size = 1048576;

    const auto config = buildAuthConfig(raw);

    EXPECT_EQ(config.supportedProtocolVersion, "1");
    EXPECT_EQ(config.maxRequestAgeSeconds, 600);
    EXPECT_EQ(config.maxFutureSkewSeconds, 60);
    EXPECT_EQ(config.maxBodySize, 1048576U);
}

// Negative values can't come from remoted (getDefine_Int_default's own min bound keeps them
// out), but buildAuthConfig() only trusts "positive", so a leftover/garbage negative must fall
// back to the default like 0 does.
TEST(AuthConfigTest, NegativeValuesFallBackToDefaults)
{
    auto raw = zeroedConfig();
    raw.auth_max_request_age = -1;
    raw.auth_max_body_size = -1;

    const auto config = buildAuthConfig(raw);

    EXPECT_EQ(config.maxRequestAgeSeconds, 300);
    EXPECT_EQ(config.maxBodySize, 10U * 1024U * 1024U);
}

