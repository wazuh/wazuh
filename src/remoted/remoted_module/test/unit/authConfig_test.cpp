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

#include <stdexcept>

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
    EXPECT_EQ(config.maxBodySize, 10U * 1024U * 1024U);
    // A zeroed C-ABI struct means "unset": the bearer profile's maxima apply -- for the skew too,
    // because "configured" is a separate flag (jwt_clock_skew_set), not the value itself.
    EXPECT_EQ(config.timePolicy.maxAgeSec(), 60);
    EXPECT_EQ(config.timePolicy.skewSec(), 30);
}

TEST(AuthConfigTest, StructValuesWin)
{
    auto raw = zeroedConfig();
    raw.jwt_max_age = 45;
    raw.jwt_clock_skew = 20;
    raw.jwt_clock_skew_set = 1;
    raw.auth_max_body_size = 1048576;

    const auto config = buildAuthConfig(raw);

    EXPECT_EQ(config.supportedProtocolVersion, "1");
    EXPECT_EQ(config.timePolicy.maxAgeSec(), 45);
    EXPECT_EQ(config.timePolicy.skewSec(), 20);
    EXPECT_EQ(config.maxBodySize, 1048576U);
}

// The whole range remoted's getDefine_Int_default() admits (jwt_max_age 1..43200, jwt_clock_skew
// 0..43200) is accepted verbatim -- including a ZERO skew, which is a valid setting ("no tolerance"),
// not "unset": the jwt_clock_skew_set flag is what distinguishes the two.
TEST(AuthConfigTest, RangeEdgesAreAcceptedVerbatimIncludingZeroSkew)
{
    auto raw = zeroedConfig();
    raw.jwt_max_age = 1;
    raw.jwt_clock_skew = 43200;
    raw.jwt_clock_skew_set = 1;
    EXPECT_EQ(buildAuthConfig(raw).timePolicy.maxAgeSec(), 1);
    EXPECT_EQ(buildAuthConfig(raw).timePolicy.skewSec(), 43200);

    raw.jwt_max_age = 43200;
    raw.jwt_clock_skew = 0;
    EXPECT_EQ(buildAuthConfig(raw).timePolicy.maxAgeSec(), 43200);
    EXPECT_EQ(buildAuthConfig(raw).timePolicy.skewSec(), 0);
    EXPECT_EQ(buildTimePolicy(43200, 0, true).skewSec(), 0);

    // Without the flag the skew value is ignored: a zeroed struct is "unset", not "zero tolerance".
    raw.jwt_clock_skew_set = 0;
    EXPECT_EQ(buildAuthConfig(raw).timePolicy.skewSec(), 30);
    EXPECT_EQ(buildTimePolicy(10, 0, false).skewSec(), 30);
    EXPECT_EQ(buildTimePolicy(10, 7, false).skewSec(), 30);
}

// Negative values can't come from remoted (getDefine_Int_default's own min bound keeps them
// out), but buildAuthConfig() only trusts "positive" for jwt_max_age, so a leftover/garbage negative
// must fall back to the default like 0 does. A configured negative skew is a contract violation.
TEST(AuthConfigTest, NegativeValuesFallBackToDefaultsOrAreRejected)
{
    auto raw = zeroedConfig();
    raw.jwt_max_age = -1;
    raw.auth_max_body_size = -1;

    const auto config = buildAuthConfig(raw);

    EXPECT_EQ(config.timePolicy.maxAgeSec(), 60);
    EXPECT_EQ(config.timePolicy.skewSec(), 30);
    EXPECT_EQ(config.maxBodySize, 10U * 1024U * 1024U);

    raw.jwt_clock_skew = -1;
    raw.jwt_clock_skew_set = 1;
    EXPECT_THROW(buildAuthConfig(raw), std::invalid_argument);
}

// Above the profile maxima is a configuration error, never a wider window: remoted's own range
// check stops it first, and this is the second barrier should a caller bypass secure.c.
TEST(AuthConfigTest, ValuesAboveTheProfileMaximaThrow)
{
    auto raw = zeroedConfig();
    raw.jwt_max_age = 43201;
    EXPECT_THROW(buildAuthConfig(raw), std::invalid_argument);

    raw.jwt_max_age = 43200;
    raw.jwt_clock_skew = 43201;
    raw.jwt_clock_skew_set = 1;
    EXPECT_THROW(buildAuthConfig(raw), std::invalid_argument);
    EXPECT_THROW(buildTimePolicy(43201, 43200, true), std::invalid_argument);
    EXPECT_THROW(buildTimePolicy(43200, 43201, true), std::invalid_argument);
}
