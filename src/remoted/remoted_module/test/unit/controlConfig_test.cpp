/*
 * Wazuh remoted module - Control config unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/controlConfig.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <string>

using namespace remoted::control;

namespace
{
    // Zero-initialized C-ABI config, like remoted's `= {0}`. All strings become
    // empty ("") and every integer field becomes 0 -- which is exactly what
    // getDefine_Int_default emits when the operator hasn't overridden the key,
    // so this doubles as "fresh-install" fixture.
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t c;
        std::memset(&c, 0, sizeof(c));
        return c;
    }
} // namespace

// -----------------------------------------------------------------------------
// Defaults: every "<=0 -> default" field falls back to the constants exported
// from controlConfig.hpp. If any of those constants change, this test breaks
// on purpose (one place to update).
// -----------------------------------------------------------------------------

TEST(ControlConfigTest, DefaultsWhenZeroed)
{
    const auto cfg = buildControlConfig(zeroedConfig());

    // String fields default to their compiled-in path constants because the
    // Config's own default member initializers survive when buildControlConfig
    // doesn't touch them.
    EXPECT_EQ(cfg.wdbSocketPath, kWdbSocketPath);
    EXPECT_EQ(cfg.taskSocketPath, kTaskSocketPath);
    EXPECT_EQ(cfg.sharedGroupsRoot, kSharedGroupsRoot);
    EXPECT_EQ(cfg.multiGroupsRoot, kMultiGroupsRoot);

    // Numeric defaults come straight from the constants.
    EXPECT_EQ(cfg.wdbRequestConnections, kWdbRequestConnections);
    EXPECT_EQ(cfg.wdbRoundtripDeadlineMs, kWdbRoundtripDeadlineMs);
    EXPECT_EQ(cfg.wdbMaxQueueSize, kWdbMaxQueueSize);
    EXPECT_EQ(cfg.tmConcurrency, kTmConcurrency);
    EXPECT_EQ(cfg.tmDeadlineMs, kTmDeadlineMs);
    EXPECT_EQ(cfg.tmMaxQueueSize, kTaskMaxQueueSize);
    EXPECT_EQ(cfg.groupsRefreshIntervalSec, kGroupsRefreshIntervalSec);
    EXPECT_EQ(cfg.keepaliveThrottleSec, kKeepaliveThrottleSec);
    EXPECT_EQ(cfg.registryEvictionTtlSec, kRegistryEvictionTtlSec);

    // limits_json is empty -> Config.limits is a JSON object (not null / not
    // discarded), so downstream .contains()/.value() calls stay safe.
    EXPECT_TRUE(cfg.limits.is_object());
    EXPECT_TRUE(cfg.limits.empty());
}

TEST(ControlConfigTest, StringFieldsAreCopiedFromCAbi)
{
    auto raw = zeroedConfig();
    std::strncpy(raw.cluster_name, "wazuh-prod", sizeof(raw.cluster_name) - 1);
    std::strncpy(raw.manager_version, "5.0.0-alpha0", sizeof(raw.manager_version) - 1);
    raw.worker_node = true;
    raw.allow_higher_versions = true;

    const auto cfg = buildControlConfig(raw);

    EXPECT_EQ(cfg.clusterName, "wazuh-prod");
    EXPECT_EQ(cfg.managerVersion, "5.0.0-alpha0");
    EXPECT_TRUE(cfg.isWorkerNode);
    EXPECT_TRUE(cfg.allowHigherVersions);
}

// -----------------------------------------------------------------------------
// Positive-value override. Mirrors what remoted's getDefine_Int_default does
// when the operator sets a value in internal_options.
// -----------------------------------------------------------------------------
TEST(ControlConfigTest, PositiveOverridesReplaceDefaults)
{
    auto raw = zeroedConfig();
    raw.groups_refresh_interval_sec = 30;
    raw.wdb_request_connections = 8;
    raw.wdb_roundtrip_deadline_ms = 5000;
    raw.wdb_max_queue_size = 50000;
    raw.tm_concurrency = 20;
    raw.tm_deadline_ms = 500;
    raw.tm_max_queue_size = 20000;

    const auto cfg = buildControlConfig(raw);

    EXPECT_EQ(cfg.groupsRefreshIntervalSec, 30U);
    EXPECT_EQ(cfg.wdbRequestConnections, 8U);
    EXPECT_EQ(cfg.wdbRoundtripDeadlineMs, 5000U);
    EXPECT_EQ(cfg.wdbMaxQueueSize, 50000U);
    EXPECT_EQ(cfg.tmConcurrency, 20U);
    EXPECT_EQ(cfg.tmDeadlineMs, 500U);
    EXPECT_EQ(cfg.tmMaxQueueSize, 20000U);
}

// -----------------------------------------------------------------------------
// Negative-value guard. remoted's getDefine_Int_default has its own min bound,
// but a bad caller / test / future migration could still hand us a negative;
// buildControlConfig must fall back to the compiled default rather than
// casting a negative into a huge uint32_t.
// -----------------------------------------------------------------------------
TEST(ControlConfigTest, NonPositiveValuesFallBackToDefaults)
{
    auto raw = zeroedConfig();
    raw.groups_refresh_interval_sec = -1;
    raw.wdb_request_connections = -1;
    raw.wdb_roundtrip_deadline_ms = -1;
    raw.wdb_max_queue_size = -1;
    raw.tm_concurrency = -1;
    raw.tm_deadline_ms = -1;
    raw.tm_max_queue_size = -1;

    const auto cfg = buildControlConfig(raw);

    EXPECT_EQ(cfg.groupsRefreshIntervalSec, kGroupsRefreshIntervalSec);
    EXPECT_EQ(cfg.wdbRequestConnections, kWdbRequestConnections);
    EXPECT_EQ(cfg.wdbRoundtripDeadlineMs, kWdbRoundtripDeadlineMs);
    EXPECT_EQ(cfg.wdbMaxQueueSize, kWdbMaxQueueSize);
    EXPECT_EQ(cfg.tmConcurrency, kTmConcurrency);
    EXPECT_EQ(cfg.tmDeadlineMs, kTmDeadlineMs);
    EXPECT_EQ(cfg.tmMaxQueueSize, kTaskMaxQueueSize);
}

// -----------------------------------------------------------------------------
// limits_json: happy path -- parsed into cfg.limits verbatim.
// -----------------------------------------------------------------------------
TEST(ControlConfigTest, LimitsJsonParsedWhenValid)
{
    auto raw = zeroedConfig();
    const char* json = R"({"max_agents":100,"disabled":["heavy_scan"]})";
    std::strncpy(raw.limits_json, json, sizeof(raw.limits_json) - 1);

    const auto cfg = buildControlConfig(raw);

    ASSERT_TRUE(cfg.limits.is_object());
    ASSERT_TRUE(cfg.limits.contains("max_agents"));
    EXPECT_EQ(cfg.limits["max_agents"], 100);
    ASSERT_TRUE(cfg.limits.contains("disabled"));
    ASSERT_TRUE(cfg.limits["disabled"].is_array());
    EXPECT_EQ(cfg.limits["disabled"][0], "heavy_scan");
}

// -----------------------------------------------------------------------------
// limits_json: malformed input collapses to an empty JSON object instead of
// null / discarded / exception -- callers can always do `limits.contains(...)`
// safely without a shape check.
// -----------------------------------------------------------------------------
TEST(ControlConfigTest, LimitsJsonFallsBackToEmptyObjectOnMalformed)
{
    auto raw = zeroedConfig();
    const char* garbage = "{not json";
    std::strncpy(raw.limits_json, garbage, sizeof(raw.limits_json) - 1);

    const auto cfg = buildControlConfig(raw);

    EXPECT_TRUE(cfg.limits.is_object());
    EXPECT_TRUE(cfg.limits.empty());
}

// -----------------------------------------------------------------------------
// limits_json: a valid JSON that happens to be a non-object (array, number)
// still lands in cfg.limits verbatim -- buildControlConfig only guards against
// parse failure, not shape. Documenting this so a future "shape guard" change
// breaks this test on purpose.
// -----------------------------------------------------------------------------
TEST(ControlConfigTest, LimitsJsonAcceptsNonObjectShape)
{
    auto raw = zeroedConfig();
    const char* arrayJson = R"([1,2,3])";
    std::strncpy(raw.limits_json, arrayJson, sizeof(raw.limits_json) - 1);

    const auto cfg = buildControlConfig(raw);

    EXPECT_TRUE(cfg.limits.is_array());
    EXPECT_EQ(cfg.limits.size(), 3U);
}
