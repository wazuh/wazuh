/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "downstream/downstreamConfig.hpp"
#include "proc.hpp"

#include <gtest/gtest.h>

#include <cstring>

using namespace remoted::downstream;

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

TEST(DownstreamConfigTest, DefaultsWhenEmpty)
{
    const auto config = buildDownstreamConfig(zeroedConfig());

    EXPECT_EQ(config.eventsSocketPath, "queue/sockets/engine-ingest-http.sock");
    // Wire contract with modulesd's inventory sync server, which hardcodes the same literal in its
    // own default (different binary, no shared header). Pinned on both sides so a drift fails a test
    // instead of producing connect failures at runtime.
    EXPECT_EQ(config.inventorySyncSocketPath, "queue/sockets/inventory-sync-http.sock");
    EXPECT_EQ(config.connectTimeoutMs, 2000);
    EXPECT_EQ(config.writeTimeoutMs, 5000);
    EXPECT_EQ(config.responseTimeoutMs, 5000);
    // /stateful's dedicated deadline: longer than the global 5 s (sessions index within the
    // request), while keeping the default budget (2+5+20 s) inside http_request_timeout's 30 s.
    EXPECT_EQ(config.statefulResponseTimeoutMs, 20000);
    // 0 is a setting here ("no header"), so a zeroed struct keeps it; the 20 s default is
    // secure.c's (remoted.downstream_stateful_retry_after), and only a negative falls back to it.
    EXPECT_EQ(config.statefulRetryAfterSec, 0);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.postProcessThreads, static_cast<std::size_t>(cpp_get_nproc()));
    // The same 10 MiB as secure.c's remoted.downstream_max_response_body_size default, so the
    // fallback and the deployed value cannot disagree.
    EXPECT_EQ(config.maxResponseBodySize, 10U * 1024U * 1024U);
}

TEST(DownstreamConfigTest, StructValuesWinAndTimeoutsConvertSecondsToMs)
{
    auto raw = zeroedConfig();
    raw.downstream_connect_timeout = 7;
    raw.downstream_write_timeout = 11;
    raw.downstream_response_timeout = 13;
    raw.downstream_stateful_response_timeout = 45;
    raw.downstream_stateful_retry_after = 35;
    raw.downstream_io_threads = 3;
    raw.downstream_post_process_threads = 6;
    raw.downstream_max_response_body_size = 1048576;

    const auto config = buildDownstreamConfig(raw);

    EXPECT_EQ(config.connectTimeoutMs, 7000);
    EXPECT_EQ(config.writeTimeoutMs, 11000);
    EXPECT_EQ(config.responseTimeoutMs, 13000);
    EXPECT_EQ(config.statefulResponseTimeoutMs, 45000);
    EXPECT_EQ(config.statefulRetryAfterSec, 35);
    EXPECT_EQ(config.ioThreads, 3U);
    EXPECT_EQ(config.postProcessThreads, 6U);
    EXPECT_EQ(config.maxResponseBodySize, 1048576U);
}

// Negative values can't come from remoted (getDefine_Int_default's own min bound keeps them
// out), but buildDownstreamConfig() only trusts "positive", so a leftover/garbage negative must
// fall back to the default like 0 does.
TEST(DownstreamConfigTest, NegativeValuesFallBackToDefaults)
{
    auto raw = zeroedConfig();
    raw.downstream_connect_timeout = -1;
    raw.downstream_io_threads = -5;
    raw.downstream_stateful_retry_after = -1;

    const auto config = buildDownstreamConfig(raw);

    EXPECT_EQ(config.connectTimeoutMs, 2000);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.statefulRetryAfterSec, 20);
}
