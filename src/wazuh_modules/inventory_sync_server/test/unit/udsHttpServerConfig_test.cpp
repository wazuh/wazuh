/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/udsHttpServerConfig.hpp"

#include "proc.hpp"

#include <gtest/gtest.h>

#include <cstdio>

using invsync::http::buildServerConfig;

namespace
{
    /// A zeroed struct is exactly what modulesd passes when every internal option is at its 0
    /// fallback, so this is the production default path, not a synthetic one.
    inventory_sync_server_config_t zeroedConfig()
    {
        return inventory_sync_server_config_t {};
    }
} // namespace

TEST(UdsHttpServerConfigTest, ZeroedStructYieldsEveryDocumentedDefault)
{
    const auto config = buildServerConfig(zeroedConfig());

    EXPECT_EQ("queue/sockets/inventory-sync.sock", config.socketPath);
    EXPECT_EQ(0660U, config.socketMode);
    EXPECT_TRUE(config.socketGroup.empty());

    EXPECT_EQ(static_cast<std::size_t>(cpp_get_nproc()), config.ioThreads);
    EXPECT_EQ(2U, config.concurrentAccepts);
    EXPECT_EQ(8192U, config.bufferSize);

    EXPECT_EQ(16U * 1024U * 1024U, config.maxBodySize);
    EXPECT_EQ(2048U, config.maxUrlSize);
    EXPECT_EQ(256U, config.maxHeaderNameSize);
    EXPECT_EQ(8192U, config.maxHeaderValueSize);
    EXPECT_EQ(64U, config.maxHeaderCount);

    EXPECT_EQ(10U, config.headerTimeoutSec);
    EXPECT_EQ(30U, config.bodyTimeoutSec);
    EXPECT_EQ(300U, config.responseTimeoutSec);
    EXPECT_EQ(10U, config.writeTimeoutSec);
    EXPECT_EQ(2U, config.drainTimeoutSec);

    EXPECT_EQ(1024U, config.maxConnections);
    EXPECT_EQ(256U * 1024U * 1024U, config.maxInFlightBytes);
}

// The socket path being relative is the whole basis of the chroot/chdir agreement with the peer:
// modulesd chdir()s to the install dir, remoted chroot()s into it. An absolute default here would
// silently break one of them.
TEST(UdsHttpServerConfigTest, DefaultSocketPathIsRelative)
{
    const auto config = buildServerConfig(zeroedConfig());
    ASSERT_FALSE(config.socketPath.empty());
    EXPECT_NE('/', config.socketPath.front()) << "the path must be relative for chroot and chdir to agree";
}

TEST(UdsHttpServerConfigTest, PositiveValuesOverrideEveryDefault)
{
    auto input = zeroedConfig();
    std::snprintf(input.socket_path, sizeof(input.socket_path), "%s", "queue/sockets/custom.sock");
    input.socket_mode = 0600;
    input.io_threads = 7;
    input.concurrent_accepts = 9;
    input.buffer_size = 4096;
    input.max_body_size = 1024;
    input.max_url_size = 512;
    input.max_header_name_size = 32;
    input.max_header_value_size = 64;
    input.max_header_count = 11;
    input.header_timeout = 3;
    input.body_timeout = 4;
    input.response_timeout = 5;
    input.write_timeout = 6;
    input.drain_timeout = 8;
    input.max_parallel_connections = 77;
    input.max_inflight_bytes = 12345;

    const auto config = buildServerConfig(input);

    EXPECT_EQ("queue/sockets/custom.sock", config.socketPath);
    EXPECT_EQ(0600U, config.socketMode);
    EXPECT_EQ(7U, config.ioThreads);
    EXPECT_EQ(9U, config.concurrentAccepts);
    EXPECT_EQ(4096U, config.bufferSize);
    EXPECT_EQ(1024U, config.maxBodySize);
    EXPECT_EQ(512U, config.maxUrlSize);
    EXPECT_EQ(32U, config.maxHeaderNameSize);
    EXPECT_EQ(64U, config.maxHeaderValueSize);
    EXPECT_EQ(11U, config.maxHeaderCount);
    EXPECT_EQ(3U, config.headerTimeoutSec);
    EXPECT_EQ(4U, config.bodyTimeoutSec);
    EXPECT_EQ(5U, config.responseTimeoutSec);
    EXPECT_EQ(6U, config.writeTimeoutSec);
    EXPECT_EQ(8U, config.drainTimeoutSec);
    EXPECT_EQ(77U, config.maxConnections);
    EXPECT_EQ(12345U, config.maxInFlightBytes);
}

// Negative is treated exactly like zero: "the caller has no opinion". Anything else would let a
// mis-set internal option produce a nonsensical size_t.
TEST(UdsHttpServerConfigTest, NegativeValuesFallBackToDefaults)
{
    auto input = zeroedConfig();
    input.io_threads = -1;
    input.max_body_size = -4096;
    input.header_timeout = -10;
    input.max_parallel_connections = -5;
    input.max_inflight_bytes = -1;
    input.socket_mode = -1;

    const auto config = buildServerConfig(input);

    EXPECT_EQ(static_cast<std::size_t>(cpp_get_nproc()), config.ioThreads);
    EXPECT_EQ(16U * 1024U * 1024U, config.maxBodySize);
    EXPECT_EQ(10U, config.headerTimeoutSec);
    EXPECT_EQ(1024U, config.maxConnections);
    EXPECT_EQ(256U * 1024U * 1024U, config.maxInFlightBytes);
    EXPECT_EQ(0660U, config.socketMode);
}

TEST(UdsHttpServerConfigTest, EmptySocketPathFallsBackToTheDefault)
{
    auto input = zeroedConfig();
    input.socket_path[0] = '\0';

    EXPECT_EQ("queue/sockets/inventory-sync.sock", buildServerConfig(input).socketPath);
}

// Thread counts track the host/cgroup's CPUs rather than a fixed constant, so a container with a
// tight quota does not get a reactor sized for the metal.
TEST(UdsHttpServerConfigTest, ThreadCountFallsBackToTheAvailableCpuCount)
{
    auto input = zeroedConfig();
    input.io_threads = 0;

    EXPECT_EQ(static_cast<std::size_t>(cpp_get_nproc()), buildServerConfig(input).ioThreads);
    EXPECT_GT(buildServerConfig(input).ioThreads, 0U);
}

// The indexer field is not the server's business; it must not leak into the transport configuration.
TEST(UdsHttpServerConfigTest, IndexerFieldDoesNotAffectTheServerConfiguration)
{
    auto withIndexer = zeroedConfig();
    withIndexer.indexer = nullptr;

    const auto a = buildServerConfig(withIndexer);
    const auto b = buildServerConfig(zeroedConfig());

    EXPECT_EQ(a.socketPath, b.socketPath);
    EXPECT_EQ(a.maxBodySize, b.maxBodySize);
}
