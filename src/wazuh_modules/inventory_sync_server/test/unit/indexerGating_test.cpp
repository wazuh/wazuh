/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer/indexerConnectorConfig.hpp"
#include "inventorySyncServerTestHooks.hpp"
#include "inventory_sync_server.h"
#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

using invsync::test::LogRecorder;
using invsync::test::testLogCallback;

namespace
{
    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/isg_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    inventory_sync_server_config_t makeConfig(const std::string& socketPath)
    {
        inventory_sync_server_config_t config {};
        std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "test-cluster");
        std::snprintf(config.node_name, sizeof(config.node_name), "%s", "test-node");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        return config;
    }
} // namespace

class IndexerGatingTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        LogRecorder::clear();
    }

    void TearDown() override
    {
        inventory_sync_server_stop();
        // An override made by one test must never leak into the next.
        invsync::test::resetIndexerConnectorFactoryToProduction();
    }
};

/**
 * No fake injected: the REAL IndexerConnectorSync constructor validates config synchronously and
 * throws "No hosts found in the configuration" for the default, empty <indexer> block -- fast, no
 * network I/O involved. The socket must never open, and the failure must be attributed to the
 * indexer, not to the socket path.
 */
TEST_F(IndexerGatingTest, BadIndexerConfigWithNoHostsBlocksSocketFromOpening)
{
    const auto path = uniqueSocketPath("nohosts");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_FALSE(LogRecorder::waitForMessageContaining("listening on", std::chrono::milliseconds {500}))
        << "the socket must never open with an invalid indexer configuration";
    EXPECT_FALSE(std::filesystem::exists(path));

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("indexer connector"))
        << "the failure must name the indexer, not the socket";
    EXPECT_FALSE(LogRecorder::sawMessageContaining("socket_path"))
        << "a config-validity failure must not be blamed on the socket";
}

TEST_F(IndexerGatingTest, ValidIndexerConfigUnblocksTheSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexer();

    const auto path = uniqueSocketPath("valid");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));
}

TEST_F(IndexerGatingTest, StopTearsDownTheIndexerConnector)
{
    auto destructions = std::make_shared<std::atomic<int>>(0);
    invsync::test::installAlwaysAvailableFakeIndexer(destructions);

    const auto path = uniqueSocketPath("teardown");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    inventory_sync_server_stop();

    EXPECT_EQ(1, destructions->load());
}

/**
 * Once construction succeeds, it is a "config is valid" signal that cannot change without a
 * restart -- it must never be redone, even across many retries of the OTHER half (the socket bind).
 * An unbindable socket path keeps that half failing and retrying, while the indexer half (already
 * constructed on the first attempt) must not be touched again.
 */
TEST_F(IndexerGatingTest, IndexerConnectorIsConstructedOnlyOnceAcrossRetries)
{
    auto constructions = invsync::test::installAlwaysAvailableFakeIndexer();

    auto config = makeConfig("/proc/self/does-not-exist/inventory-sync.sock");

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));

    // The worker thread's own first attempt races with this assertion; wait for it rather than
    // assuming it has already run.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
    while (constructions->load() < 1 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }
    ASSERT_EQ(1, constructions->load());

    // Two more retries of the whole gate, forced synchronously instead of waiting out the real 60 s
    // heartbeat -- both must still fail on the unbindable socket, without touching the indexer again.
    invsync::test_hooks::forceRetryForTests();
    invsync::test_hooks::forceRetryForTests();

    EXPECT_EQ(1, constructions->load()) << "a successful construction must never be repeated";
}

TEST(IndexerConnectorConfigTest, OverlayMapsToTheConnectorsKeyNames)
{
    inventory_sync_server_config_t config {};
    config.indexer_bulk_size_bytes = 12345;
    config.indexer_flush_interval = 42;

    const auto result = invsync::indexer::buildConnectorConfig(nlohmann::json::object(), config);

    ASSERT_TRUE(result.contains("max_bulk_size"));
    EXPECT_EQ(12345U, result.at("max_bulk_size").get<std::size_t>());
    ASSERT_TRUE(result.contains("flush_interval_seconds"));
    EXPECT_EQ(42U, result.at("flush_interval_seconds").get<std::size_t>());
}

TEST(IndexerConnectorConfigTest, NonPositiveValuesLeaveTheDefaultUntouched)
{
    inventory_sync_server_config_t config {};
    config.indexer_bulk_size_bytes = 0;
    config.indexer_flush_interval = -1;

    const auto result = invsync::indexer::buildConnectorConfig(nlohmann::json::object(), config);

    EXPECT_FALSE(result.contains("max_bulk_size"));
    EXPECT_FALSE(result.contains("flush_interval_seconds"));
}

TEST(IndexerConnectorConfigTest, PreservesTheRestOfTheIndexerBlock)
{
    inventory_sync_server_config_t config {};
    config.indexer_bulk_size_bytes = 100;

    nlohmann::json indexerConfig;
    indexerConfig["hosts"] = {"https://127.0.0.1:9200"};

    const auto result = invsync::indexer::buildConnectorConfig(indexerConfig, config);

    ASSERT_TRUE(result.contains("hosts"));
    EXPECT_EQ(1U, result.at("hosts").size());
    EXPECT_EQ(100U, result.at("max_bulk_size").get<std::size_t>());
}
