/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer/indexerConnectorConfig.hpp"
#include "inventory_sync_server.h"

#include <gtest/gtest.h>

#include <json.hpp>
#include <string>
#include <vector>

using invsync::indexer::buildAsyncConnectorConfig;
using invsync::indexer::buildSyncConnectorConfig;

namespace
{
    /// Every numeric field set to a distinct value, so a test can tell which one landed where.
    inventory_sync_server_config_t fullyPopulatedConfig()
    {
        inventory_sync_server_config_t config {};
        config.indexer_sync_max_bulk_size = 111;
        config.indexer_sync_flush_interval_seconds = 222;
        config.indexer_sync_max_retry_delay_seconds = 333;
        config.indexer_async_bulk_max_bytes = 444;
        config.indexer_async_flush_interval_seconds = 555;
        config.indexer_async_max_retry_delay_seconds = 666;
        config.indexer_async_max_queue_bytes = 777;
        config.indexer_async_logger_queue_size = 888;
        config.indexer_async_logger_threads = 999;
        return config;
    }

    const std::vector<std::string> SYNC_KEYS {"max_bulk_size", "flush_interval_seconds", "max_retry_delay_seconds"};

    const std::vector<std::string> ASYNC_KEYS {"bulk_max_bytes",
                                               "flush_interval_seconds",
                                               "max_retry_delay_seconds",
                                               "max_queue_bytes",
                                               "logger_queue_size",
                                               "logger_threads"};
} // namespace

/**
 * The sync connector must receive ONLY the keys it reads. Emitting the async connector's names too
 * would be silently ignored by IndexerConnectorSync -- indistinguishable from a typo.
 */
TEST(IndexerConnectorConfigTest, SyncOverlayEmitsOnlyTheSyncKeyNames)
{
    const auto result = buildSyncConnectorConfig(nlohmann::json::object(), fullyPopulatedConfig());

    for (const auto& key : SYNC_KEYS)
    {
        EXPECT_TRUE(result.contains(key)) << "missing sync key: " << key;
    }

    EXPECT_FALSE(result.contains("bulk_max_bytes")) << "bulk_max_bytes is the ASYNC connector's key name";
    EXPECT_FALSE(result.contains("max_queue_bytes"));
    EXPECT_FALSE(result.contains("logger_queue_size"));
    EXPECT_FALSE(result.contains("logger_threads"));

    EXPECT_EQ(111U, result.at("max_bulk_size").get<std::size_t>());
    EXPECT_EQ(222U, result.at("flush_interval_seconds").get<std::size_t>());
    EXPECT_EQ(333U, result.at("max_retry_delay_seconds").get<std::size_t>());
}

TEST(IndexerConnectorConfigTest, AsyncOverlayEmitsOnlyTheAsyncKeyNames)
{
    const auto result = buildAsyncConnectorConfig(nlohmann::json::object(), fullyPopulatedConfig());

    for (const auto& key : ASYNC_KEYS)
    {
        EXPECT_TRUE(result.contains(key)) << "missing async key: " << key;
    }

    EXPECT_FALSE(result.contains("max_bulk_size")) << "max_bulk_size is the SYNC connector's key name";

    EXPECT_EQ(444U, result.at("bulk_max_bytes").get<std::size_t>());
    EXPECT_EQ(555U, result.at("flush_interval_seconds").get<std::size_t>());
    EXPECT_EQ(666U, result.at("max_retry_delay_seconds").get<std::size_t>());
    EXPECT_EQ(777U, result.at("max_queue_bytes").get<std::size_t>());
    EXPECT_EQ(888U, result.at("logger_queue_size").get<std::size_t>());
    EXPECT_EQ(999U, result.at("logger_threads").get<std::size_t>());
}

/**
 * THE regression pin. IndexerConnectorAsync gates `max_queue_bytes` on is_number_unsigned(), unlike
 * every other key. A signed JSON integer there is ignored silently and the queue stays unbounded --
 * and a contains() assertion passes just the same, which is why this checks the node's TYPE.
 */
TEST(IndexerConnectorConfigTest, AsyncMaxQueueBytesIsStoredAsAnUnsignedJsonNumber)
{
    inventory_sync_server_config_t config {};
    config.indexer_async_max_queue_bytes = 64 * 1024 * 1024;

    const auto result = buildAsyncConnectorConfig(nlohmann::json::object(), config);

    ASSERT_TRUE(result.contains("max_queue_bytes"));
    EXPECT_TRUE(result.at("max_queue_bytes").is_number_unsigned())
        << "a signed JSON integer here is silently ignored by IndexerConnectorAsync";
}

/// Extends the unsigned invariant to every overlaid key, including ones added later.
TEST(IndexerConnectorConfigTest, EveryOverlaidNumericKeyIsAnUnsignedJsonNumber)
{
    const auto config = fullyPopulatedConfig();

    const auto syncResult = buildSyncConnectorConfig(nlohmann::json::object(), config);
    for (const auto& [key, value] : syncResult.items())
    {
        EXPECT_TRUE(value.is_number_unsigned()) << "sync key not unsigned: " << key;
    }

    const auto asyncResult = buildAsyncConnectorConfig(nlohmann::json::object(), config);
    for (const auto& [key, value] : asyncResult.items())
    {
        EXPECT_TRUE(value.is_number_unsigned()) << "async key not unsigned: " << key;
    }
}

/// `flush_interval_seconds` is the one key name both connectors read; it must be fed from two
/// independent fields so the two can be tuned separately.
TEST(IndexerConnectorConfigTest, SyncAndAsyncFlushIntervalsAreIndependent)
{
    inventory_sync_server_config_t config {};
    config.indexer_sync_flush_interval_seconds = 5;
    config.indexer_async_flush_interval_seconds = 9;

    EXPECT_EQ(
        5U, buildSyncConnectorConfig(nlohmann::json::object(), config).at("flush_interval_seconds").get<std::size_t>());
    EXPECT_EQ(
        9U,
        buildAsyncConnectorConfig(nlohmann::json::object(), config).at("flush_interval_seconds").get<std::size_t>());
}

/**
 * A non-positive value must leave the key absent so the connector's own default applies. The negative
 * case matters most: it proves the `> 0` guard runs BEFORE the widening to size_t, i.e. that -1 does
 * not silently become SIZE_MAX.
 */
TEST(IndexerConnectorConfigTest, NonPositiveValuesLeaveTheConnectorDefaultUntouched)
{
    inventory_sync_server_config_t config {};
    config.indexer_sync_max_bulk_size = 0;
    config.indexer_sync_flush_interval_seconds = -1;
    config.indexer_sync_max_retry_delay_seconds = -2;
    config.indexer_async_bulk_max_bytes = 0;
    config.indexer_async_flush_interval_seconds = -1;
    config.indexer_async_max_retry_delay_seconds = -2;
    config.indexer_async_max_queue_bytes = -3;
    config.indexer_async_logger_queue_size = 0;
    config.indexer_async_logger_threads = -1;

    const auto syncResult = buildSyncConnectorConfig(nlohmann::json::object(), config);
    for (const auto& key : SYNC_KEYS)
    {
        EXPECT_FALSE(syncResult.contains(key)) << "non-positive value must not be written: " << key;
    }

    const auto asyncResult = buildAsyncConnectorConfig(nlohmann::json::object(), config);
    for (const auto& key : ASYNC_KEYS)
    {
        EXPECT_FALSE(asyncResult.contains(key)) << "non-positive value must not be written: " << key;
    }
}

/// `0` for max_queue_bytes is the connector's own legitimate "unlimited", so it must reach the
/// connector as an ABSENT key -- which is how the connector spells unlimited internally.
TEST(IndexerConnectorConfigTest, AZeroMaxQueueBytesLeavesTheKeyAbsentMeaningUnlimited)
{
    inventory_sync_server_config_t config {};
    config.indexer_async_max_queue_bytes = 0;

    EXPECT_FALSE(buildAsyncConnectorConfig(nlohmann::json::object(), config).contains("max_queue_bytes"));
}

TEST(IndexerConnectorConfigTest, BothBuildersPreserveHostsAndSsl)
{
    nlohmann::json indexerConfig;
    indexerConfig["hosts"] = {"https://127.0.0.1:9200"};
    indexerConfig["ssl"]["certificate_authorities"] = {"/etc/ca.pem"};
    indexerConfig["ssl"]["certificate"] = "/etc/cert.pem";

    const auto config = fullyPopulatedConfig();

    for (const auto& result :
         {buildSyncConnectorConfig(indexerConfig, config), buildAsyncConnectorConfig(indexerConfig, config)})
    {
        ASSERT_TRUE(result.contains("hosts"));
        EXPECT_EQ(1U, result.at("hosts").size());
        ASSERT_TRUE(result.contains("ssl"));
        EXPECT_EQ("/etc/cert.pem", result.at("ssl").at("certificate").get<std::string>());
        EXPECT_EQ(1U, result.at("ssl").at("certificate_authorities").size());
    }
}

TEST(IndexerConnectorConfigTest, NeitherBuilderMutatesItsInput)
{
    nlohmann::json indexerConfig;
    indexerConfig["hosts"] = {"https://127.0.0.1:9200"};
    const auto original = indexerConfig;

    const auto config = fullyPopulatedConfig();
    (void)buildSyncConnectorConfig(indexerConfig, config);
    (void)buildAsyncConnectorConfig(indexerConfig, config);

    EXPECT_EQ(original, indexerConfig);
}
