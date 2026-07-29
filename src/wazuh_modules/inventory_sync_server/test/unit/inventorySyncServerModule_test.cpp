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

#include "inventory_sync_server.h"
#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using invsync::test::logCallCount;
using invsync::test::LogRecorder;
using invsync::test::testLogCallback;

namespace
{
    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/issm_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
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

class InventorySyncServerModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logCallCount().store(0, std::memory_order_relaxed);
        LogRecorder::clear();
    }

    void TearDown() override
    {
        // Ensure the module is stopped even if a test asserted early.
        inventory_sync_server_stop();
        // An override made by one test must never leak into the next.
        invsync::test::resetIndexerConnectorFactoryToProduction();
    }
};

TEST_F(InventorySyncServerModuleTest, StartAndStop)
{
    const auto path = uniqueSocketPath("startstop");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"));
    inventory_sync_server_stop();

    EXPECT_GT(logCallCount().load(), 0);
}

TEST_F(InventorySyncServerModuleTest, StopWithoutStartIsSafe)
{
    inventory_sync_server_stop();
    SUCCEED();
}

// A NULL configuration must fall back to defaults without crashing. It binds the real default socket
// path, which may well fail in a test environment -- that is fine and is itself the retry path; what
// matters is that nothing crashes.
TEST_F(InventorySyncServerModuleTest, StartWithNullConfigIsSafe)
{
    inventory_sync_server_start(testLogCallback, nullptr);
    inventory_sync_server_stop();
    EXPECT_GT(logCallCount().load(), 0);
}

TEST_F(InventorySyncServerModuleTest, DoubleStartIsIgnored)
{
    const auto path = uniqueSocketPath("double");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("already started"));
    inventory_sync_server_stop();
}

TEST_F(InventorySyncServerModuleTest, StopIsIdempotent)
{
    const auto path = uniqueSocketPath("idem");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    inventory_sync_server_stop();
    EXPECT_NO_FATAL_FAILURE(inventory_sync_server_stop());
}

/**
 * The wedge regression. If m_running were set BEFORE the worker thread was created, a throwing
 * std::thread constructor would leave the facade claiming to run with nothing running, and every
 * later start() would be refused as "already started" forever. This pins the invariant from the
 * reachable direction: a clean stop must leave the module startable again.
 */
TEST_F(InventorySyncServerModuleTest, StartStopStartAgainWorks)
{
    const auto path = uniqueSocketPath("restart");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"));
    inventory_sync_server_stop();

    LogRecorder::clear();
    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"))
        << "the module refused to restart after a clean stop";

    inventory_sync_server_stop();
}

// The socket actually in use has to be diagnosable from wazuh-manager.log alone.
TEST_F(InventorySyncServerModuleTest, StartLogsTheResolvedSocketPath)
{
    invsync::test::installAlwaysAvailableFakeIndexer();

    const auto path = uniqueSocketPath("logpath");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining(path)) << "the log must name the socket it bound";
    inventory_sync_server_stop();
}

TEST_F(InventorySyncServerModuleTest, StartCreatesTheConfiguredSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexer();

    const auto path = uniqueSocketPath("created");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));

    inventory_sync_server_stop();
    EXPECT_FALSE(std::filesystem::exists(path)) << "a clean stop must remove the socket file";
}

/**
 * A permanent misconfiguration must be reported as an ERROR that names both the offending path and
 * the setting to change -- not as an opaque retry message repeated forever.
 */
TEST_F(InventorySyncServerModuleTest, UnbindableSocketPathIsReportedNamingThePathAndTheSetting)
{
    // Without this, the indexer gate would fail first (no <indexer> configured), and the failure
    // reported would be about the indexer rather than the socket this test means to exercise.
    invsync::test::installAlwaysAvailableFakeIndexer();

    auto config = makeConfig("/proc/self/does-not-exist/inventory-sync.sock");

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("/proc/self/does-not-exist/inventory-sync.sock"))
        << "the failure must name the path that could not be bound";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("socket_path")) << "the failure must name the setting to change";

    inventory_sync_server_stop();
}

/**
 * The indexer block is BORROWED for the duration of start() only; the module deep-copies what it
 * needs. Freeing it immediately afterwards must be safe.
 *
 * Only genuinely meaningful under ASan, where a retained pointer would be reported as a
 * use-after-free instead of quietly working.
 */
TEST_F(InventorySyncServerModuleTest, IndexerConfigIsCopiedAndNotRetained)
{
    // This test is about the C-ABI's borrow contract, not about really constructing an
    // IndexerConnectorSync (whose CA-file-must-exist check would otherwise reject the fake path
    // used below) -- bypass real construction so it stays fast and deterministic.
    invsync::test::installAlwaysAvailableFakeIndexer();

    const auto path = uniqueSocketPath("indexer");
    auto config = makeConfig(path);

    cJSON* indexer = cJSON_CreateObject();
    cJSON* hosts = cJSON_CreateArray();
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.1:9200"));
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.2:9200"));
    cJSON_AddItemToObject(indexer, "hosts", hosts);
    cJSON_AddStringToObject(indexer, "username", "admin");
    cJSON* ssl = cJSON_CreateObject();
    cJSON* authorities = cJSON_CreateArray();
    cJSON_AddItemToArray(authorities, cJSON_CreateString("/etc/certs/root-ca.pem"));
    cJSON_AddItemToObject(ssl, "certificate_authorities", authorities);
    cJSON_AddStringToObject(ssl, "key", "/etc/certs/private.key");
    cJSON_AddItemToObject(indexer, "ssl", ssl);
    config.indexer = indexer;

    inventory_sync_server_start(testLogCallback, &config);

    // Freed while the module is still running: nothing may reach back into it.
    cJSON_Delete(indexer);
    config.indexer = nullptr;

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    inventory_sync_server_stop();
}

// Counts and set/unset only. The hosts can carry credentials in the URL and the certificate paths
// are not useful in a log line, so neither may be rendered.
TEST_F(InventorySyncServerModuleTest, IndexerSummaryLogsCountsNotSecrets)
{
    // Keeps this test from making a real (if fast) network attempt against the fake hosts below.
    invsync::test::installAlwaysAvailableFakeIndexer();

    const auto path = uniqueSocketPath("secrets");
    auto config = makeConfig(path);

    cJSON* indexer = cJSON_CreateObject();
    cJSON* hosts = cJSON_CreateArray();
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://user:s3cret@127.0.0.1:9200"));
    cJSON_AddItemToArray(hosts, cJSON_CreateString("https://127.0.0.2:9200"));
    cJSON_AddItemToObject(indexer, "hosts", hosts);
    cJSON* ssl = cJSON_CreateObject();
    cJSON_AddStringToObject(ssl, "key", "/etc/certs/private.key");
    cJSON_AddItemToObject(indexer, "ssl", ssl);
    config.indexer = indexer;

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("Indexer configuration received"));

    EXPECT_TRUE(LogRecorder::sawMessageContaining("hosts=2"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("s3cret")) << "credentials must never be logged";
    EXPECT_FALSE(LogRecorder::sawMessageContaining("/etc/certs/private.key"))
        << "key paths must not be logged, only whether they are set";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("ssl.key=<set>"));

    cJSON_Delete(indexer);
    inventory_sync_server_stop();
}
