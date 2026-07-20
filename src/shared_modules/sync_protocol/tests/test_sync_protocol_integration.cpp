/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"

#include "agent_sync_protocol.hpp"
#include "persistent_queue.hpp"
#include "metadata_provider.h"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <thread>

/**
 * Integration Tests for Sync Protocol
 *
 * These tests verify the real integration between components:
 * - Real PersistentQueue with SQLite database
 * - Real AgentSyncProtocol
 * - Real file I/O operations
 *
 * Unlike unit tests that use mocks, these tests verify that components
 * work correctly together in realistic scenarios.
 */

class SyncProtocolIntegrationTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Create temporary directory for test databases
            testDbPath = "/tmp/sync_protocol_integration_test_" +
                         std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
                         ".db";

            // Set up metadata for sync protocol
            agent_metadata_t metadata = {};
            strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
            strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
            strncpy(metadata.agent_version, "4.5.0", sizeof(metadata.agent_version) - 1);
            strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
            strncpy(metadata.hostname, "test-host", sizeof(metadata.hostname) - 1);
            strncpy(metadata.os_name, "Linux", sizeof(metadata.os_name) - 1);
            strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
            strncpy(metadata.os_platform, "ubuntu", sizeof(metadata.os_platform) - 1);
            strncpy(metadata.os_version, "5.10", sizeof(metadata.os_version) - 1);
            char* groups[] = {const_cast<char*>("group1")};
            metadata.groups = groups;
            metadata.groups_count = 1;
            metadata_provider_update(&metadata);

            // Create logger
            logger = [](modules_log_level_t, const std::string&)
            {
                // Silent logger for tests, but can be enabled for debugging
                // std::cout << "[" << level << "] " << msg << std::endl;
            };

            // Create MQ functions (mock for now, but could be real)
            mqFuncs.start = [](const char*, short, short)
            {
                return 0;
            };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char)
            {
                return 0;
            };
        }

        void TearDown() override
        {
            // Clean up test database
            if (std::filesystem::exists(testDbPath))
            {
                std::filesystem::remove(testDbPath);
            }

            // Reset metadata provider
            metadata_provider_reset();
        }

        std::string testDbPath;
        LoggerFunc logger;
        MQ_Functions mqFuncs;
};

// ========================================
// Integration Test: PersistentQueue with Real Database
// ========================================

TEST_F(SyncProtocolIntegrationTest, PersistentQueue_RealDatabase_BasicOperations)
{
    /**
     * Integration Test: Verify PersistentQueue works with real SQLite database
     *
     * This test:
     * 1. Creates a real PersistentQueue with SQLite database
     * 2. Submits data to the queue
     * 3. Fetches pending items
     * 4. Verifies data persistence across operations
     */

    // Create real PersistentQueue with real SQLite database
    PersistentQueue queue(testDbPath, logger);

    // Submit test data
    std::string testId = "test_package_1";
    std::string testIndex = "wazuh-states-vulnerabilities-packages";
    std::string testData = R"({"name":"test-pkg","version":"1.0","architecture":"x86_64"})";

    EXPECT_NO_THROW(
        queue.submit(testId, testIndex, testData, Operation::CREATE, 0, false)
    );

    // Fetch pending items (should return the item we just submitted)
    auto pendingItems = queue.fetchPendingItems(true);

    ASSERT_EQ(pendingItems.size(), 1);
    EXPECT_EQ(pendingItems[0].id, testId);
    EXPECT_EQ(pendingItems[0].index, testIndex);
    EXPECT_EQ(pendingItems[0].data, testData);
    EXPECT_EQ(pendingItems[0].operation, Operation::CREATE);
    EXPECT_FALSE(pendingItems[0].is_data_context);
}

TEST_F(SyncProtocolIntegrationTest, PersistentQueue_FetchOnlyDataValues)
{
    /**
     * Integration Test: Verify fetchPendingItems correctly filters DataValue vs DataContext
     *
     * This test:
     * 1. Submits both DataValue and DataContext items
     * 2. Fetches only DataValues
     * 3. Verifies correct filtering
     */

    PersistentQueue queue(testDbPath, logger);

    // Submit DataValue item
    queue.submit("datavalue1", "wazuh-states-vulnerabilities-packages",
                 R"({"name":"pkg1"})", Operation::CREATE, 0, false);

    // Submit DataContext item
    queue.submit("datacontext1", "wazuh-states-vulnerabilities-packages",
                 R"({"context":"data"})", Operation::MODIFY, 0, true);

    // Fetch only DataValues
    auto dataValues = queue.fetchPendingItems(true);

    // Should only return the DataValue item
    ASSERT_EQ(dataValues.size(), 1);
    EXPECT_EQ(dataValues[0].id, "datavalue1");
    EXPECT_FALSE(dataValues[0].is_data_context);

    // Fetch all items (DataValues + DataContext)
    auto allItems = queue.fetchPendingItems(false);

    // Should return both items
    ASSERT_EQ(allItems.size(), 2);
}

TEST_F(SyncProtocolIntegrationTest, PersistentQueue_ClearAllDataContext)
{
    /**
     * Integration Test: Verify clearAllDataContext removes only DataContext items
     *
     * This test:
     * 1. Submits both DataValue and DataContext items
     * 2. Clears all DataContext items
     * 3. Verifies only DataContext items were removed
     */

    PersistentQueue queue(testDbPath, logger);

    // Submit multiple items
    queue.submit("datavalue1", "wazuh-states-vulnerabilities-packages",
                 R"({"name":"pkg1"})", Operation::CREATE, 0, false);
    queue.submit("datacontext1", "wazuh-states-vulnerabilities-packages",
                 R"({"context":"ctx1"})", Operation::MODIFY, 0, true);
    queue.submit("datavalue2", "wazuh-states-vulnerabilities-system",
                 R"({"os":"Linux"})", Operation::CREATE, 0, false);
    queue.submit("datacontext2", "wazuh-states-vulnerabilities-system",
                 R"({"context":"ctx2"})", Operation::MODIFY, 0, true);

    // Verify we have 4 items total
    auto allItems = queue.fetchPendingItems(false);
    ASSERT_EQ(allItems.size(), 4);

    // Clear all DataContext items
    EXPECT_NO_THROW(queue.clearAllDataContext());

    // Verify only DataValue items remain
    auto remainingItems = queue.fetchPendingItems(false);
    ASSERT_EQ(remainingItems.size(), 2);
    EXPECT_FALSE(remainingItems[0].is_data_context);
    EXPECT_FALSE(remainingItems[1].is_data_context);
}

// ========================================
// Integration Test: AgentSyncProtocol with Real PersistentQueue
// ========================================

TEST_F(SyncProtocolIntegrationTest, AgentSyncProtocol_PersistAndFetch)
{
    /**
     * Integration Test: Verify AgentSyncProtocol correctly persists and fetches data
     *
     * This test:
     * 1. Creates real AgentSyncProtocol with real database
     * 2. Persists differences
     * 3. Fetches pending items
     * 4. Verifies data integrity
     */

    // Create real AgentSyncProtocol with real database
    AgentSyncProtocol protocol(
        "syscollector_vd",
        testDbPath,
        mqFuncs,
        logger,
        std::chrono::seconds(1),
        std::chrono::seconds(3),
        1,
        100,
        nullptr  // Let protocol create its own PersistentQueue
    );

    // Persist some data
    std::string packageId = "pkg_001";
    std::string packageIndex = "wazuh-states-vulnerabilities-packages";
    std::string packageData = R"({
        "name": "test-package",
        "version": "1.0.0",
        "architecture": "x86_64",
        "description": "Test package for integration tests"
    })";

    EXPECT_NO_THROW(
        protocol.persistDifference(packageId, Operation::CREATE, packageIndex, packageData, 0, false)
    );

    // Fetch pending items
    auto pendingItems = protocol.fetchPendingItems(true);

    ASSERT_EQ(pendingItems.size(), 1);
    EXPECT_EQ(pendingItems[0].id, packageId);
    EXPECT_EQ(pendingItems[0].index, packageIndex);
    EXPECT_EQ(pendingItems[0].data, packageData);
    EXPECT_EQ(pendingItems[0].operation, Operation::CREATE);
}

TEST_F(SyncProtocolIntegrationTest, AgentSyncProtocol_VDWorkflow_ClearAndFetch)
{
    /**
     * Integration Test: Verify VD workflow with real components
     *
     * This test simulates the VD workflow:
     * 1. Persist DataValue items (packages, OS)
     * 2. Persist DataContext items
     * 3. Clear all DataContext
     * 4. Fetch only DataValues
     * 5. Verify correct behavior
     */

    AgentSyncProtocol protocol(
        "syscollector_vd",
        testDbPath,
        mqFuncs,
        logger,
        std::chrono::seconds(1),
        std::chrono::seconds(3),
        1,
        100,
        nullptr
    );

    // Step 1: Persist DataValue items
    protocol.persistDifference("pkg1", Operation::CREATE,
                               "wazuh-states-vulnerabilities-packages",
                               R"({"name":"pkg1","version":"1.0"})", 0, false);

    protocol.persistDifference("os1", Operation::MODIFY,
                               "wazuh-states-vulnerabilities-system",
                               R"({"os_name":"Linux","os_version":"5.10"})", 0, false);

    // Step 2: Persist DataContext items
    protocol.persistDifference("ctx_pkg", Operation::MODIFY,
                               "wazuh-states-vulnerabilities-packages",
                               R"({"context":"packages_context"})", 0, true);

    protocol.persistDifference("ctx_os", Operation::MODIFY,
                               "wazuh-states-vulnerabilities-system",
                               R"({"context":"os_context"})", 0, true);

    // Step 3: Verify we have both types
    auto allItems = protocol.fetchPendingItems(false);
    ASSERT_EQ(allItems.size(), 4);

    // Step 4: Clear all DataContext
    EXPECT_NO_THROW(protocol.clearAllDataContext());

    // Step 5: Fetch only DataValues
    auto dataValues = protocol.fetchPendingItems(true);

    // Should only have the 2 DataValue items
    ASSERT_EQ(dataValues.size(), 2);
    EXPECT_FALSE(dataValues[0].is_data_context);
    EXPECT_FALSE(dataValues[1].is_data_context);
}

TEST_F(SyncProtocolIntegrationTest, AgentSyncProtocol_MultipleIndices)
{
    /**
     * Integration Test: Verify protocol handles multiple VD indices correctly
     *
     * This test:
     * 1. Persists data to different VD indices (packages, system, hotfixes)
     * 2. Fetches all pending items
     * 3. Verifies correct index assignment
     */

    AgentSyncProtocol protocol(
        "syscollector_vd",
        testDbPath,
        mqFuncs,
        logger,
        std::chrono::seconds(1),
        std::chrono::seconds(3),
        1,
        100,
        nullptr
    );

    // Persist to packages index
    protocol.persistDifference("item1", Operation::CREATE,
                               "wazuh-states-vulnerabilities-packages",
                               R"({"name":"package1"})", 0, false);

    // Persist to system index
    protocol.persistDifference("item2", Operation::CREATE,
                               "wazuh-states-vulnerabilities-system",
                               R"({"os":"Linux"})", 0, false);

    // Persist to hotfixes index
    protocol.persistDifference("item3", Operation::CREATE,
                               "wazuh-states-vulnerabilities-hotfixes",
                               R"({"hotfix":"KB123456"})", 0, false);

    // Fetch all items
    auto items = protocol.fetchPendingItems(true);

    ASSERT_EQ(items.size(), 3);

    // Verify indices are correct
    std::set<std::string> indices;

    for (const auto& item : items)
    {
        indices.insert(item.index);
    }

    EXPECT_TRUE(indices.count("wazuh-states-vulnerabilities-packages") > 0);
    EXPECT_TRUE(indices.count("wazuh-states-vulnerabilities-system") > 0);
    EXPECT_TRUE(indices.count("wazuh-states-vulnerabilities-hotfixes") > 0);
}

TEST_F(SyncProtocolIntegrationTest, AgentSyncProtocol_DataPersistenceAcrossInstances)
{
    /**
     * Integration Test: Verify data persists across AgentSyncProtocol instances
     *
     * This test:
     * 1. Creates protocol instance and persists data
     * 2. Destroys the instance
     * 3. Creates new instance with same database
     * 4. Verifies data is still there
     */

    // Create first instance and persist data
    {
        AgentSyncProtocol protocol1(
            "syscollector_vd",
            testDbPath,
            mqFuncs,
            logger,
            std::chrono::seconds(1),
            std::chrono::seconds(3),
            1,
            100,
            nullptr
        );

        protocol1.persistDifference("persistent_item", Operation::CREATE,
                                    "wazuh-states-vulnerabilities-packages",
                                    R"({"name":"persistent_package"})", 0, false);
    }
    // protocol1 goes out of scope and is destroyed

    // Create second instance with same database
    {
        AgentSyncProtocol protocol2(
            "syscollector_vd",
            testDbPath,
            mqFuncs,
            logger,
            std::chrono::seconds(1),
            std::chrono::seconds(3),
            1,
            100,
            nullptr
        );

        // Fetch items - should still have the item from protocol1
        auto items = protocol2.fetchPendingItems(true);

        ASSERT_EQ(items.size(), 1);
        EXPECT_EQ(items[0].id, "persistent_item");
        EXPECT_EQ(items[0].data, R"({"name":"persistent_package"})");
    }
}
