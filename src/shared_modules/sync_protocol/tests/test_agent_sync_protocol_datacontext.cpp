/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file test_agent_sync_protocol_datacontext.cpp
 * @brief Unit tests for DataContext message handling in AgentSyncProtocol
 *
 * This file contains tests for:
 * - synchronizeModule() with DataContext separation logic
 * - Mixed DataValue and DataContext scenarios
 */

#include "gmock/gmock.h"
#include "mock_sync_transport.hpp"
#include "gtest/gtest.h"

#include "agent_sync_protocol.hpp"
#include "ipersistent_queue.hpp"
#include "metadata_provider.h"

#include <iostream>
#include <optional>
#include <thread>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

// IPersistentQueue Mock
class MockPersistentQueue : public IPersistentQueue
{
    public:
        MOCK_METHOD(void,
                    submit,
                    (const std::string& id,
                     const std::string& index,
                     const std::string& data,
                     Operation operation,
                     uint64_t version,
                     bool isDataContext),
                    (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (size_t maxItems), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchPendingItems, (bool onlyDataValues), (override));
        MOCK_METHOD(void, clearSyncedItems, (), (override));
        MOCK_METHOD(void, resetSyncingItems, (), (override));
        MOCK_METHOD(void, clearItemsByIndex, (const std::string& index), (override));
        MOCK_METHOD(void, clearAllDataContext, (), (override));
        MOCK_METHOD(void, deleteDatabase, (), (override));
};

class AgentSyncProtocolDataContextTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Create and set dummy metadata
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
        }

        void TearDown() override
        {
            metadata_provider_reset();
        }

        /// Feeds a /stateful HTTP result to the protocol, as https_client_bridge.c
        /// would: "HCRESULT:<session>:<http_code>:<body>". forSession=0 skips the
        /// protocol's session-correlation check.
        bool feedHttpResult(int httpCode, const std::string& body = "{}", uint64_t forSession = 0)
        {
            const std::string text = "HCRESULT:" + std::to_string(forSession) + ":" +
                                     std::to_string(httpCode) + ":" + body;
            return protocol->parseResponseBuffer(reinterpret_cast<const uint8_t*>(text.data()), text.size());
        }

        std::shared_ptr<MockPersistentQueue> mockQueue;
        std::shared_ptr<MockSyncTransport> mockSyncTransport =
            std::make_shared<MockSyncTransport>();
        std::unique_ptr<AgentSyncProtocol> protocol;
        const uint64_t session = 1234;
        const unsigned int retries = 1;
        const unsigned int delay = 100;
        const unsigned int max_timeout = 10;
};

// ========================================
// Tests for synchronizeModule() with DataContext
// ========================================
//
// Note: DataContext items travel inside the FullSession that
// synchronizeModule() builds, so the tests below assert on the
// captured session.

// ========================================
// Tests for synchronizeModule() with DataContext
// ========================================

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithOnlyDataValueItems)
{
    // Test synchronization with only DataValue items (no DataContext)
    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Only DataValue items (is_data_context = false)
    std::vector<PersistedData> testData = {{0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},
        {1, "id_2", "processes", "proc_data_1", Operation::CREATE, 1, false}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result.success);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    // Send EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithOnlyDataContextItems)
{
    // Test synchronization with only DataContext items (no DataValue)
    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Only DataContext items (is_data_context = true)
    std::vector<PersistedData> testData = {{0, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true},
        {1, "ctx_id_2", "vd_system", "os_data", Operation::CREATE, 1, true}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result.success);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck

    // Wait for DataContext messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    // Send EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithMixedDataValueAndDataContext)
{
    // Test synchronization with both DataValue and DataContext items
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int dataValuesInBatch = 0;
    static int dataContextMessagesSent = 0;
    dataValuesInBatch = 0;       // Reset
    dataContextMessagesSent = 0; // Reset


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Mixed DataValue and DataContext items
    std::vector<PersistedData> testData =
    {
        {0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},            // DataValue
        {1, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true}, // DataContext
        {2, "id_2", "processes", "proc_data_1", Operation::CREATE, 1, false},         // DataValue
        {3, "ctx_id_2", "vd_system", "os_data", Operation::CREATE, 1, true}           // DataContext
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result.success);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck

    // Wait for all data messages (DataValue first, then DataContext)
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 3));

    // Send EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    // DataValues are packed into DataBatch messages; DataContext sent individually
    std::vector<uint8_t> keepAlive;
    const auto* session = capturedSession(mockSyncTransport, keepAlive);
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(2, countedDataValues(session));
    const auto* data = syncData(session);
    ASSERT_NE(nullptr, data);
    ASSERT_NE(nullptr, data->contexts());
    EXPECT_EQ(2u, data->contexts()->size());
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleDataContextFailureDoesNotAffectDataValue)
{
    // Test that DataContext failure doesn't prevent successful sync if DataValue succeeds
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int messageCount = 0;
    messageCount = 0; // Reset

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},
        {1, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, resetSyncingItems()).Times(1); // Should reset due to DataContext failure

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(result.success); // Should fail due to DataContext send failure
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck

    // Send EndAck with Error status to fail the session
    feedHttpResult(500);  // was Status::Error

    syncThread.join();
}

// ========================================
// Tests for SyncData payload behavior
// ========================================

TEST_F(AgentSyncProtocolDataContextTest, SyncData_DataValuesArriveTogether)
{
    // DataValues in DELTA mode must be sent inside the session's SyncData payload,
    // not as individual DataValue messages.
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int dataBatchMessagesSent = 0;
    static int dataValueMessagesSent = 0;
    static int totalDataValuesInBatches = 0;
    dataBatchMessagesSent = 0;
    dataValueMessagesSent = 0;
    totalDataValuesInBatches = 0;


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData = {{0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},
        {1, "id_2", "processes", "proc_data_1", Operation::CREATE, 1, false},
        {2, "id_3", "packages", "pkg_data_1", Operation::CREATE, 1, false}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result.success);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));


    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    // All DataValues must arrive inside the session's SyncData payload, never as
    // individual DataValue messages.
    std::vector<uint8_t> keepAlive;
    const auto* session = capturedSession(mockSyncTransport, keepAlive);
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(1, mockSyncTransport->sendCount());          // One message for the whole session.
    ASSERT_NE(nullptr, syncData(session));                 // No ~60 KB split any more.
    EXPECT_EQ(3, countedDataValues(session));
}

TEST_F(AgentSyncProtocolDataContextTest, SyncData_PayloadContainsExpectedDataValues)
{
    // Verify that the SyncData payload carries the correct seq and id for each DataValue.
    mockQueue = std::make_shared<MockPersistentQueue>();

    static std::vector<std::pair<uint64_t, std::string>> received; // {seq, id}
    received.clear();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData = {{0, "host_id_1", "network", "net_data", Operation::CREATE, 1, false},
        {1, "host_id_2", "packages", "pkg_data", Operation::CREATE, 1, false}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread(
        [this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result.success);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));


    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    std::vector<uint8_t> keepAlive;
    const auto* session = capturedSession(mockSyncTransport, keepAlive);
    ASSERT_NE(nullptr, session);
    const auto* data = syncData(session);
    ASSERT_NE(nullptr, data);
    const auto* values = data->values();
    ASSERT_NE(nullptr, values);
    ASSERT_EQ(2u, values->size());
    EXPECT_EQ("host_id_1", values->Get(0)->id()->str());
    EXPECT_EQ("host_id_2", values->Get(1)->id()->str());
}
