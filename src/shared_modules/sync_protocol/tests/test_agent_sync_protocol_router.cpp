/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "agent_sync_protocol.hpp"
#include "ipersistent_queue.hpp"
#include "agent_sync_protocol_c_interface.h"

#include <thread>
#include <iostream>

using ::testing::_;
using ::testing::Return;

// Mock for IPersistentQueue
class MockPersistentQueue : public IPersistentQueue
{
public:
    MOCK_METHOD(void, submit, (const std::string& id,
                               const std::string& index,
                               const std::string& data,
                               Operation operation,
                               uint64_t version), (override));
    MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (), (override));
    MOCK_METHOD(void, clearSyncedItems, (), (override));
    MOCK_METHOD(void, resetSyncingItems, (), (override));
    MOCK_METHOD(void, clearItemsByIndex, (const std::string& index), (override));
    MOCK_METHOD(void, deleteDatabase, (), (override));
};

class AgentSyncProtocolRouterTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // SERVER builds use Router transport
    }

    std::shared_ptr<MockPersistentQueue> mockQueue;
    std::unique_ptr<AgentSyncProtocol> protocol;

    const uint64_t session = 1234;
    const unsigned int retries = 1;
    const unsigned int maxEps = 100;
    const unsigned int syncEndDelay = 1;
    const uint8_t min_timeout = 1;
    const uint8_t max_timeout = 3;

    // Helper to create test logger
    LoggerFunc createTestLogger()
    {
        return [](modules_log_level_t, const std::string&) {};
    }
};

// Test that AgentSyncProtocol initializes with Router transport in SERVER builds
TEST_F(AgentSyncProtocolRouterTest, InitializesWithRouterTransport)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    // SERVER build doesn't need MQ_Functions, pass dummy values
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    // Should create RouterTransport internally without errors
    EXPECT_NO_THROW({
        protocol = std::make_unique<AgentSyncProtocol>(
            "test_module",
            ":memory:",
            dummyMqFuncs,
            testLogger,
            std::chrono::seconds(syncEndDelay),
            std::chrono::seconds(min_timeout),
            retries,
            maxEps,
            mockQueue
        );
    });

    ASSERT_NE(protocol, nullptr);
}

// Test persist difference with Router transport
TEST_F(AgentSyncProtocolRouterTest, PersistDifferenceSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion))
        .Times(1);

    protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion);
}

// Test persist difference in memory
TEST_F(AgentSyncProtocolRouterTest, PersistDifferenceInMemorySuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    const std::string testId = "memory_test_id";
    const std::string testIndex = "memory_test_index";
    const std::string testData = "memory_test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 456;

    EXPECT_NO_THROW(
        protocol->persistDifferenceInMemory(testId, testOperation, testIndex, testData, testVersion)
    );
}

// Test synchronize with empty data returns success
TEST_F(AgentSyncProtocolRouterTest, SynchronizeModuleWithEmptyDataReturnsSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Empty data should return true immediately
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(std::vector<PersistedData>{}));

    bool result = protocol->synchronizeModule(
        Mode::DELTA
    );

    EXPECT_TRUE(result);
}

// Test FULL mode uses in-memory data, not database
TEST_F(AgentSyncProtocolRouterTest, FullModeUsesInMemoryData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Add in-memory data
    protocol->persistDifferenceInMemory("id1", Operation::CREATE, "index1", "data1", 1);

    // Should NOT call fetchAndMarkForSync for FULL mode
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .Times(0);

    // Note: This will timeout because Router needs to be running
    // In a real integration test, the Router infrastructure would be available
    bool result = protocol->synchronizeModule(
        Mode::FULL
    );

    // Expected to timeout since Router is not running in unit test
    EXPECT_FALSE(result);
}

// Test DELTA mode uses database
TEST_F(AgentSyncProtocolRouterTest, DeltaModeUsesDatabaseQueue)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Should call fetchAndMarkForSync for DELTA mode
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(std::vector<PersistedData>{}));

    bool result = protocol->synchronizeModule(
        Mode::DELTA
    );

    EXPECT_TRUE(result);
}

// Test invalid mode validation
TEST_F(AgentSyncProtocolRouterTest, InvalidModeReturnsFailure)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Should NOT call any queue methods for invalid mode
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .Times(0);

    Mode invalidMode = static_cast<Mode>(999);

    bool result = protocol->synchronizeModule(
        invalidMode
    );

    EXPECT_FALSE(result);
}

// Test parseResponseBuffer with null buffer
TEST_F(AgentSyncProtocolRouterTest, ParseResponseBufferWithNullReturnsFailure)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    bool result = protocol->parseResponseBuffer(nullptr, 0);
    EXPECT_FALSE(result);
}

// Test parseResponseBuffer when not in sync phase
TEST_F(AgentSyncProtocolRouterTest, ParseResponseBufferWhenNotSyncingReturnsTrue)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Create a StartAck message
    flatbuffers::FlatBufferBuilder builder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union()
    );
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();

    // Should handle gracefully when not waiting for StartAck
    bool result = protocol->parseResponseBuffer(buffer, builder.GetSize());
    EXPECT_TRUE(result);
}

// Test exception handling in fetchAndMarkForSync
TEST_F(AgentSyncProtocolRouterTest, FetchAndMarkForSyncExceptionHandled)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Throw exception from fetchAndMarkForSync
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    bool result = protocol->synchronizeModule(
        Mode::DELTA
    );

    EXPECT_FALSE(result);
}

// Test exception handling in persistDifference
TEST_F(AgentSyncProtocolRouterTest, PersistDifferenceExceptionHandled)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Throw exception from submit
    EXPECT_CALL(*mockQueue, submit(_, _, _, _, _))
        .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Should not throw, just log error
    EXPECT_NO_THROW(
        protocol->persistDifference("id", Operation::CREATE, "index", "data", 1)
    );
}

// Test clearInMemoryData
TEST_F(AgentSyncProtocolRouterTest, ClearInMemoryDataSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    // Add in-memory data
    protocol->persistDifferenceInMemory("id1", Operation::CREATE, "index1", "data1", 1);
    protocol->persistDifferenceInMemory("id2", Operation::MODIFY, "index2", "data2", 2);

    // Clear it
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    // After clearing, FULL mode should have no data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .Times(0);

    bool result = protocol->synchronizeModule(
        Mode::FULL
    );

    // Should return true for empty data
    EXPECT_TRUE(result);
}

// Test deleteDatabase
TEST_F(AgentSyncProtocolRouterTest, DeleteDatabaseCallsQueue)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions dummyMqFuncs = {nullptr, nullptr};
    LoggerFunc testLogger = createTestLogger();

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        dummyMqFuncs,
        testLogger,
        std::chrono::seconds(syncEndDelay),
        std::chrono::seconds(min_timeout),
        retries,
        maxEps,
        mockQueue
    );

    EXPECT_CALL(*mockQueue, deleteDatabase())
        .Times(1);

    EXPECT_NO_THROW(protocol->deleteDatabase());
}

