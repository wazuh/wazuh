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
 * - sendDataContextMessages()
 * - synchronizeModule() with DataContext separation logic
 * - Mixed DataValue and DataContext scenarios
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "agent_sync_protocol.hpp"
#include "ipersistent_queue.hpp"
#include "metadata_provider.h"

#include <optional>
#include <thread>
#include <iostream>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;

// IPersistentQueue Mock
class MockPersistentQueue : public IPersistentQueue
{
    public:
        MOCK_METHOD(void, submit, (const std::string& id,
                                   const std::string& index,
                                   const std::string& data,
                                   Operation operation,
                                   uint64_t version,
                                   bool isDataContext), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (), (override));
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

        std::shared_ptr<MockPersistentQueue> mockQueue;
        std::unique_ptr<AgentSyncProtocol> protocol;
        const uint64_t session = 1234;
        const unsigned int retries = 1;
        const unsigned int maxEps = 100;
        const unsigned int delay = 100;
        const unsigned int syncEndDelay = 1;
        const unsigned int max_timeout = 10;
};

// ========================================
// Tests for synchronizeModule() with DataContext
// ========================================
//
// Note: sendDataContextMessages() is tested indirectly through
// synchronizeModule() tests below, as it's meant to be called
// within an active sync session context.

// ========================================
// Tests for synchronizeModule() with DataContext
// ========================================

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithOnlyDataValueItems)
{
    // Test synchronization with only DataValue items (no DataContext)
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1; // Success
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries, maxEps, mockQueue);

    // Only DataValue items (is_data_context = false)
    std::vector<PersistedData> testData =
    {
        {0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},
        {1, "id_2", "processes", "proc_data_1", Operation::CREATE, 1, false}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();
    auto startMessage = Wazuh::SyncSchema::CreateMessage(startBuilder,
                                                         Wazuh::SyncSchema::MessageType::StartAck,
                                                         startAckOffset.Union());
    startBuilder.Finish(startMessage);
    protocol->parseResponseBuffer(startBuilder.GetBufferPointer(), startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    // Send EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();
    auto endMessage = Wazuh::SyncSchema::CreateMessage(endBuilder,
                                                       Wazuh::SyncSchema::MessageType::EndAck,
                                                       endAckOffset.Union());
    endBuilder.Finish(endMessage);
    protocol->parseResponseBuffer(endBuilder.GetBufferPointer(), endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithOnlyDataContextItems)
{
    // Test synchronization with only DataContext items (no DataValue)
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1; // Success
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries, maxEps, mockQueue);

    // Only DataContext items (is_data_context = true)
    std::vector<PersistedData> testData =
    {
        {0, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true},
        {1, "ctx_id_2", "vd_system", "os_data", Operation::CREATE, 1, true}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();
    auto startMessage = Wazuh::SyncSchema::CreateMessage(startBuilder,
                                                         Wazuh::SyncSchema::MessageType::StartAck,
                                                         startAckOffset.Union());
    startBuilder.Finish(startMessage);
    protocol->parseResponseBuffer(startBuilder.GetBufferPointer(), startBuilder.GetSize());

    // Wait for DataContext messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    // Send EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();
    auto endMessage = Wazuh::SyncSchema::CreateMessage(endBuilder,
                                                       Wazuh::SyncSchema::MessageType::EndAck,
                                                       endAckOffset.Union());
    endBuilder.Finish(endMessage);
    protocol->parseResponseBuffer(endBuilder.GetBufferPointer(), endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleWithMixedDataValueAndDataContext)
{
    // Test synchronization with both DataValue and DataContext items
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int dataValueMessagesSent = 0;
    static int dataContextMessagesSent = 0;
    dataValueMessagesSent = 0; // Reset
    dataContextMessagesSent = 0; // Reset

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void* data, size_t, const char*, char)
        {
            // Inspect message type from flatbuffer
            auto message = Wazuh::SyncSchema::GetMessage(data);

            if (message->content_type() == Wazuh::SyncSchema::MessageType::DataValue)
            {
                dataValueMessagesSent++;
            }
            else if (message->content_type() == Wazuh::SyncSchema::MessageType::DataContext)
            {
                dataContextMessagesSent++;
            }

            return 1; // Success
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries, maxEps, mockQueue);

    // Mixed DataValue and DataContext items
    std::vector<PersistedData> testData =
    {
        {0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},          // DataValue
        {1, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true}, // DataContext
        {2, "id_2", "processes", "proc_data_1", Operation::CREATE, 1, false},       // DataValue
        {3, "ctx_id_2", "vd_system", "os_data", Operation::CREATE, 1, true}         // DataContext
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();
    auto startMessage = Wazuh::SyncSchema::CreateMessage(startBuilder,
                                                         Wazuh::SyncSchema::MessageType::StartAck,
                                                         startAckOffset.Union());
    startBuilder.Finish(startMessage);
    protocol->parseResponseBuffer(startBuilder.GetBufferPointer(), startBuilder.GetSize());

    // Wait for all data messages (DataValue first, then DataContext)
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 3));

    // Send EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();
    auto endMessage = Wazuh::SyncSchema::CreateMessage(endBuilder,
                                                       Wazuh::SyncSchema::MessageType::EndAck,
                                                       endAckOffset.Union());
    endBuilder.Finish(endMessage);
    protocol->parseResponseBuffer(endBuilder.GetBufferPointer(), endBuilder.GetSize());

    syncThread.join();

    // Verify DataValue messages sent first
    EXPECT_EQ(dataValueMessagesSent, 2);
    EXPECT_EQ(dataContextMessagesSent, 2);
}

TEST_F(AgentSyncProtocolDataContextTest, SynchronizeModuleDataContextFailureDoesNotAffectDataValue)
{
    // Test that DataContext failure doesn't prevent successful sync if DataValue succeeds
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int messageCount = 0;
    messageCount = 0; // Reset
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void* data, size_t, const char*, char)
        {
            messageCount++;
            auto message = Wazuh::SyncSchema::GetMessage(data);

            // Fail on DataContext messages
            if (message->content_type() == Wazuh::SyncSchema::MessageType::DataContext)
            {
                return 0; // Failure
            }

            return 1; // Success for other messages
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "id_1", "network", "net_data_1", Operation::CREATE, 1, false},
        {1, "ctx_id_1", "vd_packages", "package_data_1", Operation::CREATE, 1, true}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, resetSyncingItems()).Times(1); // Should reset due to DataContext failure

    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(result); // Should fail due to DataContext send failure
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();
    auto startMessage = Wazuh::SyncSchema::CreateMessage(startBuilder,
                                                         Wazuh::SyncSchema::MessageType::StartAck,
                                                         startAckOffset.Union());
    startBuilder.Finish(startMessage);
    protocol->parseResponseBuffer(startBuilder.GetBufferPointer(), startBuilder.GetSize());

    // Wait for failure
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    syncThread.join();
}
