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

class AgentSyncProtocolTest : public ::testing::Test
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

            // Set logger via asp_create
            MQ_Functions tmpMq
            {
                [](const char*, short, short) { return 0; },
                [](int, const void*, size_t, const char*, char)
                {
                    return 0;
                }
            };

            auto handle = asp_create(
                              "test_module",
                              ":memory:",
                              &tmpMq,
                              +[](modules_log_level_t, const char* s)
            {
                std::cout << s << std::endl;
            }
            , syncEndDelay, max_timeout, retries, maxEps);
            asp_destroy(handle);
        }

        void TearDown() override
        {
            // Reset metadata provider state for test isolation
            metadata_provider_reset();
        }

        std::shared_ptr<MockPersistentQueue> mockQueue;
        std::unique_ptr<AgentSyncProtocol> protocol;
        const uint64_t session = 1234;
        const uint64_t session2 = 5678;
        const unsigned int retries = 1;
        const unsigned int maxEps = 100;
        const unsigned int delay = 100;
        const unsigned int syncEndDelay = 1;
        const uint8_t min_timeout = 1;
        const uint8_t max_timeout = 3;
};

TEST_F(AgentSyncProtocolTest, PersistDifferenceSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion, false))
    .Times(1);

    protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion);
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceCatchesException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion, false))
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    EXPECT_NO_THROW(protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion));
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceInMemorySuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    const std::string testId = "memory_test_id";
    const std::string testIndex = "memory_test_index";
    const std::string testData = "memory_test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 456;

    EXPECT_NO_THROW(protocol->persistDifferenceInMemory(testId, testOperation, testIndex, testData, testVersion));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleNoQueueAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFetchAndMarkForSyncThrowsException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDataToSyncEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(std::vector<PersistedData> {}));

    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_TRUE(result);
}

// Tests for synchronizeModule with Mode::FULL (using in-memory data)
TEST_F(AgentSyncProtocolTest, SynchronizeModuleFullModeWithEmptyInMemoryData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    bool result = protocol->synchronizeModule(
                      Mode::FULL
                  );

    EXPECT_TRUE(result);  // Should return true for empty in-memory data
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFullModeWithInMemoryData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);

    // Expect NO calls to fetchAndMarkForSync since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Expect NO calls to clearSyncedItems or resetSyncingItems since FULL mode clears in-memory data
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Start synchronization in FULL mode
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::FULL
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFullModeFailureKeepsInMemoryData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);

    // Expect NO calls to database methods since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Simulate synchronization failure (timeout)
    bool result = protocol->synchronizeModule(
                      Mode::FULL
                  );

    EXPECT_FALSE(result);  // Should fail due to timeout

    // In-memory data should be kept for potential retry, so we can add more data
    EXPECT_NO_THROW(protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleInvalidModeValidation)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to any queue methods since validation should fail early
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Test invalid mode by casting an invalid integer to Mode enum
    Mode invalidMode = static_cast<Mode>(999);

    bool result = protocol->synchronizeModule(
                      invalidMode
                  );

    EXPECT_FALSE(result);  // Should fail due to invalid mode validation
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingSendStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return -1;    // Fail to send Start message
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStartFailDueToManager)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with ERROR status
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // syncFailed = true
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendDataMessagesFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingSendDataMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            callCount++;

            if (callCount > 1)
            {
                return -1; // Fail data messages
            }

            return 0; // Allow Start message to succeed
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendDataMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendEndFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingSendEndMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            callCount++;

            if (callCount > 3)
            {
                return -1; // Fail End message
            }

            return 0; // Allow Start and Data messages to succeed
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendEndMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndFailDueToManager)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // syncFailed = true
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with EMPTY ranges
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    // No seq ranges
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesDataEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with no valid data ranges
    // Test data seq numbers 1-2, but request ranges 10-15 and 20-25
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;

    // Range 10-15
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 10, 15);
    seqRanges.push_back(range1);

    // Range 20-25
    auto range2 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 20, 25);
    seqRanges.push_back(range2);

    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndDataResendFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingReqRetDataMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            callCount++;

            if (callCount > 4)
            {
                return -1; // Fail data resend for ReqRet
            }

            return 0; // Allow Start, initial Data messages and End
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingReqRetDataMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for initial data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;

    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);

    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithNoReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for initial data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;

    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);

    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    // Wait for data resend
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFinalizeSyncStateException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Failed to finalize sync state") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Create some sample data for synchronization to make it successful
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 0}
    };

    // Set up mock expectations for successful sync until the finalization phase
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    // The clearSyncedItems call will throw an exception
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .WillOnce(testing::Throw(std::runtime_error("Simulated clearSyncedItems exception")));

    // Start synchronization in background
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_TRUE(result); // Should still return true despite the exception in finalization
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();

    // Verify that the error was logged
    EXPECT_TRUE(loggedMessage.find("Failed to finalize sync state") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated clearSyncedItems exception") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithNullBuffer)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    bool response = protocol->parseResponseBuffer(nullptr, 0);

    EXPECT_FALSE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForStartAck)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with ERROR status
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // Status Error
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckOffline)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with OFFLINE status
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Offline); // Status Offline
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForEndAck)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    flatbuffers::FlatBufferBuilder builder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::EndAck,
                       endAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // Status Error
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckOffline)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OFFLINE status
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Offline); // Status Offline
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok); // Status Ok
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    flatbuffers::FlatBufferBuilder builder;

    // ReqRet message
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    auto range1 = Wazuh::SyncSchema::CreatePair(builder, 1, 2); // Range 1-2
    seqRanges.push_back(range1);
    auto seqRangesVector = builder.CreateVector(seqRanges);

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilder(builder);
    reqRetBuilder.add_session(session);
    reqRetBuilder.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::ReqRet,
                       reqRetOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetAndNoRanges)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with no ranges
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    // No seq field
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet
    flatbuffers::FlatBufferBuilder reqRetBuilder;

    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);

    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();

    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
                             reqRetBuilder,
                             Wazuh::SyncSchema::MessageType::ReqRet,
                             reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);

    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(reqRetBuffer, reqRetBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}


TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithUnknownMessageType)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    flatbuffers::FlatBufferBuilder builder;

    auto message = Wazuh::SyncSchema::CreateMessage(builder);
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_FALSE(response);
}

// Tests for requiresFullSync
TEST_F(AgentSyncProtocolTest, RequiresFullSyncWithMatchingChecksum)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "matching_checksum";

    // Expect NO calls to database methods since no data needs to be sent
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start requiresFullSync in a separate thread
    std::thread syncThread([this, &testIndex, &testChecksum]()
    {
        bool result = protocol->requiresFullSync(
                          testIndex,
                          testChecksum
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with matching checksum status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for checksum message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with matching checksum (Status::Ok)
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncWithNonMatchingChecksum)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "non_matching_checksum";

    // Expect NO calls to database methods since no data needs to be sent
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start requiresFullSync in a separate thread
    std::thread syncThread([this, &testIndex, &testChecksum]()
    {
        bool result = protocol->requiresFullSync(
                          testIndex,
                          testChecksum
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for checksum message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with non-matching checksum (Status::ChecksumMismatch indicates mismatch)
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::ChecksumMismatch);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncNoQueueAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingSendStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return -1;    // Fail to send Start message
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncSendChecksumMessageFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingChecksumMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            callCount++;

            if (callCount == 1)
            {
                // First call is Start message - let it succeed
                return 0;
            }
            else
            {
                // Second call is ChecksumModule message - make it fail
                return -1;
            }
        }
    };

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Failed to send ChecksumModule message") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingChecksumMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    // Start the integrity check in background
    std::thread syncThread([this, testIndex, testChecksum]()
    {
        bool result = protocol->requiresFullSync(
                          testIndex,
                          testChecksum
                      );
        EXPECT_FALSE(result); // Should fail due to ChecksumModule message failure
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status to get past the start phase
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    syncThread.join();

    // Verify that the error was logged
    EXPECT_TRUE(loggedMessage.find("Failed to send ChecksumModule message") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, EnsureQueueAvailableException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions throwingMqFuncs =
    {
        .start = [](const char*, short int, short int) -> int {
            throw std::runtime_error("Simulated MQ start exception");
        },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Exception when checking queue availability") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    // Try to synchronize, which should trigger ensureQueueAvailable() and catch the exception
    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result); // Should fail due to exception in ensureQueueAvailable

    // Verify that the exception error was logged
    EXPECT_TRUE(loggedMessage.find("Exception when checking queue availability") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated MQ start exception") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, SendStartAndWaitAckException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions throwingMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; }, // Let start succeed
        .send_binary = [](int, const void*, size_t, const char*, char) -> int
        {
            // Throw exception when trying to send the Start message
            throw std::runtime_error("Simulated send_binary exception in Start message");
            return -1; // This line will never be reached, but needed for compilation
        }
    };

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Exception when sending Start message") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    // Set up mock data for synchronization to trigger sendStartAndWaitAck
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    // Try to synchronize, which should trigger sendStartAndWaitAck and catch the exception
    bool result = protocol->synchronizeModule(
                      Mode::DELTA
                  );

    EXPECT_FALSE(result); // Should fail due to exception in sendStartAndWaitAck

    // Verify that the exception error was logged
    EXPECT_TRUE(loggedMessage.find("Exception when sending Start message") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated send_binary exception in Start message") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, SendDataMessagesException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions throwingMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; }, // Let start succeed
        .send_binary = [](int, const void*, size_t, const char*, char) -> int
        {
            callCount++;

            if (callCount == 1)
            {
                // First call is Start message - let it succeed
                return 0;
            }
            else
            {
                // Subsequent calls are Data messages - throw exception
                throw std::runtime_error("Simulated send_binary exception in Data message");
                return -1; // This line will never be reached, but needed for compilation
            }
        }
    };

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Exception when sending Data messages") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                   mockQueue);

    // Set up mock data for synchronization to trigger sendDataMessages
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    // Start synchronization in background
    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result); // Should fail due to exception in sendDataMessages
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status to get past the start phase
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    syncThread.join();

    // Verify that the exception error was logged
    EXPECT_TRUE(loggedMessage.find("Exception when sending Data messages") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated send_binary exception in Data message") != std::string::npos);
}

// Tests for clearInMemoryData
TEST_F(AgentSyncProtocolTest, ClearInMemoryDataWithEmptyData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Clear empty in-memory data should not throw
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

TEST_F(AgentSyncProtocolTest, ClearInMemoryDataWithData)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);
    protocol->persistDifferenceInMemory("memory_id_3", Operation::DELETE_, "memory_index_3", "memory_data_3", 3);

    // Clear in-memory data should not throw
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

TEST_F(AgentSyncProtocolTest, ClearInMemoryDataAfterFailedFullSync)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);

    // Expect NO calls to database methods since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Simulate synchronization failure (timeout)
    bool result = protocol->synchronizeModule(
                      Mode::FULL
                  );

    EXPECT_FALSE(result);  // Should fail due to timeout

    // Clear in-memory data after failed sync
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    // Verify data is cleared by attempting to add new data and sync with empty state
    protocol->persistDifferenceInMemory("memory_id_3", Operation::CREATE, "memory_index_3", "memory_data_3", 3);

    // This should work without issues
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

TEST_F(AgentSyncProtocolTest, ClearInMemoryDataMultipleTimes)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Add data and clear multiple times
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    protocol->persistDifferenceInMemory("memory_id_3", Operation::DELETE_, "memory_index_3", "memory_data_3", 3);
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    // Clear on already empty data
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

// Tests for synchronizeMetadataOrGroups
TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithMetadataDeltaMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_DELTA,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithMetadataCheckMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_CHECK,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupDeltaMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_DELTA,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupCheckMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_CHECK,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_TRUE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithInvalidMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Try with Mode::DELTA (not allowed for synchronizeMetadataOrGroups)
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::DELTA,
                      testIndices,
                      12345 // globalVersion
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithFailedQueueStart)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_DELTA,
                      testIndices,
                      12345 // globalVersion
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    // Don't send any response, causing timeout
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_CHECK,
                      testIndices,
                      12345 // globalVersion
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_DELTA,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Don't send EndAck, causing timeout

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithStartAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_DELTA,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with Error status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_CHECK,
                          testIndices,
                          12345 // globalVersion
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with Error status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

// Tests for deleteDatabase
TEST_F(AgentSyncProtocolTest, DeleteDatabaseCallsQueueDeleteDatabase)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .Times(1);

    EXPECT_NO_THROW(protocol->deleteDatabase());
}

TEST_F(AgentSyncProtocolTest, DeleteDatabaseThrowsOnQueueError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    bool errorLogged = false;
    std::string loggedMessage;
    LoggerFunc testLogger = [&errorLogged, &loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Failed to delete database") != std::string::npos)
        {
            errorLogged = true;
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .WillOnce(::testing::Throw(std::runtime_error("Database deletion failed")));

    EXPECT_NO_THROW(protocol->deleteDatabase());
    EXPECT_TRUE(errorLogged);
    EXPECT_NE(loggedMessage.find("Database deletion failed"), std::string::npos);
}

// Tests for notifyDataClean
TEST_F(AgentSyncProtocolTest, NotifyDataCleanWithEmptyIndices)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> emptyIndices;

    // Should not call any queue methods with empty indices
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(emptyIndices);

    EXPECT_FALSE(result); // Should fail with empty indices
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanNoQueueAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Queue start fails
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when queue is not available
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingSendMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return -1; // Send fails
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendMqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps,
                                                   mockQueue);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when send fails
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result); // Should fail due to timeout
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to manager error
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with ERROR status
    flatbuffers::FlatBufferBuilder builder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto message = Wazuh::SyncSchema::CreateMessage(
                       builder,
                       Wazuh::SyncSchema::MessageType::StartAck,
                       startAckOffset.Union());
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer, builder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to timeout
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Don't send EndAck to cause timeout
    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to manager error
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanClearItemsByIndexThrows)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called but throw exception
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .WillOnce(::testing::Throw(std::runtime_error("Clear items failed")));

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to clearItemsByIndex exception
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithSingleIndex)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called once for successful notification
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_TRUE(result); // Should succeed
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithMultipleIndices)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(min_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1", "test_index_2", "test_index_3"};

    // clearItemsByIndex should be called once for each index
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_2"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_3"))
    .Times(1);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_TRUE(result); // Should succeed
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder,
                          Wazuh::SyncSchema::MessageType::EndAck,
                          endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSendDataCleanMessagesException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    // Create a custom MQ_Functions that will cause an exception during data clean message sending
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void* data, size_t size, const char*, char)
        {
            (void)data; // Suppress unused parameter warning
            (void)size; // Suppress unused parameter warning
            // Allow StartAck to succeed, but fail on DataClean messages
            static int callCount = 0;
            callCount++;

            if (callCount == 1)
            {
                // First call is Start message - let it succeed
                return 1;
            }
            else
            {
                // Subsequent calls are DataClean messages - simulate an exception
                // This will trigger the catch block in sendDataCleanMessages
                throw std::bad_alloc(); // Simulate memory allocation failure
            }
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when sendDataCleanMessages throws
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to exception in sendDataCleanMessages
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status to get past the start phase
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for the exception to occur during DataClean message sending
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 2));

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SendChecksumMessageException)
{
    // Test that exceptions in sendChecksumMessage are properly caught and logged
    // Uses requiresFullSync which calls sendChecksumMessage internally

    mockQueue = std::make_shared<MockPersistentQueue>();

    // Create protocol with throwing message queue function
    static int callCount = 0;
    callCount = 0; // Reset counter for this test

    MQ_Functions throwingMq
    {
        .start = [](const char*, short, short) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) -> int
        {
            callCount++;
            // Always throw an exception to trigger the catch block
            throw std::runtime_error("Simulated ChecksumModule message exception");
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    auto testProtocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMq, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                            mockQueue);

    std::string index = "test_index";
    std::string checksum = "test_checksum";

    // This should trigger the exception and catch block through requiresFullSync
    bool result = testProtocol->requiresFullSync(index, checksum);

    // The method should return false when an exception occurs
    EXPECT_FALSE(result);

    // Verify the message sending function was called (causing the exception)
    EXPECT_GT(callCount, 0);
}

TEST_F(AgentSyncProtocolTest, SendEndMessageException)
{
    // Test that exceptions in sendEndAndWaitAck are properly caught and logged
    // Uses synchronizeModule which calls sendEndAndWaitAck internally

    mockQueue = std::make_shared<MockPersistentQueue>();

    // Create protocol with throwing message queue function that fails on End message
    static int callCount = 0;
    callCount = 0; // Reset counter for this test

    MQ_Functions throwingMq
    {
        .start = [](const char*, short, short) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) -> int
        {
            callCount++;
            // Let Start and Data messages succeed, but throw on End message (3rd call)
            if (callCount <= 2)
            {
                return 0; // Success for Start and Data messages
            }
            else
            {
                // Always throw an exception to trigger the catch block in sendEndAndWaitAck
                throw std::runtime_error("Simulated End message exception");
            }
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    auto testProtocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMq, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps,
                                                            mockQueue);

    // Set up mock data for synchronization
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    // Start synchronization in background to trigger sendEndAndWaitAck
    std::thread syncThread([&testProtocol, this]()
    {
        bool result = testProtocol->synchronizeModule(
                          Mode::DELTA
                      );
        EXPECT_FALSE(result); // Should fail due to exception in sendEndAndWaitAck
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status to get past the start phase
    flatbuffers::FlatBufferBuilder startBuilder;
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder,
                            Wazuh::SyncSchema::MessageType::StartAck,
                            startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    testProtocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for the exception to occur during End message sending
    std::this_thread::sleep_for(std::chrono::milliseconds(delay * 3));

    syncThread.join();

    // Verify the message sending function was called enough times (Start, Data, End)
    EXPECT_GT(callCount, 2);
}

// ============================================================================
// Tests for Optional Database Path (No Persistence Mode)
// ============================================================================

TEST_F(AgentSyncProtocolTest, ConstructionWithoutDbPathSuccess)
{
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Construct without dbPath
    EXPECT_NO_THROW(
    {
        protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, mqFuncs, testLogger,
                                                       std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout),
                                                       retries, maxEps, nullptr);
    });
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceLogsErrorWithoutQueue)
{
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath and without queue
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout),
                                                   retries, maxEps, nullptr);

    // persistDifference should log error when no queue is available
    protocol->persistDifference("id1", Operation::CREATE, "index1", "data1", 1);

    // Verify error was logged
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to persist item") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, DeltaModeSyncLogsErrorWithoutQueue)
{
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout),
                                                   retries, maxEps, nullptr);

    // DELTA mode should return false and log error when no queue is available
    bool result = protocol->synchronizeModule(Mode::DELTA);

    EXPECT_FALSE(result);
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to fetch items for sync") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanLogsErrorWithoutQueue)
{
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 1; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };

    // Capture logger output
    std::vector<std::string> loggedMessages;
    std::vector<modules_log_level_t> loggedLevels;
    LoggerFunc testLogger = [&loggedMessages, &loggedLevels](modules_log_level_t level, const std::string & msg)
    {
        loggedLevels.push_back(level);
        loggedMessages.push_back(msg);
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, mqFuncs, testLogger, std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout), retries, maxEps, nullptr);

    std::vector<std::string> indices = {"test_index_1"};

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to clearItemsByIndex exception
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck with OK status
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder, Wazuh::SyncSchema::MessageType::StartAck, startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for DataClean to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage = Wazuh::SyncSchema::CreateMessage(
                          endBuilder, Wazuh::SyncSchema::MessageType::EndAck, endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    syncThread.join();

    // Verify error was logged
    bool foundError = false;

    for (const auto& msg : loggedMessages)
    {
        if (msg.find("Failed to clear items by index") != std::string::npos ||
                msg.find("requires a persistent queue") != std::string::npos)
        {
            foundError = true;
            break;
        }
    }

    EXPECT_TRUE(foundError);
}

TEST_F(AgentSyncProtocolTest, DeleteDatabaseLogsErrorWithoutQueue)
{
    MQ_Functions mqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, mqFuncs, testLogger,
                                                   std::chrono::seconds(syncEndDelay), std::chrono::seconds(max_timeout),
                                                   retries, maxEps, nullptr);

    // deleteDatabase should log error when no queue is available
    protocol->deleteDatabase();

    // Verify error was logged
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to delete database") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckChecksumMismatch)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {.start = [](const char*, short int, short int) { return 0; },
    .send_binary =
        [](int, const void*, size_t, const char*, char)
    {
        return 0;
    }
                           };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module",
                                                   ":memory:",
                                                   mqFuncs,
                                                   testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries,
                                                   maxEps,
                                                   mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));

        bool syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult);
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder2;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder2(startBuilder2);
    startAckBuilder2.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder2.add_session(session);
    auto startAckOffset2 = startAckBuilder2.Finish();

    auto startMessage2 = Wazuh::SyncSchema::CreateMessage(
                             startBuilder2, Wazuh::SyncSchema::MessageType::StartAck, startAckOffset2.Union());
    startBuilder2.Finish(startMessage2);

    const uint8_t* startBuffer2 = startBuilder2.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer2, startBuilder2.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ChecksumMismatch status
    flatbuffers::FlatBufferBuilder endBuilder2;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder2(endBuilder2);
    endAckBuilder2.add_status(Wazuh::SyncSchema::Status::ChecksumMismatch); // Status ChecksumMismatch
    endAckBuilder2.add_session(session);
    auto endAckOffset2 = endAckBuilder2.Finish();

    auto endMessage2 =
        Wazuh::SyncSchema::CreateMessage(endBuilder2, Wazuh::SyncSchema::MessageType::EndAck, endAckOffset2.Union());
    endBuilder2.Finish(endMessage2);

    const uint8_t* endBuffer2 = endBuilder2.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer2, endBuilder2.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckGenericError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {.start = [](const char*, short int, short int) { return 0; },
    .send_binary =
        [](int, const void*, size_t, const char*, char)
    {
        return 0;
    }
                           };
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module",
                                                   ":memory:",
                                                   mqFuncs,
                                                   testLogger,
                                                   std::chrono::seconds(syncEndDelay),
                                                   std::chrono::seconds(max_timeout),
                                                   retries,
                                                   maxEps,
                                                   mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).WillOnce(Return(testData));

        bool syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult);
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;

    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    auto startAckOffset = startAckBuilder.Finish();

    auto startMessage = Wazuh::SyncSchema::CreateMessage(
                            startBuilder, Wazuh::SyncSchema::MessageType::StartAck, startAckOffset.Union());
    startBuilder.Finish(startMessage);

    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer, startBuilder.GetSize());

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with Error status (which should map to GENERIC_ERROR)
    flatbuffers::FlatBufferBuilder endBuilder;

    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // Status Error
    endAckBuilder.add_session(session);
    auto endAckOffset = endAckBuilder.Finish();

    auto endMessage =
        Wazuh::SyncSchema::CreateMessage(endBuilder, Wazuh::SyncSchema::MessageType::EndAck, endAckOffset.Union());
    endBuilder.Finish(endMessage);

    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer, endBuilder.GetSize());

    EXPECT_TRUE(response);

    syncThread.join();
}

// Test to cover IAgentSyncProtocol D0 destructor (delete through base pointer)
TEST(InterfaceDestructorTest, IAgentSyncProtocolDeletingDestructor)
{
    // Create concrete implementation through base interface pointer
    IAgentSyncProtocol* protocol = nullptr;

    // Set up mock queue
    auto mockQueue = std::make_shared<MockPersistentQueue>();

    // Create mock MQ functions
    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 1; },
        [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Create AgentSyncProtocol through base interface pointer
    protocol = new AgentSyncProtocol("test_module", std::nullopt, mockMq, testLogger, std::chrono::seconds(1), std::chrono::seconds(1000), 1, 100, mockQueue);

    // Delete through base pointer - this calls D0 destructor
    delete protocol;
}

// ========================================
// Tests for fetchPendingItems()
// ========================================

TEST_F(AgentSyncProtocolTest, fetchPendingItems_WithNullPersistentQueue)
{
    /**
     * Test: fetchPendingItems should throw when persistent queue is null
     * This happens when AgentSyncProtocol is initialized without a dbPath
     */

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Create AgentSyncProtocol WITHOUT persistent queue (dbPath = std::nullopt)
    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        std::nullopt,  // No dbPath - persistent queue will be null
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        nullptr  // No persistent queue
    );

    // fetchPendingItems should catch exception and return empty vector
    auto result = protocol->fetchPendingItems(true);

    EXPECT_TRUE(result.empty());
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_OnlyDataValues_True)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=true
     * Should fetch only DataValue items (not DataContext)
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare test data - DataValue items only
    std::vector<PersistedData> expectedData;
    PersistedData item1;
    item1.seq = 1;
    item1.id = "hash_id_1";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({"name":"package1","version":"1.0"})";
    item1.operation = Operation::CREATE;
    expectedData.push_back(item1);

    PersistedData item2;
    item2.seq = 2;
    item2.id = "hash_id_2";
    item2.index = "wazuh-states-inventory-system";
    item2.data = R"({"hostname":"test-host"})";
    item2.operation = Operation::MODIFY;
    expectedData.push_back(item2);

    // Mock fetchPendingItems to return DataValue items
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems with onlyDataValues=true
    auto result = protocol->fetchPendingItems(true);

    // Verify results
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[0].id, "hash_id_1");
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-packages");
    EXPECT_EQ(result[0].operation, Operation::CREATE);
    EXPECT_EQ(result[1].seq, 2);
    EXPECT_EQ(result[1].id, "hash_id_2");
    EXPECT_EQ(result[1].index, "wazuh-states-inventory-system");
    EXPECT_EQ(result[1].operation, Operation::MODIFY);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_OnlyDataValues_False)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=false
     * Should fetch both DataValue AND DataContext items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare test data - Mix of DataValue and DataContext
    std::vector<PersistedData> expectedData;
    
    // DataValue item
    PersistedData dataValue;
    dataValue.seq = 1;
    dataValue.id = "hash_id_1";
    dataValue.index = "wazuh-states-inventory-packages";
    dataValue.data = R"({"name":"package1","version":"1.0"})";
    dataValue.operation = Operation::CREATE;
    expectedData.push_back(dataValue);

    // DataContext item
    PersistedData dataContext;
    dataContext.seq = 2;
    dataContext.id = "hash_id_2";
    dataContext.index = "wazuh-states-inventory-system";
    dataContext.data = R"({"hostname":"test-host"})";
    dataContext.operation = Operation::MODIFY;
    expectedData.push_back(dataContext);

    // Mock fetchPendingItems to return both types
    EXPECT_CALL(*mockQueue, fetchPendingItems(false))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems with onlyDataValues=false
    auto result = protocol->fetchPendingItems(false);

    // Verify results include both types
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[1].seq, 2);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_EmptyQueue)
{
    /**
     * Test: fetchPendingItems returns empty vector when queue is empty
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Mock fetchPendingItems to return empty vector
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(std::vector<PersistedData>()));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify result is empty
    EXPECT_TRUE(result.empty());
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_MultipleIndices)
{
    /**
     * Test: fetchPendingItems correctly returns items from multiple indices
     * Tests packages, system, and hotfixes indices
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare test data from multiple indices
    std::vector<PersistedData> expectedData;
    
    PersistedData pkgItem;
    pkgItem.seq = 1;
    pkgItem.id = "pkg_hash_1";
    pkgItem.index = "wazuh-states-inventory-packages";
    pkgItem.data = R"({"name":"vim","version":"8.2"})";
    pkgItem.operation = Operation::CREATE;
    expectedData.push_back(pkgItem);

    PersistedData sysItem;
    sysItem.seq = 2;
    sysItem.id = "sys_hash_1";
    sysItem.index = "wazuh-states-inventory-system";
    sysItem.data = R"({"os_name":"Ubuntu","os_version":"22.04"})";
    sysItem.operation = Operation::MODIFY;
    expectedData.push_back(sysItem);

    PersistedData hfItem;
    hfItem.seq = 3;
    hfItem.id = "hf_hash_1";
    hfItem.index = "wazuh-states-inventory-hotfixes";
    hfItem.data = R"({"hotfix":"KB123456"})";
    hfItem.operation = Operation::CREATE;
    expectedData.push_back(hfItem);

    // Mock fetchPendingItems to return items from all indices
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify all items are returned
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-packages");
    EXPECT_EQ(result[1].index, "wazuh-states-inventory-system");
    EXPECT_EQ(result[2].index, "wazuh-states-inventory-hotfixes");
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_DifferentOperations)
{
    /**
     * Test: fetchPendingItems correctly preserves operation types
     * Tests CREATE, MODIFY, and DELETE operations
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare test data with different operations
    std::vector<PersistedData> expectedData;
    
    PersistedData createItem;
    createItem.seq = 1;
    createItem.id = "create_hash";
    createItem.index = "wazuh-states-inventory-packages";
    createItem.data = R"({"name":"new-package"})";
    createItem.operation = Operation::CREATE;
    expectedData.push_back(createItem);

    PersistedData modifyItem;
    modifyItem.seq = 2;
    modifyItem.id = "modify_hash";
    modifyItem.index = "wazuh-states-inventory-packages";
    modifyItem.data = R"({"name":"updated-package"})";
    modifyItem.operation = Operation::MODIFY;
    expectedData.push_back(modifyItem);

    PersistedData deleteItem;
    deleteItem.seq = 3;
    deleteItem.id = "delete_hash";
    deleteItem.index = "wazuh-states-inventory-packages";
    deleteItem.data = R"({"name":"removed-package"})";
    deleteItem.operation = Operation::DELETE_;
    expectedData.push_back(deleteItem);

    // Mock fetchPendingItems
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify operations are preserved
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].operation, Operation::CREATE);
    EXPECT_EQ(result[1].operation, Operation::MODIFY);
    EXPECT_EQ(result[2].operation, Operation::DELETE_);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_ExceptionHandling)
{
    /**
     * Test: fetchPendingItems handles exceptions and returns empty vector
     * Verifies graceful error handling when persistent queue throws
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    bool loggerCalled = false;
    LoggerFunc testLogger = [&loggerCalled](modules_log_level_t level, const std::string& msg) {
        if (level == LOG_ERROR && msg.find("Failed to fetch pending items") != std::string::npos)
        {
            loggerCalled = true;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Mock fetchPendingItems to throw exception
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(testing::Throw(std::runtime_error("Database error")));

    // Call fetchPendingItems - should catch exception and return empty
    auto result = protocol->fetchPendingItems(true);

    // Verify error handling
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(loggerCalled);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_LargeDataSet)
{
    /**
     * Test: fetchPendingItems handles large number of items
     * Verifies performance and correctness with many items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare large dataset (1000 items)
    std::vector<PersistedData> expectedData;
    for (int i = 0; i < 1000; ++i)
    {
        PersistedData item;
        item.seq = i + 1;
        item.id = "hash_id_" + std::to_string(i);
        item.index = "wazuh-states-inventory-packages";
        item.data = R"({"name":"package)" + std::to_string(i) + R"("})";
        item.operation = Operation::CREATE;
        expectedData.push_back(item);
    }

    // Mock fetchPendingItems to return large dataset
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify all items are returned correctly
    ASSERT_EQ(result.size(), 1000);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[999].seq, 1000);
    EXPECT_EQ(result[0].id, "hash_id_0");
    EXPECT_EQ(result[999].id, "hash_id_999");
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_SequenceNumberOrdering)
{
    /**
     * Test: fetchPendingItems returns items in correct sequence order
     * Verifies sequence numbers are properly maintained
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mockMq
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
        "test_module",
        ":memory:",
        mockMq,
        testLogger,
        std::chrono::seconds(1),
        std::chrono::seconds(1),
        retries,
        maxEps,
        mockQueue
    );

    // Prepare test data with specific sequence numbers
    std::vector<PersistedData> expectedData;
    
    PersistedData item1;
    item1.seq = 100;
    item1.id = "hash_100";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({})";
    item1.operation = Operation::CREATE;
    expectedData.push_back(item1);

    PersistedData item2;
    item2.seq = 101;
    item2.id = "hash_101";
    item2.index = "wazuh-states-inventory-packages";
    item2.data = R"({})";
    item2.operation = Operation::CREATE;
    expectedData.push_back(item2);

    PersistedData item3;
    item3.seq = 102;
    item3.id = "hash_102";
    item3.index = "wazuh-states-inventory-packages";
    item3.data = R"({})";
    item3.operation = Operation::CREATE;
    expectedData.push_back(item3);

    // Mock fetchPendingItems
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify sequence ordering is maintained
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].seq, 100);
    EXPECT_EQ(result[1].seq, 101);
    EXPECT_EQ(result[2].seq, 102);
}

// ========================================
// Tests for clearAllDataContext()
// ========================================

TEST_F(AgentSyncProtocolTest, clearAllDataContext_WithValidQueue)
{
    /**
     * Test: clearAllDataContext should call clearAllDataContext on the persistent queue
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   std::nullopt,
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    // Expect clearAllDataContext to be called once
    EXPECT_CALL(*mockQueue, clearAllDataContext())
        .Times(1);

    // Call clearAllDataContext
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

TEST_F(AgentSyncProtocolTest, clearAllDataContext_WithNullQueue)
{
    /**
     * Test: clearAllDataContext should handle null persistent queue gracefully
     */

    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   std::nullopt,
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   nullptr
               );

    // Should not throw when queue is null
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

TEST_F(AgentSyncProtocolTest, clearAllDataContext_ExceptionHandling)
{
    /**
     * Test: clearAllDataContext should handle exceptions from the persistent queue
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   std::nullopt,
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    // Make clearAllDataContext throw an exception
    EXPECT_CALL(*mockQueue, clearAllDataContext())
        .Times(1)
        .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Should handle exception gracefully
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

// ========================================
// Tests for notifyDataClean() with Option parameter
// ========================================

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithSyncOption_EmptyIndices)
{
    /**
     * Test: notifyDataClean should return false when indices vector is empty
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    std::vector<std::string> emptyIndices;

    // Should return false for empty indices
    bool result = protocol->notifyDataClean(emptyIndices, Option::SYNC);
    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithVDCLEANOption_SingleIndex)
{
    /**
     * Test: notifyDataClean should accept VDCLEAN option for VD indices
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    std::vector<std::string> vdIndices = {"wazuh-states-vulnerabilities"};

    // We can't fully test the send without a real transport, but we can verify it doesn't crash
    // and handles the VDCLEAN option parameter correctly
    EXPECT_NO_THROW(protocol->notifyDataClean(vdIndices, Option::VDCLEAN));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithSyncOption_MultipleIndices)
{
    /**
     * Test: notifyDataClean should handle multiple indices with SYNC option
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    std::vector<std::string> indices =
    {
        "wazuh-states-inventory-hardware",
        "wazuh-states-inventory-ports",
        "wazuh-states-inventory-networks"
    };

    // Should handle multiple indices
    EXPECT_NO_THROW(protocol->notifyDataClean(indices, Option::SYNC));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithVDCLEANOption_VDIndices)
{
    /**
     * Test: notifyDataClean with VDCLEAN option for VD-specific indices
     * This simulates the VD sync protocol cleaning VD data
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "syscollector_vd",  // VD module name
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    std::vector<std::string> vdIndices =
    {
        "wazuh-states-inventory-system",    // OS
        "wazuh-states-inventory-packages",  // Packages
        "wazuh-states-inventory-hotfixes"   // Hotfixes
    };

    // Should handle VD indices with VDCLEAN option
    EXPECT_NO_THROW(protocol->notifyDataClean(vdIndices, Option::VDCLEAN));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_DefaultOption)
{
    /**
     * Test: notifyDataClean should use SYNC as default option when not specified
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    std::vector<std::string> indices = {"wazuh-states-inventory-hardware"};

    // Should use default SYNC option
    EXPECT_NO_THROW(protocol->notifyDataClean(indices));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithNullQueue)
{
    /**
     * Test: notifyDataClean should handle null persistent queue
     */

    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "test_module",
                   std::nullopt,
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   nullptr
               );

    std::vector<std::string> indices = {"wazuh-states-inventory-hardware"};

    // Should handle null queue gracefully
    EXPECT_NO_THROW(protocol->notifyDataClean(indices, Option::SYNC));
}

// ========================================
// Tests for Option enum conversions
// ========================================

TEST_F(AgentSyncProtocolTest, Option_SYNC_Value)
{
    /**
     * Test: Verify Option::SYNC has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::SYNC), OPTION_SYNC);
}

TEST_F(AgentSyncProtocolTest, Option_VDFIRST_Value)
{
    /**
     * Test: Verify Option::VDFIRST has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::VDFIRST), OPTION_VD_FIRST);
}

TEST_F(AgentSyncProtocolTest, Option_VDCLEAN_Value)
{
    /**
     * Test: Verify Option::VDCLEAN has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::VDCLEAN), OPTION_VD_CLEAN);
}

TEST_F(AgentSyncProtocolTest, Option_VDSYNC_Value)
{
    /**
     * Test: Verify Option::VDSYNC has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::VDSYNC), OPTION_VD_SYNC);
}

// ========================================
// Integration tests for VD workflow
// ========================================

TEST_F(AgentSyncProtocolTest, VDWorkflow_ClearDataContextBeforeSync)
{
    /**
     * Test: VD workflow should clear DataContext before synchronization
     * This simulates the workflow in processVDDataContext()
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "syscollector_vd",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    // Step 1: Clear all DataContext
    EXPECT_CALL(*mockQueue, clearAllDataContext())
        .Times(1);

    protocol->clearAllDataContext();

    // Step 2: Fetch pending DataValue items (onlyDataValues=true)
    std::vector<PersistedData> dataValues;
    PersistedData item1;
    item1.seq = 0;
    item1.id = "pkg1";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({"name":"test-pkg"})";
    item1.operation = Operation::CREATE;
    item1.is_data_context = false;
    dataValues.push_back(item1);

    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(dataValues));

    auto result = protocol->fetchPendingItems(true);
    ASSERT_EQ(result.size(), 1);
    EXPECT_FALSE(result[0].is_data_context);
}

TEST_F(AgentSyncProtocolTest, VDWorkflow_FetchOnlyDataValues)
{
    /**
     * Test: VD workflow should be able to fetch only DataValue items
     * excluding DataContext items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs
    {
        [](const char*, short, short) { return 0; },
        [](int, const void*, size_t, const char*, char) { return 0; }
    };

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>(
                   "syscollector_vd",
                   ":memory:",
                   mqFuncs,
                   logger,
                   std::chrono::seconds(syncEndDelay),
                   std::chrono::seconds(max_timeout),
                   retries,
                   maxEps,
                   mockQueue
               );

    // Create mixed data (DataValue and DataContext)
    std::vector<PersistedData> allData;

    PersistedData dataValue;
    dataValue.seq = 0;
    dataValue.id = "os1";
    dataValue.index = "wazuh-states-inventory-system";
    dataValue.data = R"({"os_name":"Linux"})";
    dataValue.operation = Operation::MODIFY;
    dataValue.is_data_context = false;
    allData.push_back(dataValue);

    PersistedData dataContext;
    dataContext.seq = 1;
    dataContext.id = "ctx1";
    dataContext.index = "wazuh-states-inventory-packages";
    dataContext.data = R"({"context":"data"})";
    dataContext.operation = Operation::MODIFY;
    dataContext.is_data_context = true;
    allData.push_back(dataContext);

    // When fetching only DataValues, should return only non-context items
    std::vector<PersistedData> onlyDataValues = {dataValue};

    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
        .Times(1)
        .WillOnce(Return(onlyDataValues));

    auto result = protocol->fetchPendingItems(true);
    ASSERT_EQ(result.size(), 1);
    EXPECT_FALSE(result[0].is_data_context);
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-system");
}
