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
                                   uint64_t version), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (), (override));
        MOCK_METHOD(void, clearSyncedItems, (), (override));
        MOCK_METHOD(void, resetSyncingItems, (), (override));
        MOCK_METHOD(void, clearItemsByIndex, (const std::string& index), (override));
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
            metadata.groups = nullptr;
            metadata.groups_count = 0;
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
                          );
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion))
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion))
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, mockQueue);

    bool result = protocol->synchronizeModule(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    bool result = protocol->synchronizeModule(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(Return(std::vector<PersistedData> {}));

    bool result = protocol->synchronizeModule(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Expect NO calls to fetchAndMarkForSync since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    bool result = protocol->synchronizeModule(
                      Mode::FULL,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::FULL,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);

    // Expect NO calls to database methods since FULL mode uses in-memory data
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Simulate synchronization failure (timeout)
    bool result = protocol->synchronizeModule(
                      Mode::FULL,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                      invalidMode,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendStartMqFuncs, testLogger, mockQueue);

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
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendDataMqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendEndMqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingReqRetDataMqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
        bool result = protocol->synchronizeModule(Mode::DELTA, std::chrono::seconds(max_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          testChecksum,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          testChecksum,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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

    // EndAck with non-matching checksum (Status::Error indicates mismatch)
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendStartMqFuncs, testLogger, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingChecksumMqFuncs, testLogger, mockQueue);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    // Start the integrity check in background
    std::thread syncThread([this, testIndex, testChecksum]()
    {
        bool result = protocol->requiresFullSync(
                          testIndex,
                          testChecksum,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, mockQueue);

    // Try to synchronize, which should trigger ensureQueueAvailable() and catch the exception
    bool result = protocol->synchronizeModule(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, mockQueue);

    // Set up mock data for synchronization to trigger sendStartAndWaitAck
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    // Try to synchronize, which should trigger sendStartAndWaitAck and catch the exception
    bool result = protocol->synchronizeModule(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMqFuncs, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                      Mode::FULL,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Try with Mode::DELTA (not allowed for synchronizeMetadataOrGroups)
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::DELTA,
                      testIndices,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, mockQueue);

    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_DELTA,
                      testIndices,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Don't send any response, causing timeout
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_CHECK,
                      testIndices,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_DELTA,
                          testIndices,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_DELTA,
                          testIndices,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_CHECK,
                          testIndices,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps,
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    LoggerFunc testLogger = [&errorLogged, &loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Failed to delete database") != std::string::npos)
        {
            errorLogged = true;
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> emptyIndices;

    // Should not call any queue methods with empty indices
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(emptyIndices, std::chrono::seconds(min_timeout), retries, maxEps);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingStartMqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when queue is not available
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", failingSendMqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when send fails
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called but throw exception
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .WillOnce(::testing::Throw(std::runtime_error("Clear items failed")));

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called once for successful notification
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

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
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", mqFuncs, testLogger, mockQueue);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when sendDataCleanMessages throws
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
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
    auto testProtocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMq, testLogger, mockQueue);

    std::string index = "test_index";
    std::string checksum = "test_checksum";

    // This should trigger the exception and catch block through requiresFullSync
    bool result = testProtocol->requiresFullSync(index, checksum, std::chrono::seconds(1), retries, maxEps);

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
    auto testProtocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", throwingMq, testLogger, mockQueue);

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
                          Mode::DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
