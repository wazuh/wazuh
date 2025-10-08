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
using ::testing::DoAll;

// IPersistentQueue Mock
class MockPersistentQueue : public IPersistentQueue
{
    public:
        MOCK_METHOD(void, submit, (const std::string& id,
                                   const std::string& index,
                                   const std::string& data,
                                   Operation operation), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (), (override));
        MOCK_METHOD(void, clearSyncedItems, (), (override));
        MOCK_METHOD(void, resetSyncingItems, (), (override));

};

class AgentSyncProtocolTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
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

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation))
    .Times(1);

    protocol->persistDifference(testId, testOperation, testIndex, testData);
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

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation))
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    EXPECT_NO_THROW(protocol->persistDifference(testId, testOperation, testIndex, testData));
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

    EXPECT_NO_THROW(protocol->persistDifferenceInMemory(testId, testOperation, testIndex, testData));
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
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1");
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2");

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
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1");

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
    EXPECT_NO_THROW(protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2"));
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
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
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1");
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2");
    protocol->persistDifferenceInMemory("memory_id_3", Operation::DELETE_, "memory_index_3", "memory_data_3");

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
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1");
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2");

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
    protocol->persistDifferenceInMemory("memory_id_3", Operation::CREATE, "memory_index_3", "memory_data_3");

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
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1");
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2");
    EXPECT_NO_THROW(protocol->clearInMemoryData());

    protocol->persistDifferenceInMemory("memory_id_3", Operation::DELETE_, "memory_index_3", "memory_data_3");
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_DELTA,
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_CHECK,
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_DELTA,
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_CHECK,
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
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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

    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_DELTA,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
    bool result = protocol->synchronizeMetadataOrGroups(
                      Mode::METADATA_CHECK,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::METADATA_DELTA,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
        bool result = protocol->synchronizeMetadataOrGroups(
                          Mode::GROUP_CHECK,
                          std::chrono::seconds(max_timeout),
                          retries,
                          maxEps
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
