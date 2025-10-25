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

            mockQueue = std::make_shared<MockPersistentQueue>();
        }

        std::shared_ptr<MockPersistentQueue> mockQueue;
        std::unique_ptr<AgentSyncProtocol> protocol;
        const uint64_t session = 1234;
        const uint64_t session2 = 5678;
        const unsigned int retries = 1;
        const unsigned int maxEps = 100;
        const unsigned int delay = 1000;
        const uint8_t min_timeout = 1;
        const uint8_t max_timeout = 3;

        LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {
        };

        MQ_Functions mqFuncs = {.start = [](const char*, short int, short int) { return 0; },
                                .send_binary =
                                    [](int, const void*, size_t, const char*, char)
                                {
                                    return 0;
                                }};

        MQ_Functions failingSendMqFuncs = {.start = [](const char*, short int, short int) { return 1; },
                                           .send_binary =
                                               [](int, const void*, size_t, const char*, char)
                                           {
                                               return 1; // Send fails
                                           }};

        // Helper methods to reduce code duplication

        // Helper to create and send StartAck message
        void sendStartAck(Wazuh::SyncSchema::Status status = Wazuh::SyncSchema::Status::Ok,
                          uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            flatbuffers::FlatBufferBuilder builder;
            Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
            startAckBuilder.add_status(status);
            startAckBuilder.add_session(sessionId);
            auto startAckOffset = startAckBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               builder,
                               Wazuh::SyncSchema::MessageType::StartAck,
                               startAckOffset.Union());
            builder.Finish(message);

            const uint8_t* buffer = builder.GetBufferPointer();
            protocol->parseResponseBuffer(buffer, builder.GetSize());
        }

        // Helper to create and send EndAck message
        void sendEndAck(Wazuh::SyncSchema::Status status = Wazuh::SyncSchema::Status::Ok,
                        uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            flatbuffers::FlatBufferBuilder builder;
            Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
            endAckBuilder.add_status(status);
            endAckBuilder.add_session(sessionId);
            auto endAckOffset = endAckBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               builder,
                               Wazuh::SyncSchema::MessageType::EndAck,
                               endAckOffset.Union());
            builder.Finish(message);

            const uint8_t* buffer = builder.GetBufferPointer();
            protocol->parseResponseBuffer(buffer, builder.GetSize());
        }

        // Helper to create and send ReqRet message with sequence ranges
        void sendReqRet(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                        uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            flatbuffers::FlatBufferBuilder builder;
            std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;

            for (const auto& range : ranges)
            {
                auto pairOffset = Wazuh::SyncSchema::CreatePair(builder, range.first, range.second);
                seqRanges.push_back(pairOffset);
            }

            auto seqRangesVector = builder.CreateVector(seqRanges);

            Wazuh::SyncSchema::ReqRetBuilder reqRetBuilder(builder);
            reqRetBuilder.add_session(sessionId);
            reqRetBuilder.add_seq(seqRangesVector);
            auto reqRetOffset = reqRetBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               builder,
                               Wazuh::SyncSchema::MessageType::ReqRet,
                               reqRetOffset.Union());
            builder.Finish(message);

            const uint8_t* buffer = builder.GetBufferPointer();
            protocol->parseResponseBuffer(buffer, builder.GetSize());
        }

        // Helper to build StartAck message and return buffer (for direct parseResponseBuffer testing)
        std::pair<std::vector<uint8_t>, size_t> buildStartAck(
            Wazuh::SyncSchema::Status status = Wazuh::SyncSchema::Status::Ok,
            uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            auto builder = std::make_shared<flatbuffers::FlatBufferBuilder>();
            Wazuh::SyncSchema::StartAckBuilder startAckBuilder(*builder);
            startAckBuilder.add_status(status);
            startAckBuilder.add_session(sessionId);
            auto startAckOffset = startAckBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               *builder,
                               Wazuh::SyncSchema::MessageType::StartAck,
                               startAckOffset.Union());
            builder->Finish(message);

            const uint8_t* bufferPtr = builder->GetBufferPointer();
            size_t size = builder->GetSize();
            std::vector<uint8_t> data(bufferPtr, bufferPtr + size);
            return {data, size};
        }

        // Helper to build EndAck message and return buffer (for direct parseResponseBuffer testing)
        std::pair<std::vector<uint8_t>, size_t> buildEndAck(
            Wazuh::SyncSchema::Status status = Wazuh::SyncSchema::Status::Ok,
            uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            auto builder = std::make_shared<flatbuffers::FlatBufferBuilder>();
            Wazuh::SyncSchema::EndAckBuilder endAckBuilder(*builder);
            endAckBuilder.add_status(status);
            endAckBuilder.add_session(sessionId);
            auto endAckOffset = endAckBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               *builder,
                               Wazuh::SyncSchema::MessageType::EndAck,
                               endAckOffset.Union());
            builder->Finish(message);

            const uint8_t* bufferPtr = builder->GetBufferPointer();
            size_t size = builder->GetSize();
            std::vector<uint8_t> data(bufferPtr, bufferPtr + size);
            return {data, size};
        }

        // Helper to build ReqRet message and return buffer (for direct parseResponseBuffer testing)
        std::pair<std::vector<uint8_t>, size_t> buildReqRet(
            const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
            uint64_t sessionId = 0)
        {
            if (sessionId == 0)
            {
                sessionId = session;
            }

            auto builder = std::make_shared<flatbuffers::FlatBufferBuilder>();
            std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;

            for (const auto& range : ranges)
            {
                auto pairOffset = Wazuh::SyncSchema::CreatePair(*builder, range.first, range.second);
                seqRanges.push_back(pairOffset);
            }

            auto seqRangesVector = builder->CreateVector(seqRanges);

            Wazuh::SyncSchema::ReqRetBuilder reqRetBuilder(*builder);
            reqRetBuilder.add_session(sessionId);
            reqRetBuilder.add_seq(seqRangesVector);
            auto reqRetOffset = reqRetBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(
                               *builder,
                               Wazuh::SyncSchema::MessageType::ReqRet,
                               reqRetOffset.Union());
            builder->Finish(message);

            const uint8_t* bufferPtr = builder->GetBufferPointer();
            size_t size = builder->GetSize();
            std::vector<uint8_t> data(bufferPtr, bufferPtr + size);
            return {data, size};
        }

        // Helper to create test data with customizable count and prefix
        std::vector<PersistedData> createTestData(int count = 2,
                const std::string& idPrefix = "test_id",
                const std::string& indexPrefix = "test_index",
                const std::string& dataPrefix = "test_data")
        {
            std::vector<PersistedData> data;
            for (int i = 1; i <= count; ++i)
            {
                data.push_back(
                {
                    0,
                    idPrefix + "_" + std::to_string(i),
                    indexPrefix + "_" + std::to_string(i),
                    dataPrefix + "_" + std::to_string(i),
                    (i % 2 == 1) ? Operation::CREATE : Operation::MODIFY,
                    static_cast<uint64_t>(i)
                });
            }
            return data;
        }

        // Helper to wait for synchronization
        void waitForSync()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }

        // Helper to initialize protocol with standard parameters
        void initProtocol(const MQ_Functions& mq = {}, LoggerFunc logger = nullptr)
        {
            // Use default mqFuncs if not provided
            const MQ_Functions& mqToUse = (mq.start == nullptr) ? mqFuncs : mq;

            // Use default testLogger if not provided
            LoggerFunc loggerToUse = logger ? logger : testLogger;

            protocol = std::make_unique<AgentSyncProtocol>(
                           "test_module",
                           ":memory:",
                           mqToUse,
                           loggerToUse,
                           mockQueue);
        }

        // Helper to setup standard mock expectations for successful sync
        void setupMockForSuccessfulSync(const std::vector<PersistedData>& testData)
        {
            EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));

            EXPECT_CALL(*mockQueue, clearSyncedItems())
            .Times(1);
        }

        // Helper to setup standard mock expectations for failed sync
        void setupMockForFailedSync(const std::vector<PersistedData>& testData)
        {
            EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));

            EXPECT_CALL(*mockQueue, resetSyncingItems())
            .Times(1);
        }
};

TEST_F(AgentSyncProtocolTest, PersistDifferenceSuccess)
{
    initProtocol();

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion))
    .Times(1);

    protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion);
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceCatchesException)
{
    initProtocol();

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion))
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    EXPECT_NO_THROW(protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion));
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceInMemorySuccess)
{
    initProtocol();

    const std::string testId = "memory_test_id";
    const std::string testIndex = "memory_test_index";
    const std::string testData = "memory_test_data";
    const Operation testOperation = Operation::CREATE;
    const uint64_t testVersion = 456;

    EXPECT_NO_THROW(protocol->persistDifferenceInMemory(testId, testOperation, testIndex, testData, testVersion));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleNoQueueAvailable)
{
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    initProtocol(failingStartMqFuncs);

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
    initProtocol();

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
    initProtocol();

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
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

    bool result = protocol->synchronizeModule(
                      Mode::FULL,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
                  );

    EXPECT_TRUE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFullModeWithInMemoryData)
{
    initProtocol();

    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).Times(0);
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems()).Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFullModeFailureKeepsInMemoryData)
{
    initProtocol();

    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems()).Times(0);

    bool result = protocol->synchronizeModule(
                      Mode::FULL,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
                  );

    EXPECT_FALSE(result);

    EXPECT_NO_THROW(protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleInvalidModeValidation)
{
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync()).Times(0);
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems()).Times(0);

    Mode invalidMode = static_cast<Mode>(999);

    bool result = protocol->synchronizeModule(
                      invalidMode,
                      std::chrono::seconds(min_timeout),
                      retries,
                      maxEps
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendStartFails)
{
    MQ_Functions failingSendStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return -1;
        }
    };

    initProtocol(failingSendStartMqFuncs);

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStartAckTimeout)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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
    static int callCount = 0;
    MQ_Functions failingSendDataMqFuncs = {.start = [](const char*, short int, short int) { return 0; },
                                           .send_binary =
                                               [](int, const void*, size_t, const char*, char)
                                           {
                                               callCount++;
                                               if (callCount > 1)
                                               {
                                                   return -1;
                                               }
                                               return 0;
                                           }};

    initProtocol(failingSendDataMqFuncs);

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendEndFails)
{
    static int callCount = 0;
    MQ_Functions failingSendEndMqFuncs = {.start = [](const char*, short int, short int) { return 0; },
                                          .send_binary =
                                              [](int, const void*, size_t, const char*, char)
                                          {
                                              callCount++;
                                              if (callCount > 3)
                                              {
                                                  return -1;
                                              }
                                              return 0;
                                          }};

    initProtocol(failingSendEndMqFuncs);

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndFailDueToManager)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesEmpty)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendReqRet({});

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesDataEmpty)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendReqRet({{10, 15}, {20, 25}});

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndDataResendFails)
{
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

    initProtocol(failingReqRetDataMqFuncs);

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendReqRet({{1, 2}});

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndAckTimeout)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForFailedSync(testData);

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

    waitForSync();
    sendStartAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithNoReqRet)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForSuccessfulSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithReqRet)
{
    initProtocol();

    auto testData = createTestData();
    setupMockForSuccessfulSync(testData);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendReqRet({{1, 2}});
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFinalizeSyncStateException)
{
    // Logger to capture error messages
    std::string loggedMessage;

    LoggerFunc captureTestLogger = [&loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Failed to finalize sync state") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    initProtocol(mqFuncs, captureTestLogger);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 0}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .WillOnce(testing::Throw(std::runtime_error("Simulated clearSyncedItems exception")));

    std::thread syncThread([this]()
    {
        bool result = protocol->synchronizeModule(Mode::DELTA, std::chrono::seconds(max_timeout), retries, maxEps);
        EXPECT_TRUE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();

    // Verify that the error was logged
    EXPECT_TRUE(loggedMessage.find("Failed to finalize sync state") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated clearSyncedItems exception") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithNullBuffer)
{
    initProtocol();

    bool response = protocol->parseResponseBuffer(nullptr, 0);

    EXPECT_FALSE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForStartAck)
{
    initProtocol();

    auto [buffer, size] = buildStartAck();
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckError)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();

    auto [buffer, size] = buildStartAck(Wazuh::SyncSchema::Status::Error);
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckOffline)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();

    auto [buffer, size] = buildStartAck(Wazuh::SyncSchema::Status::Offline);
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckSuccess)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();

    auto [buffer, size] = buildStartAck();
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForEndAck)
{
    initProtocol();

    auto [buffer, size] = buildEndAck();
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckError)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    auto [buffer, size] = buildEndAck(Wazuh::SyncSchema::Status::Error);
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckOffline)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    auto [buffer, size] = buildEndAck(Wazuh::SyncSchema::Status::Offline);
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckSuccess)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    auto [buffer, size] = buildEndAck();
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForReqRet)
{
    initProtocol();

    auto [buffer, size] = buildReqRet({{1, 2}});
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetAndNoRanges)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    auto [buffer, size] = buildReqRet({});
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetSuccess)
{
    initProtocol();

    std::thread syncThread([this]()
    {
        auto testData = createTestData(1);
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    auto [buffer, size] = buildReqRet({{1, 2}});
    bool response = protocol->parseResponseBuffer(buffer.data(), size);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithUnknownMessageType)
{
    initProtocol();

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
    initProtocol();

    const std::string testIndex = "test_index";
    const std::string testChecksum = "matching_checksum";

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncWithNonMatchingChecksum)
{
    initProtocol();

    const std::string testIndex = "test_index";
    const std::string testChecksum = "non_matching_checksum";

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncNoQueueAvailable)
{
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    initProtocol(failingStartMqFuncs);

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
    MQ_Functions failingSendStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return -1;    // Fail to send Start message
        }
    };

    initProtocol(failingSendStartMqFuncs);

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
    initProtocol();

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

    LoggerFunc captureTestLogger = [&loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Failed to send ChecksumModule message") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    initProtocol(failingChecksumMqFuncs, captureTestLogger);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    std::thread syncThread([this, testIndex, testChecksum]()
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

    waitForSync();
    sendStartAck();

    syncThread.join();

    EXPECT_TRUE(loggedMessage.find("Failed to send ChecksumModule message") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, EnsureQueueAvailableException)
{

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
    LoggerFunc captureTestLogger = [&loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Exception when checking queue availability") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    initProtocol(throwingMqFuncs, captureTestLogger);

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

    LoggerFunc captureTestLogger = [&loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Exception when sending Start message") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    initProtocol(throwingMqFuncs, captureTestLogger);

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

    LoggerFunc captureTestLogger = [&loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Exception when sending Data messages") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    initProtocol(throwingMqFuncs, captureTestLogger);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

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

    waitForSync();
    sendStartAck();

    syncThread.join();

    EXPECT_TRUE(loggedMessage.find("Exception when sending Data messages") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated send_binary exception in Data message") != std::string::npos);
}

// Tests for clearInMemoryData
TEST_F(AgentSyncProtocolTest, ClearInMemoryDataWithEmptyData)
{
    initProtocol();

    // Clear empty in-memory data should not throw
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

TEST_F(AgentSyncProtocolTest, ClearInMemoryDataWithData)
{
    initProtocol();

    // Add some in-memory data
    protocol->persistDifferenceInMemory("memory_id_1", Operation::CREATE, "memory_index_1", "memory_data_1", 1);
    protocol->persistDifferenceInMemory("memory_id_2", Operation::MODIFY, "memory_index_2", "memory_data_2", 2);
    protocol->persistDifferenceInMemory("memory_id_3", Operation::DELETE_, "memory_index_3", "memory_data_3", 3);

    // Clear in-memory data should not throw
    EXPECT_NO_THROW(protocol->clearInMemoryData());
}

TEST_F(AgentSyncProtocolTest, ClearInMemoryDataAfterFailedFullSync)
{
    initProtocol();

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
    initProtocol();

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
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithMetadataCheckMode)
{
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupDeltaMode)
{
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupCheckMode)
{
    initProtocol();

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .Times(0);

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithInvalidMode)
{
    initProtocol();

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
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 0;
        }
    };

    initProtocol(failingStartMqFuncs);

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
    initProtocol();

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
    initProtocol();

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

    waitForSync();
    sendStartAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithStartAckError)
{
    initProtocol();

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

    waitForSync();
    sendStartAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithEndAckError)
{
    initProtocol();

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

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

// Tests for deleteDatabase
TEST_F(AgentSyncProtocolTest, DeleteDatabaseCallsQueueDeleteDatabase)
{
    initProtocol();

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .Times(1);

    EXPECT_NO_THROW(protocol->deleteDatabase());
}

TEST_F(AgentSyncProtocolTest, DeleteDatabaseThrowsOnQueueError)
{
    bool errorLogged = false;
    std::string loggedMessage;
    LoggerFunc captureTestLogger = [&errorLogged, &loggedMessage](modules_log_level_t level, const std::string& message)
    {
        if (level == LOG_ERROR && message.find("Failed to delete database") != std::string::npos)
        {
            errorLogged = true;
            loggedMessage = message;
        }
    };

    initProtocol(mqFuncs, captureTestLogger);

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .WillOnce(::testing::Throw(std::runtime_error("Database deletion failed")));

    EXPECT_NO_THROW(protocol->deleteDatabase());
    EXPECT_TRUE(errorLogged);
    EXPECT_NE(loggedMessage.find("Database deletion failed"), std::string::npos);
}

// Tests for notifyDataClean
TEST_F(AgentSyncProtocolTest, NotifyDataCleanWithEmptyIndices)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> emptyIndices;

    // Should not call any queue methods with empty indices
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(emptyIndices, std::chrono::seconds(min_timeout), retries, maxEps);

    EXPECT_FALSE(result); // Should fail with empty indices
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanNoQueueAvailable)
{
    MQ_Functions failingStartMqFuncs =
    {
        .start = [](const char*, short int, short int) { return -1; }, // Queue start fails
        .send_binary = [](int, const void*, size_t, const char*, char)
        {
            return 1;
        }
    };

    initProtocol(failingStartMqFuncs);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when queue is not available
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSendStartFails)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when send fails
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckTimeout)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);

    EXPECT_FALSE(result); // Should fail due to timeout
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckError)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_FALSE(result);
    });

    waitForSync();
    sendStartAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckTimeout)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_FALSE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckError)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_FALSE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck(Wazuh::SyncSchema::Status::Error);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanClearItemsByIndexThrows)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .WillOnce(::testing::Throw(std::runtime_error("Clear items failed")));

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_FALSE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithSingleIndex)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_TRUE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithMultipleIndices)
{
    initProtocol(failingSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1", "test_index_2", "test_index_3"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_2"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_3"))
    .Times(1);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_TRUE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    sendEndAck();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSendDataCleanMessagesException)
{
    // Create a custom MQ_Functions that will cause an exception during data clean message sending
    MQ_Functions exceptionSendMqFuncs = {.start = [](const char*, short int, short int) { return 1; },
                                         .send_binary =
                                             [](int, const void* data, size_t size, const char*, char)
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
                                         }};

    initProtocol(exceptionSendMqFuncs);

    std::vector<std::string> indices = {"test_index_1"};

    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices, std::chrono::seconds(min_timeout), retries, maxEps);
        EXPECT_FALSE(result);
    });

    waitForSync();
    sendStartAck();
    waitForSync();
    waitForSync();

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SendChecksumMessageException)
{
    // Test that exceptions in sendChecksumMessage are properly caught and logged
    // Uses requiresFullSync which calls sendChecksumMessage internally

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

    initProtocol(throwingMq);

    std::string index = "test_index";
    std::string checksum = "test_checksum";

    // This should trigger the exception and catch block through requiresFullSync
    bool result = protocol->requiresFullSync(index, checksum, std::chrono::seconds(1), retries, maxEps);

    // The method should return false when an exception occurs
    EXPECT_FALSE(result);

    // Verify the message sending function was called (causing the exception)
    EXPECT_GT(callCount, 0);
}

TEST_F(AgentSyncProtocolTest, SendEndMessageException)
{
    // Test that exceptions in sendEndAndWaitAck are properly caught and logged
    // Uses synchronizeModule which calls sendEndAndWaitAck internally

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

    initProtocol(throwingMq);

    auto testData = createTestData(1);
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
    .WillOnce(testing::Return(testData));

    std::thread syncThread(
        [this]()
        {
            bool result = protocol->synchronizeModule(Mode::DELTA, std::chrono::seconds(max_timeout), retries, maxEps);
            EXPECT_FALSE(result);
        });

    waitForSync();
    sendStartAck();
    waitForSync();
    waitForSync();
    waitForSync();

    syncThread.join();

    EXPECT_GT(callCount, 2);
}
