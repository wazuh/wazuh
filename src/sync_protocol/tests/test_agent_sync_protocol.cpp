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

#include <thread>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;

// IPersistentQueue Mock
class MockPersistentQueue : public IPersistentQueue {
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
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);
    
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
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation))
        .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    EXPECT_NO_THROW(protocol->persistDifference(testId, testOperation, testIndex, testData));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleNoQueueAvailable) 
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingStartMqFuncs = {
        .start = [](const char*, short int, short int) { return -1; }, // Fail to start queue
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", failingStartMqFuncs, mockQueue);

    bool result = protocol->synchronizeModule(
        Wazuh::SyncSchema::Mode::Full,
        std::chrono::seconds(min_timeout),
        retries,
        maxEps
    );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFetchAndMarkForSyncThrowsException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    bool result = protocol->synchronizeModule(
        Wazuh::SyncSchema::Mode::Full,
        std::chrono::seconds(min_timeout),
        retries,
        maxEps
    );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDataToSyncEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(std::vector<PersistedData>{}));

    bool result = protocol->synchronizeModule(
        Wazuh::SyncSchema::Mode::Full,
        std::chrono::seconds(min_timeout),
        retries,
        maxEps
    );

    EXPECT_TRUE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions failingSendStartMqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return -1; } // Fail to send Start message
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", failingSendStartMqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    bool result = protocol->synchronizeModule(
        Wazuh::SyncSchema::Mode::Full,
        std::chrono::seconds(min_timeout),
        retries,
        maxEps
    );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStartFailDueToManager)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // syncFailed = true
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    bool result = protocol->synchronizeModule(
        Wazuh::SyncSchema::Mode::Full,
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
    MQ_Functions failingSendDataMqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { 
            callCount++;
            if (callCount > 1) {
                return -1; // Fail data messages
            }
            return 0; // Allow Start message to succeed
        }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", failingSendDataMqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendEndFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingSendEndMqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { 
            callCount++;
            if (callCount > 3) {
                return -1; // Fail End message
            }
            return 0; // Allow Start and Data messages to succeed
        }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", failingSendEndMqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndFailDueToManager)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // syncFailed = true
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with EMPTY ranges
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_module_(reqRetModule);
    // No seq ranges
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndRangesDataEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with no valid data ranges
    // Test data seq numbers 1-2, but request ranges 10-15 and 20-25
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
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
    reqRetBuilderObj.add_module_(reqRetModule);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleWithReqRetAndDataResendFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    MQ_Functions failingReqRetDataMqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { 
            callCount++;
            if (callCount > 4) {
                return -1; // Fail data resend for ReqRet
            }
            return 0; // Allow Start, initial Data messages and End
        }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", failingReqRetDataMqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for initial data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    
    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_module_(reqRetModule);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithNoReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    protocol->parseResponseBuffer(buffer);

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    std::vector<PersistedData> testData = {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
        .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
        .Times(1);

    // Start synchronization
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
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
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for initial data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    
    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_module_(reqRetModule);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(reqRetBuffer);

    // Wait for data resend
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(endBuffer);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithNullBuffer) 
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    bool response = protocol->parseResponseBuffer(nullptr);

    EXPECT_FALSE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForStartAck) 
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    flatbuffers::FlatBufferBuilder builder;
    
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with ERROR status
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // Status Error
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckOffline)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with OFFLINE status
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Offline); // Status Offline
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithStartAckSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingStartAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForEndAck)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(module);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));
            
        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // Status Error
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckOffline)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));
            
        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OFFLINE status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Offline); // Status Offline
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));
            
        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok); // Status Ok
    endAckBuilder.add_session(session);
    endAckBuilder.add_module_(endModule);
    auto endAckOffset = endAckBuilder.Finish();
    
    auto endMessage = Wazuh::SyncSchema::CreateMessage(
        endBuilder,
        Wazuh::SyncSchema::MessageType::EndAck,
        endAckOffset.Union());
    endBuilder.Finish(endMessage);
    
    const uint8_t* endBuffer = endBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(endBuffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    // ReqRet message
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    auto range1 = Wazuh::SyncSchema::CreatePair(builder, 1, 2); // Range 1-2
    seqRanges.push_back(range1);
    auto seqRangesVector = builder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilder(builder);
    reqRetBuilder.add_session(session);
    reqRetBuilder.add_module_(module);
    reqRetBuilder.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetAndNoRanges)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));
            
        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet with no ranges
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_module_(reqRetModule);
    // No seq field
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(reqRetBuffer);

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithReqRetSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]() {
        std::vector<PersistedData> testData = {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE}
        };
        
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync())
            .WillOnce(Return(testData));
            
        protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(max_timeout),
            retries,
            maxEps
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(session);
    startAckBuilder.add_module_(startModule);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto startMessage = Wazuh::SyncSchema::CreateMessage(
        startBuilder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    startBuilder.Finish(startMessage);
    
    const uint8_t* startBuffer = startBuilder.GetBufferPointer();
    protocol->parseResponseBuffer(startBuffer);

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // ReqRet
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(session);
    reqRetBuilderObj.add_module_(reqRetModule);
    reqRetBuilderObj.add_seq(seqRangesVector);
    auto reqRetOffset = reqRetBuilderObj.Finish();
    
    auto reqRetMessage = Wazuh::SyncSchema::CreateMessage(
        reqRetBuilder,
        Wazuh::SyncSchema::MessageType::ReqRet,
        reqRetOffset.Union());
    reqRetBuilder.Finish(reqRetMessage);
    
    const uint8_t* reqRetBuffer = reqRetBuilder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(reqRetBuffer);

    EXPECT_TRUE(response);

    syncThread.join();
}


TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithUnknownMessageType)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    MQ_Functions mqFuncs = {
        .start = [](const char*, short int, short int) { return 0; },
        .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", mqFuncs, mockQueue);

    flatbuffers::FlatBufferBuilder builder;
    
    auto message = Wazuh::SyncSchema::CreateMessage(builder);
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_FALSE(response);
}
