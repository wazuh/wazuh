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
        std::chrono::seconds(1),
        1,
        100
    );

    EXPECT_FALSE(result); // Fail to open queue
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
        std::chrono::seconds(1),
        1,
        100
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
        std::chrono::seconds(1),
        1,
        100
    );

    EXPECT_TRUE(result); // No pending items to synchronize for module
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
        std::chrono::seconds(1),
        1,
        100
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with ERROR status
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // This triggers syncFailed = true
    startAckBuilder.add_session(1234);
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
        std::chrono::seconds(1),
        1,
        100
    );

    EXPECT_FALSE(result); // StartAck timeout
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate EndAck response with ERROR status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Error); // This triggers syncFailed = true
    endAckBuilder.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result); // Should fail due to empty ranges
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate ReqRet response with EMPTY ranges
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result); // Should fail due to empty range data
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ReqRet response with no valid data ranges
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
    reqRetBuilderObj.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result); // Should fail due to data resend failure
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ReqRet response with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    
    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_FALSE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_TRUE(result);
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response
    flatbuffers::FlatBufferBuilder builder;
    auto module = builder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate EndAck response
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(1234);
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

    // Start synchronization in a separate thread
    std::thread syncThread([this]() {
        bool result = protocol->synchronizeModule(
            Wazuh::SyncSchema::Mode::Full,
            std::chrono::seconds(5),
            1,
            100
        );
        EXPECT_TRUE(result); // Should succeed with ReqRet
    });

    // Wait for start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate StartAck response with OK status
    flatbuffers::FlatBufferBuilder startBuilder;
    auto startModule = startBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::StartAckBuilder startAckBuilder(startBuilder);
    startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    startAckBuilder.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ReqRet response with valid ranges 1-2
    flatbuffers::FlatBufferBuilder reqRetBuilder;
    auto reqRetModule = reqRetBuilder.CreateString("test_module");
    
    std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> seqRanges;
    
    // Range 1-2
    auto range1 = Wazuh::SyncSchema::CreatePair(reqRetBuilder, 1, 2);
    seqRanges.push_back(range1);
    
    auto seqRangesVector = reqRetBuilder.CreateVector(seqRanges);
    
    Wazuh::SyncSchema::ReqRetBuilder reqRetBuilderObj(reqRetBuilder);
    reqRetBuilderObj.add_session(1234);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // EndAck response with OK status
    flatbuffers::FlatBufferBuilder endBuilder;
    auto endModule = endBuilder.CreateString("test_module");
    
    Wazuh::SyncSchema::EndAckBuilder endAckBuilder(endBuilder);
    endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
    endAckBuilder.add_session(1234);
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
    startAckBuilder.add_session(1234);
    startAckBuilder.add_module_(module);
    auto startAckOffset = startAckBuilder.Finish();
    
    auto message = Wazuh::SyncSchema::CreateMessage(
        builder,
        Wazuh::SyncSchema::MessageType::StartAck,
        startAckOffset.Union());
    builder.Finish(message);
    
    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer);

    EXPECT_TRUE(response); // Should be false
}

// TODO: Add test for ParseResponseBuffer with StartAck with error

// TODO: Add test for ParseResponseBuffer with success StartAck

// TODO: Add test for ParseResponseBuffer when not waiting for EndAck

// TODO: Add test for ParseResponseBuffer with EndAck with error

// TODO: Add test for ParseResponseBuffer with success EndAck

// TODO: Add test for ParseResponseBuffer when not waiting for ReqRet

// TODO: Add test for ParseResponseBuffer with ReqRet with error

// TODO: Add test for ParseResponseBuffer with success ReqRet


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
