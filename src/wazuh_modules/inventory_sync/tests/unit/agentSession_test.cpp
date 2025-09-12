/**
 * Wazuh Inventory Sync - AgentSession Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentSession.hpp"
#include "flatbuffers/flatbuffers.h"
#include "mock_agentSession.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace ::testing;

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}

class AgentSessionTest : public ::testing::Test
{
protected:
    using AgentSessionForTest = AgentSessionImpl<MockStore, MockIndexerQueue, MockResponseDispatcher>;

    StrictMock<MockStore> mockStore;
    StrictMock<MockIndexerQueue> mockIndexerQueue;
    StrictMock<MockResponseDispatcher> mockResponseDispatcher;

    flatbuffers::FlatBufferBuilder builder;
    uint64_t sessionId = 12345;
    std::string agentId = "001";

    flatbuffers::Offset<Wazuh::SyncSchema::Start>
    createStartMessage(uint64_t size, const std::string& /*moduleName*/, uint64_t /*agentId*/)
    {
        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_size(size);
        startBuilder.add_mode(Wazuh::SyncSchema::Mode_Full);
        return startBuilder.Finish();
    }

    void TearDown() override
    {
        builder.Clear();
    }
};

TEST_F(AgentSessionTest, Constructor_Success)
{
    auto startMsg = createStartMessage(10, "syscollector", 1);
    builder.Finish(startMsg);

    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);

    ASSERT_NO_THROW({
        AgentSessionForTest session(sessionId,
                                    "1",
                                    "syscollector",
                                    "test-agent",
                                    "127.0.0.1",
                                    "4.0.0",
                                    start,
                                    mockStore,
                                    mockIndexerQueue,
                                    mockResponseDispatcher);
    });
}

TEST_F(AgentSessionTest, Constructor_NullData)
{
    EXPECT_THROW(
        {
            AgentSessionForTest session(sessionId,
                                        "1",
                                        "syscollector",
                                        "test-agent",
                                        "127.0.0.1",
                                        "4.0.0",
                                        nullptr,
                                        mockStore,
                                        mockIndexerQueue,
                                        mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_InvalidSize)
{
    auto startMsg = createStartMessage(0, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(Wazuh::SyncSchema::Status_Error, _, _, _)).Times(1);
    EXPECT_THROW(
        {
            AgentSessionForTest session(sessionId,
                                        "1",
                                        "syscollector",
                                        "test-agent",
                                        "127.0.0.1",
                                        "4.0.0",
                                        start,
                                        mockStore,
                                        mockIndexerQueue,
                                        mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_NullModule)
{
    Wazuh::SyncSchema::StartBuilder startBuilder(builder);
    startBuilder.add_size(10);
    startBuilder.add_mode(Wazuh::SyncSchema::Mode_Full);
    auto startMsg = startBuilder.Finish();

    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    // Now this should succeed since we use the constructor parameter for moduleName
    EXPECT_CALL(mockResponseDispatcher, sendStartAck(Wazuh::SyncSchema::Status_Ok, _, _, _)).Times(1);
    EXPECT_NO_THROW({
        AgentSessionForTest session(sessionId,
                                    "1",
                                    "syscollector",
                                    "test-agent",
                                    "127.0.0.1",
                                    "4.0.0",
                                    start,
                                    mockStore,
                                    mockIndexerQueue,
                                    mockResponseDispatcher);
    });
}

TEST_F(AgentSessionTest, Constructor_ValidAgentIdZero)
{
    auto startMsg = createStartMessage(10, "syscollector", 0);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(Wazuh::SyncSchema::Status_Ok, _, _, _)).Times(1);

    AgentSessionForTest session(sessionId,
                                "0",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);
}

TEST_F(AgentSessionTest, HandleData_Success)
{
    auto startMsg = createStartMessage(1, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);
    AgentSessionForTest session(sessionId,
                                "1",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleData(data, reinterpret_cast<const flatbuffers::Vector<uint8_t>*>(data->data()));
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndNotReceived)
{
    auto startMsg = createStartMessage(1, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);
    AgentSessionForTest session(sessionId,
                                "1",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0); // End not received, should not push

    session.handleData(data, reinterpret_cast<const flatbuffers::Vector<uint8_t>*>(data->data()));
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndReceived)
{
    auto startMsg = createStartMessage(1, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);
    AgentSessionForTest session(sessionId,
                                "1",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);

    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(_, _, _, _)).Times(1);
    session.handleEnd(mockResponseDispatcher); // Simulate end received first

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleData(data, reinterpret_cast<const flatbuffers::Vector<uint8_t>*>(data->data()));
}

TEST_F(AgentSessionTest, HandleEnd_GapSetNotEmpty)
{
    auto startMsg = createStartMessage(2, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);
    AgentSessionForTest session(sessionId,
                                "1",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);

    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(_, _, _, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleEnd(mockResponseDispatcher);
}

TEST_F(AgentSessionTest, HandleEnd_GapSetEmpty)
{
    auto startMsg = createStartMessage(1, "syscollector", 1);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _, _, _)).Times(1);
    AgentSessionForTest session(sessionId,
                                "1",
                                "syscollector",
                                "test-agent",
                                "127.0.0.1",
                                "4.0.0",
                                start,
                                mockStore,
                                mockIndexerQueue,
                                mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    session.handleData(data, reinterpret_cast<const flatbuffers::Vector<uint8_t>*>(data->data()));

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);
    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(_, _, _, _)).Times(0);

    session.handleEnd(mockResponseDispatcher);
}
