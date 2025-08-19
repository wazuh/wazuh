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
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
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
    uint64_t agentId = 1;

    flatbuffers::Offset<Wazuh::SyncSchema::Start>
    createStartMessage(uint64_t size, const std::string& moduleName, uint64_t agentId)
    {

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_size(size);
        startBuilder.add_agent_id(agentId);
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
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(10, moduleTestName, agentId);
    builder.Finish(startMsg);

    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);

    ASSERT_NO_THROW({
        AgentSessionForTest session(
            sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);
    });
}

TEST_F(AgentSessionTest, Constructor_NullData)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    EXPECT_THROW(
        {
            AgentSessionForTest session(
                sessionId, agentIdTest, moduleTestName, nullptr, mockStore, mockIndexerQueue, mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_InvalidSize)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(0, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_THROW(
        {
            AgentSessionForTest session(
                sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_NullModule)
{
    const std::string moduleTestName = ""; // Empty module name to test null/empty case
    const std::string agentIdTest = "1";

    Wazuh::SyncSchema::StartBuilder startBuilder(builder);
    startBuilder.add_size(10);
    startBuilder.add_agent_id(agentId);
    startBuilder.add_mode(Wazuh::SyncSchema::Mode_Full);
    // Note: Not adding module name to test null module
    auto startMsg = startBuilder.Finish();

    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_THROW(
        {
            AgentSessionForTest session(
                sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_InvalidAgentId)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = ""; // Invalid agent ID (empty string)

    auto startMsg = createStartMessage(10, moduleTestName, 0);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_THROW(
        {
            AgentSessionForTest session(
                sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, HandleData_Success)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(1, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);
    AgentSessionForTest session(
        sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;
    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());
    std::vector<char> dataRaw(dataBuilder.GetBufferPointer(), dataBuilder.GetBufferPointer() + dataBuilder.GetSize());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleData(data, dataRaw);
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndNotReceived)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(1, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);
    AgentSessionForTest session(
        sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;
    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());
    std::vector<char> dataRaw(dataBuilder.GetBufferPointer(), dataBuilder.GetBufferPointer() + dataBuilder.GetSize());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0); // End not received, should not push

    session.handleData(data, dataRaw);
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndReceived)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(1, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);
    AgentSessionForTest session(
        sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);

    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(sessionId, _)).Times(1);
    session.handleEnd(mockResponseDispatcher); // Simulate end received first

    flatbuffers::FlatBufferBuilder dataBuilder;
    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());
    std::vector<char> dataRaw(dataBuilder.GetBufferPointer(), dataBuilder.GetBufferPointer() + dataBuilder.GetSize());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleData(data, dataRaw);
}

TEST_F(AgentSessionTest, HandleEnd_GapSetNotEmpty)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(2, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);
    AgentSessionForTest session(
        sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);

    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(sessionId, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleEnd(mockResponseDispatcher);
}

TEST_F(AgentSessionTest, HandleEnd_GapSetEmpty)
{
    const std::string moduleTestName = "syscollector";
    const std::string agentIdTest = "1";

    auto startMsg = createStartMessage(1, moduleTestName, agentId);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockResponseDispatcher, sendStartAck(_, _)).Times(1);
    AgentSessionForTest session(
        sessionId, agentIdTest, moduleTestName, start, mockStore, mockIndexerQueue, mockResponseDispatcher);

    flatbuffers::FlatBufferBuilder dataBuilder;
    Wazuh::SyncSchema::DataBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_seq(0);
    dataMsgBuilder.add_session(sessionId);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::Data>(dataBuilder.GetBufferPointer());
    std::vector<char> dataRaw(dataBuilder.GetBufferPointer(), dataBuilder.GetBufferPointer() + dataBuilder.GetSize());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    session.handleData(data, dataRaw);

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);
    EXPECT_CALL(mockResponseDispatcher, sendEndMissingSeq(_, _)).Times(0);

    session.handleEnd(mockResponseDispatcher);
}
