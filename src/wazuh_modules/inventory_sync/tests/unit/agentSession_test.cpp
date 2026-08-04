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

    static inline const LogFn s_logFn {};

    StrictMock<MockStore> mockStore;
    StrictMock<MockIndexerQueue> mockIndexerQueue;
    StrictMock<MockResponseDispatcher> mockResponseDispatcher;

    flatbuffers::FlatBufferBuilder builder;
    uint64_t sessionId = 12345;
    std::string agentId = "001";

    flatbuffers::Offset<Wazuh::SyncSchema::Start>
    createStartMessage(uint64_t size,
                       const std::string& agentIdStr = "001",
                       const std::string& agentName = "test-agent",
                       const std::string& agentVersion = "4.0.0",
                       const std::string& moduleName = "syscollector",
                       Wazuh::SyncSchema::Mode mode = Wazuh::SyncSchema::Mode_ModuleDelta)
    {
        auto agentIdOffset = builder.CreateString(agentIdStr);
        auto agentNameOffset = builder.CreateString(agentName);
        auto agentVersionOffset = builder.CreateString(agentVersion);
        auto moduleOffset = builder.CreateString(moduleName);

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_module_(moduleOffset);
        startBuilder.add_size(size);
        startBuilder.add_mode(mode);
        startBuilder.add_option(Wazuh::SyncSchema::Option_Sync);
        startBuilder.add_agentid(agentIdOffset);
        startBuilder.add_agentname(agentNameOffset);
        startBuilder.add_agentversion(agentVersionOffset);
        return startBuilder.Finish();
    }

    void TearDown() override
    {
        builder.Clear();
    }
};

TEST_F(AgentSessionTest, Constructor_Success)
{
    auto startMsg = createStartMessage(10, "001", "test-agent", "4.0.0");
    builder.Finish(startMsg);

    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    ASSERT_NO_THROW({
        AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
    });
}

TEST_F(AgentSessionTest, Constructor_NullData)
{
    EXPECT_THROW(
        {
            AgentSessionForTest session(
                sessionId, nullptr, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_InvalidSize)
{
    auto startMsg = createStartMessage(0);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_THROW(
        {
            AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
        },
        AgentSessionException);
}

TEST_F(AgentSessionTest, Constructor_NullModule)
{
    Wazuh::SyncSchema::StartBuilder startBuilder(builder);
    startBuilder.add_size(10);
    startBuilder.add_mode(Wazuh::SyncSchema::Mode_ModuleDelta);
    startBuilder.add_option(Wazuh::SyncSchema::Option_Sync);
    auto startMsg = startBuilder.Finish();

    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    // Now this should succeed since we use the constructor parameter for moduleName
    EXPECT_NO_THROW({
        AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
    });
}

TEST_F(AgentSessionTest, Constructor_ValidAgentIdZero)
{
    auto startMsg = createStartMessage(10, "0");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
}

TEST_F(AgentSessionTest, HandleData_Success)
{
    auto startMsg = createStartMessage(1, "1");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataValueBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size());
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndNotReceived)
{
    auto startMsg = createStartMessage(1, "1");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataValueBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0); // End not received, should not push

    session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size());
}

TEST_F(AgentSessionTest, HandleData_CompletesGapSet_EndReceived)
{
    auto startMsg = createStartMessage(1, "1");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    session.handleEnd(mockResponseDispatcher); // Simulate end received first

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataValueBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size());
}

TEST_F(AgentSessionTest, HandleEnd_GapSetNotEmpty)
{
    auto startMsg = createStartMessage(2, "1");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    session.handleEnd(mockResponseDispatcher);
}

TEST_F(AgentSessionTest, HandleEnd_GapSetEmpty)
{
    auto startMsg = createStartMessage(1, "1");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dataBuilder;

    // Create some test data
    std::vector<int8_t> testData = {0x01, 0x02, 0x03, 0x04};
    auto dataVector = dataBuilder.CreateVector(testData);

    Wazuh::SyncSchema::DataValueBuilder dataMsgBuilder(dataBuilder);
    dataMsgBuilder.add_data(dataVector);
    auto dataMsg = dataMsgBuilder.Finish();
    dataBuilder.Finish(dataMsg);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size());

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleEnd(mockResponseDispatcher);
}

TEST_F(AgentSessionTest, HandleChecksumModule_Success)
{
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    // Create session with ModuleCheck mode (size can be 0 for ModuleCheck)
    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create ChecksumModule message
    flatbuffers::FlatBufferBuilder checksumBuilder;
    auto checksumStr = checksumBuilder.CreateString("abc123def456");
    auto indexStr = checksumBuilder.CreateString("wazuh-states-vulnerabilities");

    Wazuh::SyncSchema::ChecksumModuleBuilder checksumModuleBuilder(checksumBuilder);
    checksumModuleBuilder.add_checksum(checksumStr);
    checksumModuleBuilder.add_index(indexStr);
    auto checksumMsg = checksumModuleBuilder.Finish();
    checksumBuilder.Finish(checksumMsg);

    auto checksumModule = flatbuffers::GetRoot<Wazuh::SyncSchema::ChecksumModule>(checksumBuilder.GetBufferPointer());

    ASSERT_NO_THROW({ session.handleChecksumModule(checksumModule); });
}

TEST_F(AgentSessionTest, HandleChecksumModule_NullData)
{
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_THROW({ session.handleChecksumModule(nullptr); }, AgentSessionException);
}

TEST_F(AgentSessionTest, HandleChecksumModule_EmptyChecksum)
{
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create ChecksumModule message with no checksum
    flatbuffers::FlatBufferBuilder checksumBuilder;
    auto indexStr = checksumBuilder.CreateString("wazuh-states-vulnerabilities");

    Wazuh::SyncSchema::ChecksumModuleBuilder checksumModuleBuilder(checksumBuilder);
    checksumModuleBuilder.add_index(indexStr);
    auto checksumMsg = checksumModuleBuilder.Finish();
    checksumBuilder.Finish(checksumMsg);

    auto checksumModule = flatbuffers::GetRoot<Wazuh::SyncSchema::ChecksumModule>(checksumBuilder.GetBufferPointer());

    // Should handle gracefully without throwing
    ASSERT_NO_THROW({ session.handleChecksumModule(checksumModule); });
}

TEST_F(AgentSessionTest, HandleDataClean_Success)
{
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create DataClean message
    flatbuffers::FlatBufferBuilder dataCleanBuilder;
    auto indexStr = dataCleanBuilder.CreateString("wazuh-states-fim-files");

    Wazuh::SyncSchema::DataCleanBuilder dataCleanMsgBuilder(dataCleanBuilder);
    dataCleanMsgBuilder.add_index(indexStr);
    auto dataCleanMsg = dataCleanMsgBuilder.Finish();
    dataCleanBuilder.Finish(dataCleanMsg);

    auto dataClean = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dataCleanBuilder.GetBufferPointer());

    // Handle DataClean message
    ASSERT_NO_THROW({ session.handleDataClean(dataClean); });
}

TEST_F(AgentSessionTest, HandleDataClean_MultipleIndices)
{
    auto startMsg = createStartMessage(3, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create DataClean messages for multiple indices
    std::vector<std::string> indices = {
        "wazuh-states-fim-files", "wazuh-states-fim-registry-keys", "wazuh-states-fim-registry-values"};

    for (size_t i = 0; i < indices.size(); ++i)
    {
        flatbuffers::FlatBufferBuilder dataCleanBuilder;
        auto indexStr = dataCleanBuilder.CreateString(indices[i]);

        Wazuh::SyncSchema::DataCleanBuilder dataCleanMsgBuilder(dataCleanBuilder);
        dataCleanMsgBuilder.add_index(indexStr);
        auto dataCleanMsg = dataCleanMsgBuilder.Finish();
        dataCleanBuilder.Finish(dataCleanMsg);

        auto dataClean = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dataCleanBuilder.GetBufferPointer());
        ASSERT_NO_THROW({ session.handleDataClean(dataClean); });
    }
}

TEST_F(AgentSessionTest, HandleDataClean_NullData)
{
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Passing null should throw
    ASSERT_THROW({ session.handleDataClean(nullptr); }, AgentSessionException);
}

TEST_F(AgentSessionTest, HandleDataClean_WithEnd)
{
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create DataClean message
    flatbuffers::FlatBufferBuilder dataCleanBuilder;
    auto indexStr = dataCleanBuilder.CreateString("wazuh-states-fim-files");

    Wazuh::SyncSchema::DataCleanBuilder dataCleanMsgBuilder(dataCleanBuilder);
    dataCleanMsgBuilder.add_index(indexStr);
    auto dataCleanMsg = dataCleanMsgBuilder.Finish();
    dataCleanBuilder.Finish(dataCleanMsg);

    auto dataClean = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dataCleanBuilder.GetBufferPointer());

    // Handle DataClean message
    session.handleDataClean(dataClean);

    // Handle End
    // Expect the indexer queue to be pushed when all sequences received
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);
    ASSERT_NO_THROW({ session.handleEnd(mockResponseDispatcher); });
}

TEST_F(AgentSessionTest, HandleDataContext_Success)
{
    auto startMsg =
        createStartMessage(1, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create DataContext message
    flatbuffers::FlatBufferBuilder dataContextBuilder;
    auto idStr = dataContextBuilder.CreateString("context-id-123");
    auto indexStr = dataContextBuilder.CreateString("wazuh-states-vulnerabilities");
    std::vector<int8_t> contextData = {0x01, 0x02, 0x03, 0x04};
    auto dataVec = dataContextBuilder.CreateVector(contextData);

    Wazuh::SyncSchema::DataContextBuilder dataContextMsgBuilder(dataContextBuilder);
    dataContextMsgBuilder.add_id(idStr);
    dataContextMsgBuilder.add_index(indexStr);
    dataContextMsgBuilder.add_data(dataVec);
    auto dataContextMsg = dataContextMsgBuilder.Finish();
    dataContextBuilder.Finish(dataContextMsg);

    auto dataContext = flatbuffers::GetRoot<Wazuh::SyncSchema::DataContext>(dataContextBuilder.GetBufferPointer());

    // Expect put call to RocksDB
    EXPECT_CALL(mockStore, put(_, _)).Times(1);

    // Handle DataContext message
    ASSERT_NO_THROW({
        session.handleDataContext(dataContext, dataContextBuilder.GetBufferPointer(), dataContextBuilder.GetSize());
    });
}

TEST_F(AgentSessionTest, HandleDataContext_MultipleMessages)
{
    auto startMsg =
        createStartMessage(3, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(3); // Expect 3 put calls for 3 DataContext messages
    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create multiple DataContext messages
    for (size_t i = 0; i < 3; ++i)
    {
        flatbuffers::FlatBufferBuilder dataContextBuilder;
        auto idStr = dataContextBuilder.CreateString(std::string("context-id-") + std::to_string(i));
        auto indexStr = dataContextBuilder.CreateString("wazuh-states-vulnerabilities");
        std::vector<int8_t> contextData = {static_cast<int8_t>(i), 0x02, 0x03, 0x04};
        auto dataVec = dataContextBuilder.CreateVector(contextData);

        Wazuh::SyncSchema::DataContextBuilder dataContextMsgBuilder(dataContextBuilder);
        dataContextMsgBuilder.add_id(idStr);
        dataContextMsgBuilder.add_index(indexStr);
        dataContextMsgBuilder.add_data(dataVec);
        auto dataContextMsg = dataContextMsgBuilder.Finish();
        dataContextBuilder.Finish(dataContextMsg);

        auto dataContext = flatbuffers::GetRoot<Wazuh::SyncSchema::DataContext>(dataContextBuilder.GetBufferPointer());
        ASSERT_NO_THROW({
            session.handleDataContext(dataContext, dataContextBuilder.GetBufferPointer(), dataContextBuilder.GetSize());
        });
    }
}

TEST_F(AgentSessionTest, HandleDataContext_NullData)
{
    auto startMsg =
        createStartMessage(1, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Passing null should throw
    ASSERT_THROW({ session.handleDataContext(nullptr, nullptr, 0); }, AgentSessionException);
}

TEST_F(AgentSessionTest, HandleDataContext_WithEnd)
{
    auto startMsg =
        createStartMessage(1, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Create DataContext message
    flatbuffers::FlatBufferBuilder dataContextBuilder;
    auto idStr = dataContextBuilder.CreateString("context-id-123");
    auto indexStr = dataContextBuilder.CreateString("wazuh-states-vulnerabilities");
    std::vector<int8_t> contextData = {0x01, 0x02, 0x03, 0x04};
    auto dataVec = dataContextBuilder.CreateVector(contextData);

    Wazuh::SyncSchema::DataContextBuilder dataContextMsgBuilder(dataContextBuilder);
    dataContextMsgBuilder.add_id(idStr);
    dataContextMsgBuilder.add_index(indexStr);
    dataContextMsgBuilder.add_data(dataVec);
    auto dataContextMsg = dataContextMsgBuilder.Finish();
    dataContextBuilder.Finish(dataContextMsg);

    auto dataContext = flatbuffers::GetRoot<Wazuh::SyncSchema::DataContext>(dataContextBuilder.GetBufferPointer());

    // Expect put call to RocksDB
    EXPECT_CALL(mockStore, put(_, _)).Times(1);

    // Handle DataContext message
    session.handleDataContext(dataContext, dataContextBuilder.GetBufferPointer(), dataContextBuilder.GetSize());

    // Handle End
    // Expect the indexer queue to be pushed when all sequences received
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);
    ASSERT_NO_THROW({ session.handleEnd(mockResponseDispatcher); });
}

TEST_F(AgentSessionTest, Constructor_ValidSize_ModuleCheck)
{
    // Create a StartMessage with ModuleCheck mode and size 0 (which is valid for ModuleCheck)
    auto agentIdOffset = builder.CreateString("001");
    auto agentNameOffset = builder.CreateString("test-agent");
    auto agentVersionOffset = builder.CreateString("4.0.0");
    auto moduleOffset = builder.CreateString("syscollector");

    Wazuh::SyncSchema::StartBuilder startBuilder(builder);
    startBuilder.add_module_(moduleOffset);
    startBuilder.add_size(0);
    startBuilder.add_mode(Wazuh::SyncSchema::Mode_ModuleCheck);
    startBuilder.add_option(Wazuh::SyncSchema::Option_Sync);
    startBuilder.add_agentid(agentIdOffset);
    startBuilder.add_agentname(agentNameOffset);
    startBuilder.add_agentversion(agentVersionOffset);
    auto startMsg = startBuilder.Finish();

    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    ASSERT_NO_THROW({
        AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);
    });
}

// =============================================================================
// Tests cover the safeguards/security hardening  (`wazuh-states-*` filtering,
// out-of-range seq, dedup guards, and the declaredSize() accessor).
// =============================================================================

namespace
{
    flatbuffers::Offset<Wazuh::SyncSchema::Start>
    createStartWithIndices(flatbuffers::FlatBufferBuilder& builder,
                           uint64_t size,
                           const std::vector<std::string>& indices,
                           Wazuh::SyncSchema::Mode mode = Wazuh::SyncSchema::Mode_ModuleDelta,
                           const std::string& moduleName = "syscollector")
    {
        auto agentIdOffset = builder.CreateString("001");
        auto agentNameOffset = builder.CreateString("test-agent");
        auto agentVersionOffset = builder.CreateString("4.0.0");
        auto moduleOffset = builder.CreateString(moduleName);

        std::vector<flatbuffers::Offset<flatbuffers::String>> indexOffsets;
        indexOffsets.reserve(indices.size());
        for (const auto& idx : indices)
        {
            indexOffsets.push_back(builder.CreateString(idx));
        }
        auto indexVector = builder.CreateVector(indexOffsets);

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_module_(moduleOffset);
        startBuilder.add_size(size);
        startBuilder.add_mode(mode);
        startBuilder.add_option(Wazuh::SyncSchema::Option_Sync);
        startBuilder.add_agentid(agentIdOffset);
        startBuilder.add_agentname(agentNameOffset);
        startBuilder.add_agentversion(agentVersionOffset);
        startBuilder.add_index(indexVector);
        return startBuilder.Finish();
    }
} // namespace

TEST_F(AgentSessionTest, Constructor_StartIndices_FiltersOutNonStatePrefix)
{
    auto startMsg = createStartWithIndices(builder, 1, {"wazuh-states-fim-files", "wazuh-other-foo", "random"});
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    const auto& storedIndices = session.getContext()->indices;
    ASSERT_EQ(storedIndices.size(), 1u);
    EXPECT_EQ(storedIndices[0], "wazuh-states-fim-files");
}

TEST_F(AgentSessionTest, Constructor_StartIndices_EmptyPrefixOnlyRejected)
{
    // "wazuh-states-" (empty suffix) matches no agent-scoped family: rejected.
    auto startMsg = createStartWithIndices(builder, 1, {"wazuh-states-"});
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_TRUE(session.getContext()->indices.empty());
}

TEST_F(AgentSessionTest, Constructor_StartIndices_AllValidPassedThrough)
{
    auto startMsg = createStartWithIndices(
        builder, 1, {"wazuh-states-vulnerabilities", "wazuh-states-inventory-system", "wazuh-states-fim-files"});
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_EQ(session.getContext()->indices.size(), 3u);
}

// A wazuh-states-* name outside the agent scope must be rejected.
TEST_F(AgentSessionTest, Constructor_StartIndices_RejectsOutOfScopeStateIndex)
{
    auto startMsg = createStartWithIndices(
        builder, 1, {"wazuh-states-inventory-packages", "wazuh-states-something-else", "wazuh-states-rules"});
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    const auto& storedIndices = session.getContext()->indices;
    ASSERT_EQ(storedIndices.size(), 1u);
    EXPECT_EQ(storedIndices[0], "wazuh-states-inventory-packages");
}

// Manager-governance indices must be rejected.
TEST_F(AgentSessionTest, Constructor_StartIndices_RejectsManagerGovernanceIndices)
{
    auto startMsg = createStartWithIndices(builder,
                                           1,
                                           {"wazuh-states-agent-management",
                                            "wazuh-states-cluster-nodes",
                                            "wazuh-states-manager-status",
                                            "wazuh-states-vulnerabilities"},
                                           Wazuh::SyncSchema::Mode_ModuleDelta,
                                           "syscollector_vd");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    // Only the in-scope vulnerabilities index survives.
    const auto& storedIndices = session.getContext()->indices;
    ASSERT_EQ(storedIndices.size(), 1u);
    EXPECT_EQ(storedIndices[0], "wazuh-states-vulnerabilities");
}

// Direct coverage of the index-authorization predicate.
TEST_F(AgentSessionTest, IsAgentScopedStateIndex_AllowlistAndBlocklist)
{
    // In-scope families.
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-inventory-packages"));
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-inventory-system"));
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-vulnerabilities"));
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-fim-files"));
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-fim-registry-keys"));
    EXPECT_TRUE(isAgentScopedStateIndex("wazuh-states-sca"));

    // Manager-governance indices: denied (not in the allowlist).
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-states-agent-management"));
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-states-cluster-nodes"));
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-states-manager-status"));

    // Out-of-scope / malformed names.
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-states-"));
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-states-rules"));
    EXPECT_FALSE(isAgentScopedStateIndex("wazuh-other-foo"));
    EXPECT_FALSE(isAgentScopedStateIndex("random"));
    EXPECT_FALSE(isAgentScopedStateIndex(""));
}

TEST_F(AgentSessionTest, HandleChecksumModule_NonStateIndex_Ignored)
{
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder checksumBuilder;
    auto checksumStr = checksumBuilder.CreateString("abc123");
    auto indexStr = checksumBuilder.CreateString("wazuh-other-foo");

    Wazuh::SyncSchema::ChecksumModuleBuilder cmBuilder(checksumBuilder);
    cmBuilder.add_checksum(checksumStr);
    cmBuilder.add_index(indexStr);
    auto cmMsg = cmBuilder.Finish();
    checksumBuilder.Finish(cmMsg);

    auto checksumModule = flatbuffers::GetRoot<Wazuh::SyncSchema::ChecksumModule>(checksumBuilder.GetBufferPointer());
    ASSERT_NO_THROW({ session.handleChecksumModule(checksumModule); });

    // The non-states index must NOT be persisted on the context. The checksum
    // value itself is still allowed in (it is used for comparison only and never
    // reaches the indexer URL), but checksumIndex must stay empty.
    EXPECT_TRUE(session.getContext()->checksumIndex.empty());
}

TEST_F(AgentSessionTest, HandleChecksumModule_StateIndex_Stored)
{
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder checksumBuilder;
    auto checksumStr = checksumBuilder.CreateString("abc123");
    auto indexStr = checksumBuilder.CreateString("wazuh-states-vulnerabilities");

    Wazuh::SyncSchema::ChecksumModuleBuilder cmBuilder(checksumBuilder);
    cmBuilder.add_checksum(checksumStr);
    cmBuilder.add_index(indexStr);
    auto cmMsg = cmBuilder.Finish();
    checksumBuilder.Finish(cmMsg);

    auto checksumModule = flatbuffers::GetRoot<Wazuh::SyncSchema::ChecksumModule>(checksumBuilder.GetBufferPointer());
    ASSERT_NO_THROW({ session.handleChecksumModule(checksumModule); });

    EXPECT_EQ(session.getContext()->checksumIndex, "wazuh-states-vulnerabilities");
}

TEST_F(AgentSessionTest, HandleDataClean_NonStateIndex_Ignored)
{
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dcBuilder;
    auto indexStr = dcBuilder.CreateString("wazuh-not-states");

    Wazuh::SyncSchema::DataCleanBuilder b(dcBuilder);
    b.add_index(indexStr);
    auto msg = b.Finish();
    dcBuilder.Finish(msg);

    auto dc = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dcBuilder.GetBufferPointer());
    ASSERT_NO_THROW({ session.handleDataClean(dc); });

    EXPECT_TRUE(session.getContext()->dataCleanIndices.empty());
}

TEST_F(AgentSessionTest, HandleData_SeqOutOfRange_DoesNotStore)
{
    // TODO(#38117): seq field removed from FlatBuffer schema on the agent side; the manager now
    // assigns it internally via a per-session arrival-order counter (AgentSessionImpl::m_seqCounter).
    // declaredSize=1 means only the first call gets an in-range seq (0); a second call gets seq=1,
    // which is out of range and must be rejected. m_gapSet->observe throws std::out_of_range and the
    // handler surfaces it; m_store.put is NEVER reached for the rejected call.
    auto startMsg = createStartMessage(1, "001");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dataBuilder;
    std::vector<int8_t> testData = {0x01};
    auto dataVector = dataBuilder.CreateVector(testData);
    Wazuh::SyncSchema::DataValueBuilder dvb(dataBuilder);
    dvb.add_data(dataVector);
    auto dvOff = dvb.Finish();
    dataBuilder.Finish(dvOff);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    // First call consumes the only declared slot (seq=0).
    ASSERT_NO_THROW(
        { session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size()); });

    // Second call is assigned seq=1, which is out of declared size bounds (declaredSize=1).
    EXPECT_THROW(
        { session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size()); },
        std::out_of_range);
}

TEST_F(AgentSessionTest, HandleDataContext_SeqOutOfRange_DoesNotStore)
{
    // TODO(#38117): seq field removed from FlatBuffer schema on the agent side; see the m_seqCounter
    // note in HandleData_SeqOutOfRange_DoesNotStore. First call consumes the only declared slot
    // (seq=0); the second call is assigned seq=1, out of range for declaredSize=1.
    auto startMsg = createStartMessage(1, "001");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dcBuilder;
    std::vector<int8_t> raw = {0x01};
    auto dataVec = dcBuilder.CreateVector(raw);
    Wazuh::SyncSchema::DataContextBuilder b(dcBuilder);
    b.add_data(dataVec);
    auto off = b.Finish();
    dcBuilder.Finish(off);

    auto ctx = flatbuffers::GetRoot<Wazuh::SyncSchema::DataContext>(dcBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);

    ASSERT_NO_THROW({
        session.handleDataContext(ctx, reinterpret_cast<const uint8_t*>(ctx->data()->data()), ctx->data()->size());
    });

    EXPECT_THROW(
        { session.handleDataContext(ctx, reinterpret_cast<const uint8_t*>(ctx->data()->data()), ctx->data()->size()); },
        std::out_of_range);
}

TEST_F(AgentSessionTest, HandleDataClean_SeqOutOfRange_DoesNotInsertIndex)
{
    // TODO(#38117): seq field removed from FlatBuffer schema on the agent side; see the m_seqCounter
    // note in HandleData_SeqOutOfRange_DoesNotStore. A first DataClean consumes the only declared
    // slot (seq=0) and is accepted; a second DataClean (distinct index, to tell them apart) is
    // assigned seq=1, out of range for declaredSize=1, and must not insert its own index.
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dcBuilder1;
    auto indexStr1 = dcBuilder1.CreateString("wazuh-states-fim-files");
    Wazuh::SyncSchema::DataCleanBuilder b1(dcBuilder1);
    b1.add_index(indexStr1);
    auto msg1 = b1.Finish();
    dcBuilder1.Finish(msg1);
    auto dc1 = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dcBuilder1.GetBufferPointer());
    ASSERT_NO_THROW({ session.handleDataClean(dc1); });

    flatbuffers::FlatBufferBuilder dcBuilder2;
    auto indexStr2 = dcBuilder2.CreateString("wazuh-states-fim-registry-keys");
    Wazuh::SyncSchema::DataCleanBuilder b2(dcBuilder2);
    b2.add_index(indexStr2);
    auto msg2 = b2.Finish();
    dcBuilder2.Finish(msg2);
    auto dc2 = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dcBuilder2.GetBufferPointer());

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(0);
    EXPECT_THROW({ session.handleDataClean(dc2); }, std::out_of_range);

    ASSERT_EQ(session.getContext()->dataCleanIndices.size(), 1u);
    EXPECT_TRUE(session.getContext()->dataCleanIndices.count("wazuh-states-fim-files") == 1);
    EXPECT_TRUE(session.getContext()->dataCleanIndices.count("wazuh-states-fim-registry-keys") == 0);
}

TEST_F(AgentSessionTest, HandleData_DuplicateAfterEnd_DoesNotRePush)
{
    // TODO(#38117): seq field removed from FlatBuffer schema on the agent side; the manager now
    // assigns it internally via a per-session arrival-order counter (AgentSessionImpl::m_seqCounter),
    // which cannot recognize a retransmission of the same logical item the way the agent-supplied
    // seq did. A "retransmission" now consumes a NEW counter value, which - for a session with
    // declaredSize=1 - is out of range and rejected with std::out_of_range instead of being silently
    // absorbed. This is a known, accepted regression of this temporary shim (see class-level TODO);
    // real retry/dedup semantics require the FullSession-based manager rewrite owned by the server team.
    auto startMsg = createStartMessage(1, "001");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dataBuilder;
    std::vector<int8_t> testData = {0x01};
    auto dataVector = dataBuilder.CreateVector(testData);
    Wazuh::SyncSchema::DataValueBuilder dvb(dataBuilder);
    dvb.add_data(dataVector);
    auto dvOff = dvb.Finish();
    dataBuilder.Finish(dvOff);

    auto data = flatbuffers::GetRoot<Wazuh::SyncSchema::DataValue>(dataBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size());
    session.handleEnd(mockResponseDispatcher);
    // Retransmission arrives AFTER the End has been pushed; it gets a new (out-of-range) seq.
    EXPECT_THROW(
        { session.handleData(data, reinterpret_cast<const uint8_t*>(data->data()->data()), data->data()->size()); },
        std::out_of_range);
}

TEST_F(AgentSessionTest, HandleDataContext_DuplicateAfterEnd_DoesNotRePush)
{
    // TODO(#38117): see the m_seqCounter note in HandleData_DuplicateAfterEnd_DoesNotRePush - a
    // retransmission now consumes a new (out-of-range) seq under declaredSize=1 and is rejected.
    auto startMsg = createStartMessage(1, "001");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dcBuilder;
    std::vector<int8_t> raw = {0x01};
    auto dataVec = dcBuilder.CreateVector(raw);
    Wazuh::SyncSchema::DataContextBuilder b(dcBuilder);
    b.add_data(dataVec);
    auto off = b.Finish();
    dcBuilder.Finish(off);

    auto ctx = flatbuffers::GetRoot<Wazuh::SyncSchema::DataContext>(dcBuilder.GetBufferPointer());

    EXPECT_CALL(mockStore, put(_, _)).Times(1);
    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleDataContext(ctx, reinterpret_cast<const uint8_t*>(ctx->data()->data()), ctx->data()->size());
    session.handleEnd(mockResponseDispatcher);
    EXPECT_THROW(
        { session.handleDataContext(ctx, reinterpret_cast<const uint8_t*>(ctx->data()->data()), ctx->data()->size()); },
        std::out_of_range);
}

TEST_F(AgentSessionTest, HandleDataClean_DuplicateAfterEnd_DoesNotRePush)
{
    // TODO(#38117): see the m_seqCounter note in HandleData_DuplicateAfterEnd_DoesNotRePush - a
    // retransmission now consumes a new (out-of-range) seq under declaredSize=1 and is rejected.
    auto startMsg = createStartMessage(1, "001", "test-agent", "4.0.0", "fim", Wazuh::SyncSchema::Mode_ModuleDelta);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    flatbuffers::FlatBufferBuilder dcBuilder;
    auto indexStr = dcBuilder.CreateString("wazuh-states-fim-files");
    Wazuh::SyncSchema::DataCleanBuilder b(dcBuilder);
    b.add_index(indexStr);
    auto msg = b.Finish();
    dcBuilder.Finish(msg);

    auto dc = flatbuffers::GetRoot<Wazuh::SyncSchema::DataClean>(dcBuilder.GetBufferPointer());

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    session.handleDataClean(dc);
    session.handleEnd(mockResponseDispatcher);
    // Retransmission after the End was pushed; it gets a new (out-of-range) seq.
    EXPECT_THROW({ session.handleDataClean(dc); }, std::out_of_range);
}

TEST_F(AgentSessionTest, HandleChecksumModule_AfterEnd_IsIgnored)
{
    // size=0 + Mode_ModuleCheck so the End handler pushes the Response right
    // away (no missing seqs). A late ChecksumModule must not modify the
    // context — the bulk thread could already be reading checksumIndex/checksum
    // and the agent must not race against it.
    auto startMsg =
        createStartMessage(0, "001", "test-agent", "4.0.0", "syscollector", Wazuh::SyncSchema::Mode_ModuleCheck);
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_CALL(mockIndexerQueue, push(_)).Times(1);

    // End first.
    session.handleEnd(mockResponseDispatcher);

    // Late ChecksumModule must NOT mutate the context.
    flatbuffers::FlatBufferBuilder checksumBuilder;
    auto checksumStr = checksumBuilder.CreateString("late-checksum");
    auto indexStr = checksumBuilder.CreateString("wazuh-states-vulnerabilities");
    Wazuh::SyncSchema::ChecksumModuleBuilder cmBuilder(checksumBuilder);
    cmBuilder.add_checksum(checksumStr);
    cmBuilder.add_index(indexStr);
    auto cmMsg = cmBuilder.Finish();
    checksumBuilder.Finish(cmMsg);

    auto checksumModule = flatbuffers::GetRoot<Wazuh::SyncSchema::ChecksumModule>(checksumBuilder.GetBufferPointer());
    ASSERT_NO_THROW({ session.handleChecksumModule(checksumModule); });

    EXPECT_TRUE(session.getContext()->checksum.empty());
    EXPECT_TRUE(session.getContext()->checksumIndex.empty());
}

TEST_F(AgentSessionTest, DeclaredSize_ReturnsValueFromStart)
{
    constexpr uint64_t kSize = 5;
    auto startMsg = createStartMessage(kSize, "001");
    builder.Finish(startMsg);
    auto start = flatbuffers::GetRoot<Wazuh::SyncSchema::Start>(builder.GetBufferPointer());

    AgentSessionForTest session(sessionId, start, mockStore, mockIndexerQueue, mockResponseDispatcher, s_logFn);

    EXPECT_EQ(session.declaredSize(), kSize);
}
