/**
 * Wazuh Inventory Sync - ResponseDispatcher Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "flatbuffers/flatbuffers.h"
#include "responseDispatcher.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace ::testing;

// Mock for the TQueue
class MockResponseQueue
{
public:
    MOCK_METHOD(void, push, (ResponseMessage && message));
};

class ResponseDispatcherTest : public ::testing::Test
{
protected:
    using ResponseDispatcherForTest = ResponseDispatcherImpl<MockResponseQueue>;
};

TEST_F(ResponseDispatcherTest, SendStartAck)
{
    auto* mockQueue = new StrictMock<MockResponseQueue>();
    ResponseDispatcherForTest dispatcher(mockQueue);

    std::string agentId = "001";
    uint64_t sessionId = 12345;
    std::string moduleName = "syscollector";

    EXPECT_CALL(*mockQueue, push(_))
        .WillOnce(Invoke(
            [&](ResponseMessage&& responseMsg)
            {
                auto msg = flatbuffers::GetRoot<Wazuh::SyncSchema::Message>(responseMsg.builder.GetBufferPointer());
                ASSERT_EQ(msg->content_type(), Wazuh::SyncSchema::MessageType_StartAck);

                auto startAck = msg->content_as_StartAck();
                ASSERT_NE(startAck, nullptr);
                EXPECT_EQ(startAck->status(), Wazuh::SyncSchema::Status_Ok);
                EXPECT_EQ(startAck->session(), 12345);
                // Note: StartAck schema doesn't include module field
            }));

    dispatcher.sendStartAck(Wazuh::SyncSchema::Status_Ok, agentId, sessionId, moduleName);
}

TEST_F(ResponseDispatcherTest, SendEndAck)
{
    auto* mockQueue = new StrictMock<MockResponseQueue>();
    ResponseDispatcherForTest dispatcher(mockQueue);

    std::string agentId = "002";
    uint64_t sessionId = 54321;
    std::string moduleName = "another_module";

    EXPECT_CALL(*mockQueue, push(_))
        .WillOnce(Invoke(
            [&](ResponseMessage&& responseMsg)
            {
                auto msg = flatbuffers::GetRoot<Wazuh::SyncSchema::Message>(responseMsg.builder.GetBufferPointer());
                ASSERT_EQ(msg->content_type(), Wazuh::SyncSchema::MessageType_EndAck);

                auto endAck = msg->content_as_EndAck();
                ASSERT_NE(endAck, nullptr);
                EXPECT_EQ(endAck->status(), Wazuh::SyncSchema::Status_Error);
                EXPECT_EQ(endAck->session(), 54321);
                // Note: EndAck schema doesn't include module field
            }));

    dispatcher.sendEndAck(Wazuh::SyncSchema::Status_Error, agentId, sessionId, moduleName);
}

TEST_F(ResponseDispatcherTest, SendEndMissingSeq)
{
    auto* mockQueue = new StrictMock<MockResponseQueue>();
    ResponseDispatcherForTest dispatcher(mockQueue);

    uint64_t sessionId = 98765;
    std::vector<std::pair<uint64_t, uint64_t>> ranges = {{1, 5}, {8, 10}};

    EXPECT_CALL(*mockQueue, push(_))
        .WillOnce(Invoke(
            [&](ResponseMessage&& responseMsg)
            {
                auto msg = flatbuffers::GetRoot<Wazuh::SyncSchema::Message>(responseMsg.builder.GetBufferPointer());
                ASSERT_EQ(msg->content_type(), Wazuh::SyncSchema::MessageType_ReqRet);

                auto reqRet = msg->content_as_ReqRet();
                ASSERT_NE(reqRet, nullptr);
                EXPECT_EQ(reqRet->session(), 98765);

                auto receivedRanges = reqRet->seq();
                ASSERT_EQ(receivedRanges->size(), 2);
                EXPECT_EQ(receivedRanges->Get(0)->begin(), 1);
                EXPECT_EQ(receivedRanges->Get(0)->end(), 5);
                EXPECT_EQ(receivedRanges->Get(1)->begin(), 8);
                EXPECT_EQ(receivedRanges->Get(1)->end(), 10);
            }));

    dispatcher.sendEndMissingSeq("001", sessionId, "test_module", ranges);
}
