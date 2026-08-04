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
                // TODO(#38117): session field removed from agent FlatBuffer schema
                // EXPECT_EQ(endAck->session(), 54321);
                // Note: EndAck schema doesn't include module field
            }));

    dispatcher.sendEndAck(Wazuh::SyncSchema::Status_Error, agentId, sessionId, moduleName);
}
