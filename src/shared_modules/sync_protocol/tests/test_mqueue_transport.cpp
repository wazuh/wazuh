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

#include "mqueue_transport.hpp"
#include "agent_sync_protocol_c_interface_types.h"
#include "defs.h"

#include <thread>
#include <chrono>
#include <atomic>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgReferee;

/**
 * @brief Test fixture for MQueueTransport
 */
class MQueueTransportTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logMessages.clear();
        mqStartCalls = 0;
        mqSendCalls = 0;
        mqStartReturnValue = 1;  // Valid queue descriptor
        mqSendReturnValue = 0;   // Success
        shouldThrowException = false;
    }

    void TearDown() override
    {
        logMessages.clear();
    }

    // Mock state
    static std::vector<std::string> logMessages;
    static int mqStartCalls;
    static int mqSendCalls;
    static int mqStartReturnValue;
    static int mqSendReturnValue;
    static bool shouldThrowException;

    // Mock MQ_Functions
    static int mockMqStart(const char* path, short type, short n)
    {
        mqStartCalls++;
        if (shouldThrowException)
        {
            throw std::runtime_error("MQ start error");
        }
        return mqStartReturnValue;
    }

    static int mockMqSendBinary(int queue, const void* buffer, size_t size, const char* module, char mq_type)
    {
        mqSendCalls++;
        return mqSendReturnValue;
    }

    static void mockLogger(modules_log_level_t level, const std::string& msg)
    {
        logMessages.push_back(msg);
    }

    MQ_Functions createMockMqFunctions()
    {
        return MQ_Functions
        {
            mockMqStart,
            mockMqSendBinary
        };
    }

    LoggerFunc createMockLogger()
    {
        return mockLogger;
    }
};

// Initialize static members
std::vector<std::string> MQueueTransportTest::logMessages;
int MQueueTransportTest::mqStartCalls = 0;
int MQueueTransportTest::mqSendCalls = 0;
int MQueueTransportTest::mqStartReturnValue = 1;
int MQueueTransportTest::mqSendReturnValue = 0;
bool MQueueTransportTest::shouldThrowException = false;

/**
 * @brief Test constructor initializes correctly
 */
TEST_F(MQueueTransportTest, ConstructorInitializesCorrectly)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();

    MQueueTransport transport("test_module", mqFuncs, logger);

    // Constructor should not call any MQ functions yet
    EXPECT_EQ(mqStartCalls, 0);
    EXPECT_EQ(mqSendCalls, 0);
    EXPECT_TRUE(logMessages.empty());
}

/**
 * @brief Test shutdown does nothing
 */
TEST_F(MQueueTransportTest, ShutdownDoesNothing)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();

    MQueueTransport transport("test_module", mqFuncs, logger);
    
    transport.shutdown();

    // Constructor should not call any MQ functions yet
    EXPECT_EQ(mqStartCalls, 0);
    EXPECT_EQ(mqSendCalls, 0);
    EXPECT_TRUE(logMessages.empty());
}

/**
 * @brief Test checkStatus succeeds when queue is available
 */
TEST_F(MQueueTransportTest, CheckStatusSucceedsWhenQueueAvailable)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqStartReturnValue = 5;  // Valid queue descriptor

    MQueueTransport transport("test_module", mqFuncs, logger);

    bool result = transport.checkStatus();

    EXPECT_TRUE(result);
    EXPECT_EQ(mqStartCalls, 1);
    EXPECT_TRUE(logMessages.empty());
}

/**
 * @brief Test checkStatus fails when queue cannot be opened
 */
TEST_F(MQueueTransportTest, CheckStatusFailsWhenQueueUnavailable)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqStartReturnValue = -1;  // Failure

    MQueueTransport transport("test_module", mqFuncs, logger);

    bool result = transport.checkStatus();

    EXPECT_FALSE(result);
    EXPECT_EQ(mqStartCalls, 1);
    EXPECT_EQ(logMessages.size(), 1);
    EXPECT_TRUE(logMessages[0].find("Failed to open queue") != std::string::npos);
}

/**
 * @brief Test checkStatus caches queue descriptor (doesn't reopen)
 */
TEST_F(MQueueTransportTest, CheckStatusCachesQueueDescriptor)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqStartReturnValue = 5;

    MQueueTransport transport("test_module", mqFuncs, logger);

    transport.checkStatus();
    transport.checkStatus();
    transport.checkStatus();

    // Queue should only be opened once
    EXPECT_EQ(mqStartCalls, 1);
}

/**
 * @brief Test checkStatus caches exception
 */
TEST_F(MQueueTransportTest, CheckStatusCachesException)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqStartReturnValue = -1;
    shouldThrowException = true;

    MQueueTransport transport("test_module", mqFuncs, logger);

    transport.checkStatus();

    // Queue should only be opened once
    EXPECT_EQ(mqStartCalls, 1);
    EXPECT_EQ(logMessages.size(), 2);
    EXPECT_TRUE(logMessages[0].find("Exception when checking queue availability") != std::string::npos);
    EXPECT_TRUE(logMessages[1].find("Failed to open queue") != std::string::npos);
}

/**
 * @brief Test sendMessage succeeds
 */
TEST_F(MQueueTransportTest, SendMessageSucceeds)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqSendReturnValue = 0;  // Success

    MQueueTransport transport("test_module", mqFuncs, logger);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    EXPECT_TRUE(result);
    EXPECT_EQ(mqSendCalls, 1);
}

/**
 * @brief Test m_msgSent resets after reaching maxEps
 */
TEST_F(MQueueTransportTest, SendMessageSucceedsWithEps)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqSendReturnValue = 0;  // Success

    MQueueTransport transport("test_module", mqFuncs, logger);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result1 = transport.sendMessage(message, 1);
    bool result2 = transport.sendMessage(message, 1);

    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    EXPECT_EQ(mqSendCalls, 2);
}

/**
 * @brief Test sendMessage succeeds
 */
TEST_F(MQueueTransportTest, SendMessageSucceedsAfterQueueReinit)
{
    auto logger = createMockLogger();
    mqStartReturnValue = 5;

    MQ_Functions customMqFuncs
    {
        mockMqStart,
        [](int queue, const void* buffer, size_t size, const char* module, char mq_type) -> int
        {
            mqSendCalls++;
            static int count = 0;
            count++;
            if (count == 1)
            {
                return -1;
            }
            return 5;
        }
    };

    MQueueTransport transport("test_module", customMqFuncs, logger);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    EXPECT_TRUE(result);
    EXPECT_EQ(mqSendCalls, 2);
    EXPECT_EQ(mqStartCalls, 1);  // Opens queue once for reinit
    EXPECT_EQ(logMessages.size(), 1);
    EXPECT_TRUE(logMessages[0].find("SendMSG failed, attempting to reinitialize queue") != std::string::npos);
}

/**
 * @brief Test sendMessage fails after retry
 */
TEST_F(MQueueTransportTest, SendMessageFailsAfterRetry)
{
    auto mqFuncs = createMockMqFunctions();
    auto logger = createMockLogger();
    mqStartReturnValue = 5;
    mqSendReturnValue = -1;

    MQueueTransport transport("test_module", mqFuncs, logger);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    EXPECT_FALSE(result);
    EXPECT_EQ(mqSendCalls, 2);
    EXPECT_EQ(mqStartCalls, 1);  // Opens queue once for reinit
    EXPECT_EQ(logMessages.size(), 2);
    EXPECT_TRUE(logMessages[0].find("SendMSG failed, attempting to reinitialize queue") != std::string::npos);
    EXPECT_TRUE(logMessages[1].find("SendMSG failed to send message after retry") != std::string::npos);
}

/**
 * @brief Test sendMessage fails when queue reinit fails
 */
TEST_F(MQueueTransportTest, SendMessageFailsWhenQueueReinitFails)
{
    auto logger = createMockLogger();
    mqStartReturnValue = -1;

    MQ_Functions customMqFuncs
    {
        mockMqStart,
        [](int queue, const void* buffer, size_t size, const char* module, char mq_type) -> int
        {
            mqSendCalls++;
            static int count = 0;
            count++;
            if (count == 1)
            {
                return -1;
            }
            return 5;
        }
    };

    MQueueTransport transport("test_module", customMqFuncs, logger);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    EXPECT_FALSE(result);
    EXPECT_EQ(mqSendCalls, 1);  //  send_binary is not called again on reinit failure
    EXPECT_EQ(mqStartCalls, 1);  // Opens queue once for reinit
    EXPECT_EQ(logMessages.size(), 2);
    EXPECT_TRUE(logMessages[0].find("SendMSG failed, attempting to reinitialize queue") != std::string::npos);
    EXPECT_TRUE(logMessages[1].find("SendMSG failed to send message after retry") != std::string::npos);
}

