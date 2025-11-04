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

#include "router_transport.hpp"
#include "agent_sync_protocol_types.hpp"

#include <thread>
#include <chrono>
#include <atomic>

using ::testing::_;
using ::testing::Return;

/**
 * @brief Test fixture for RouterTransport
 *
 * Note: These tests focus on the RouterTransport logic. Full integration
 * tests with Router module are in test_agent_sync_protocol_router.cpp
 */
class RouterTransportTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logMessages.clear();
        callbackInvoked = false;
        callbackData.clear();
    }

    void TearDown() override
    {
        logMessages.clear();
    }

    static std::vector<std::string> logMessages;
    static bool callbackInvoked;
    static std::vector<char> callbackData;

    static void mockLogger(modules_log_level_t level, const std::string& msg)
    {
        logMessages.push_back(msg);
    }

    static void responseCallback(const std::vector<char>& data)
    {
        callbackInvoked = true;
        callbackData = data;
    }

    LoggerFunc createMockLogger()
    {
        return mockLogger;
    }

    std::function<void(const std::vector<char>&)> createResponseCallback()
    {
        return responseCallback;
    }
};

// Initialize static members
std::vector<std::string> RouterTransportTest::logMessages;
bool RouterTransportTest::callbackInvoked = false;
std::vector<char> RouterTransportTest::callbackData;

/**
 * @brief Test constructor initializes correctly
 */
TEST_F(RouterTransportTest, ConstructorInitializesCorrectly)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // Constructor should not log errors
    EXPECT_TRUE(logMessages.empty());
}

/**
 * @brief Test destructor calls shutdown
 */
TEST_F(RouterTransportTest, DestructorCallsShutdown)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    {
        RouterTransport transport("test", logger, callback);
        // Initialize router
        transport.checkStatus();
    }  // Destructor called here

    // No errors should be logged during normal shutdown
    bool hasShutdownError = false;
    for (const auto& msg : logMessages)
    {
        if (msg.find("Exception in RouterTransport shutdown") != std::string::npos)
        {
            hasShutdownError = true;
        }
    }
    EXPECT_FALSE(hasShutdownError);
}

/**
 * @brief Test checkStatus initializes router
 */
TEST_F(RouterTransportTest, CheckStatusInitializesRouter)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    bool result = transport.checkStatus();

    // Check if RouterProvider and RouterSubscriber are initialized
    EXPECT_TRUE(result);
    EXPECT_TRUE(logMessages.size() >= 2);  // Should log initialization messages
    bool hasProviderInitLog = false;
    bool hasSubscriberInitLog = false;
    for (const auto& msg : logMessages)
    {
        if (msg.find("RouterProvider started") != std::string::npos)
        {
            hasProviderInitLog = true;
        }
        if (msg.find("RouterSubscriber created") != std::string::npos)
        {
            hasSubscriberInitLog = true;
        }
    }
    EXPECT_TRUE(hasProviderInitLog);
    EXPECT_TRUE(hasSubscriberInitLog);
}

/**
 * @brief Test checkStatus returns true when router is already initialized
 */
TEST_F(RouterTransportTest, CheckStatusReturnsSuccessWhenAlreadyInitialized)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // First call
    bool result1 = transport.checkStatus();

    // Wait for subscriber to be ready
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    size_t logCountAfterFirst = logMessages.size();

    // Second call - should use cached router
    bool result2 = transport.checkStatus();

    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Third call
    bool result3 = transport.checkStatus();

    // If first succeeded, subsequent calls should also succeed
    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    EXPECT_TRUE(result3);

    EXPECT_EQ(logMessages.size(), logCountAfterFirst);  // No new logs on subsequent calls
}

/**
 * @brief Test sendMessage fails when router not initialized
 */
TEST_F(RouterTransportTest, SendMessageFailsWhenRouterNotInitialized)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // Don't call checkStatus() - router not initialized

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    // Should fail because router not initialized
    EXPECT_FALSE(result);
}

/**
 * @brief Test sendMessage succeeds when router is initialized
 */
TEST_F(RouterTransportTest, SendMessageSucceedsWhenRouterInitialized)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // Initialize router
    bool initResult = transport.checkStatus();

    // Wait for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    bool result = transport.sendMessage(message, 0);

    EXPECT_TRUE(initResult);
    EXPECT_TRUE(result);
}

/**
 * @brief Test shutdown can be called multiple times
 */
TEST_F(RouterTransportTest, ShutdownCanBeCalledMultipleTimes)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);
    transport.checkStatus();

    // Wait for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Multiple shutdown calls should not cause errors
    transport.shutdown();
    transport.shutdown();
    transport.shutdown();

    // Check no exception-related errors
    bool hasException = false;
    for (const auto& msg : logMessages)
    {
        if (msg.find("Exception") != std::string::npos)
        {
            hasException = true;
        }
    }

    EXPECT_FALSE(hasException);
}

/**
 * @brief Test re-initialization after shutdown works correctly
 */
TEST_F(RouterTransportTest, ReInitializationAfterShutdown)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // First initialization
    bool initResult1 = transport.checkStatus();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Shutdown
    transport.shutdown();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Re-initialize
    bool initResult2 = transport.checkStatus();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // If first init succeeded, re-init should also succeed or handle gracefully
    EXPECT_TRUE(initResult1);
    EXPECT_TRUE(initResult2);
}

/**
 * @brief Test shutdown without initialization
 */
TEST_F(RouterTransportTest, ShutdownWithoutInitialization)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);

    // Shutdown without initializing
    transport.shutdown();

    // Should not cause errors
    EXPECT_TRUE(logMessages.empty());
}

/**
 * @brief Test sendMessage after shutdown
 */
TEST_F(RouterTransportTest, SendMessageAfterShutdown)
{
    auto logger = createMockLogger();
    auto callback = createResponseCallback();

    RouterTransport transport("test", logger, callback);
    transport.checkStatus();

    // Wait for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    transport.shutdown();

    // Try to send after shutdown
    std::vector<uint8_t> message = {1, 2, 3};
    bool result = transport.sendMessage(message, 0);

    // Should fail
    EXPECT_FALSE(result);
}

