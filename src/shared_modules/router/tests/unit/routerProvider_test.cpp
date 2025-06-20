/*
 * Wazuh router - RouterProvider tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerProvider.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

/**
 * @brief Runs unit tests for RouterProvider class
 */
class RouterProviderTest : public ::testing::Test
{
protected:
    RouterProviderTest() = default;
    ~RouterProviderTest() override = default;
};

/*
 * @brief Tests the instantiation of the RouterProvider class for local provider
 */
TEST_F(RouterProviderTest, TestRouterProviderLocalInstantiation)
{
    const std::string topicName = "test-topic";

    EXPECT_NO_THROW(std::make_shared<RouterProvider>(topicName, true));
}

/*
 * @brief Tests the instantiation of the RouterProvider class for remote provider
 */
TEST_F(RouterProviderTest, TestRouterProviderRemoteInstantiation)
{
    const std::string topicName = "test-topic";

    EXPECT_NO_THROW(std::make_shared<RouterProvider>(topicName, false));
}

/*
 * @brief Tests RouterProvider with empty topic name
 */
TEST_F(RouterProviderTest, TestRouterProviderEmptyTopicName)
{
    EXPECT_NO_THROW(std::make_shared<RouterProvider>("", true));
}

/*
 * @brief Tests multiple RouterProvider instances with same topic name
 */
TEST_F(RouterProviderTest, TestMultipleRouterProvidersWithSameTopic)
{
    const std::string topicName = "same-topic";

    auto provider1 = std::make_shared<RouterProvider>(topicName, true);
    auto provider2 = std::make_shared<RouterProvider>(topicName, true);

    EXPECT_NE(provider1, provider2);
}

/*
 * @brief Tests RouterProvider start method for local provider
 */
TEST_F(RouterProviderTest, TestRouterProviderStartLocal)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    EXPECT_NO_THROW(provider->start());
}

/*
 * @brief Tests RouterProvider start with callback for local provider
 */
TEST_F(RouterProviderTest, TestRouterProviderStartWithCallbackLocal)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    bool callbackCalled = false;
    auto onConnect = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(provider->start(onConnect));
    EXPECT_TRUE(callbackCalled);
}

/*
 * @brief Tests RouterProvider start with callback for remote provider
 */
TEST_F(RouterProviderTest, TestRouterProviderStartWithCallbackRemote)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, false);

    bool callbackCalled = false;
    auto onConnect = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(provider->start(onConnect));
    // For remote providers, callback might not be called immediately
}

/*
 * @brief Tests RouterProvider stop method
 */
TEST_F(RouterProviderTest, TestRouterProviderStop)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    provider->start();
    EXPECT_NO_THROW(provider->stop());
}

/*
 * @brief Tests RouterProvider start/stop cycle
 */
TEST_F(RouterProviderTest, TestRouterProviderStartStopCycle)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    EXPECT_NO_THROW(provider->start());
    EXPECT_NO_THROW(provider->stop());

    // Should be able to start again
    EXPECT_NO_THROW(provider->start());
    EXPECT_NO_THROW(provider->stop());
}

/*
 * @brief Tests RouterProvider send method with valid data
 */
TEST_F(RouterProviderTest, TestRouterProviderSendValidData)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    provider->start();

    const std::vector<char> testData = {'t', 'e', 's', 't'};
    EXPECT_NO_THROW(provider->send(testData));

    provider->stop();
}

/*
 * @brief Tests RouterProvider send method with empty data
 */
TEST_F(RouterProviderTest, TestRouterProviderSendEmptyData)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    provider->start();

    const std::vector<char> emptyData;
    EXPECT_NO_THROW(provider->send(emptyData));

    provider->stop();
}

/*
 * @brief Tests RouterProvider send method with large data
 */
TEST_F(RouterProviderTest, TestRouterProviderSendLargeData)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    provider->start();

    // Create large data vector (1MB)
    const std::vector<char> largeData(1024 * 1024, 'x');
    EXPECT_NO_THROW(provider->send(largeData));

    provider->stop();
}

/*
 * @brief Tests RouterProvider send without starting
 */
TEST_F(RouterProviderTest, TestRouterProviderSendWithoutStart)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    const std::vector<char> testData = {'t', 'e', 's', 't'};
    // Should not throw, but might not work as expected
    EXPECT_NO_THROW(provider->send(testData));
}

/*
 * @brief Tests RouterProvider multiple send operations
 */
TEST_F(RouterProviderTest, TestRouterProviderMultipleSends)
{
    const std::string topicName = "test-topic";
    auto provider = std::make_shared<RouterProvider>(topicName, true);

    provider->start();

    // Send multiple messages
    for (int i = 0; i < 10; ++i)
    {
        std::string message = "message-" + std::to_string(i);
        const std::vector<char> testData(message.begin(), message.end());
        EXPECT_NO_THROW(provider->send(testData));
    }

    provider->stop();
}
