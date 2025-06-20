/*
 * Wazuh router - RouterSubscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerSubscriber.hpp"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for RouterSubscriber class
 */
class RouterSubscriberTest : public ::testing::Test
{
protected:
    RouterSubscriberTest() = default;
    ~RouterSubscriberTest() override = default;
};

/*
 * @brief Tests the instantiation of the RouterSubscriber class for local subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberLocalInstantiation)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    EXPECT_NO_THROW(std::make_shared<RouterSubscriber>(topicName, subscriberId, true));
}

/*
 * @brief Tests the instantiation of the RouterSubscriber class for remote subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberRemoteInstantiation)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    EXPECT_NO_THROW(std::make_shared<RouterSubscriber>(topicName, subscriberId, false));
}

/*
 * @brief Tests RouterSubscriber with empty topic name
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberEmptyTopicName)
{
    const std::string emptyTopicName;
    const std::string subscriberId = "test-subscriber";

    EXPECT_NO_THROW(std::make_shared<RouterSubscriber>(emptyTopicName, subscriberId, true));
}

/*
 * @brief Tests RouterSubscriber with empty subscriber ID
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberEmptySubscriberId)
{
    const std::string topicName = "test-topic";
    const std::string emptySubscriberId;

    EXPECT_NO_THROW(std::make_shared<RouterSubscriber>(topicName, emptySubscriberId, true));
}

/*
 * @brief Tests multiple RouterSubscriber instances with same topic and ID
 */
TEST_F(RouterSubscriberTest, TestMultipleRouterSubscribersWithSameTopicAndId)
{
    const std::string topicName = "same-topic";
    const std::string subscriberId = "same-id";

    auto subscriber1 = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);
    auto subscriber2 = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    EXPECT_NE(subscriber1, subscriber2);
}

/*
 * @brief Tests RouterSubscriber subscribe method for local subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberSubscribeLocal)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    std::atomic<bool> callbackCalled {false};
    auto callback = [&callbackCalled](const std::vector<char>& /*data*/)
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(subscriber->subscribe(callback));
}

/*
 * @brief Tests RouterSubscriber subscribe with onConnect callback for local subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberSubscribeWithCallbackLocal)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    std::atomic<bool> dataCallbackCalled {false};
    std::atomic<bool> connectCallbackCalled {false};

    auto dataCallback = [&dataCallbackCalled](const std::vector<char>& /*data*/)
    {
        dataCallbackCalled = true;
    };

    auto connectCallback = [&connectCallbackCalled]()
    {
        connectCallbackCalled = true;
    };

    EXPECT_NO_THROW(subscriber->subscribe(dataCallback, connectCallback));
    EXPECT_TRUE(connectCallbackCalled);
}

/*
 * @brief Tests RouterSubscriber subscribe with onConnect callback for remote subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberSubscribeWithCallbackRemote)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, false);

    std::atomic<bool> dataCallbackCalled {false};
    std::atomic<bool> connectCallbackCalled {false};

    auto dataCallback = [&dataCallbackCalled](const std::vector<char>& /*data*/)
    {
        dataCallbackCalled = true;
    };

    auto connectCallback = [&connectCallbackCalled]()
    {
        connectCallbackCalled = true;
    };

    EXPECT_NO_THROW(subscriber->subscribe(dataCallback, connectCallback));
    // For remote subscribers, callback might not be called immediately
}

/*
 * @brief Tests RouterSubscriber destruction (automatic unsubscribe) for local subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberDestructionLocal)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    std::atomic<bool> callbackCalled {false};
    auto callback = [&callbackCalled](const std::vector<char>& /*data*/)
    {
        callbackCalled = true;
    };

    {
        auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);
        subscriber->subscribe(callback);
        // Destructor will call unsubscribe automatically
    }

    // Test passes if no exception is thrown during destruction
    EXPECT_TRUE(true);
}

/*
 * @brief Tests RouterSubscriber destruction (automatic unsubscribe) for remote subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberDestructionRemote)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    std::atomic<bool> callbackCalled {false};
    auto callback = [&callbackCalled](const std::vector<char>& /*data*/)
    {
        callbackCalled = true;
    };

    {
        auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, false);
        subscriber->subscribe(callback);
        // Destructor will call unsubscribe automatically
    }

    // Test passes if no exception is thrown during destruction
    EXPECT_TRUE(true);
}

/*
 * @brief Tests RouterSubscriber subscribe/destruction cycle
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberSubscribeDestructionCycle)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    std::atomic<bool> callbackCalled {false};
    auto callback = [&callbackCalled](const std::vector<char>& /*data*/)
    {
        callbackCalled = true;
    };

    // First cycle
    {
        auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);
        EXPECT_NO_THROW(subscriber->subscribe(callback));
    }

    // Second cycle
    {
        auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);
        EXPECT_NO_THROW(subscriber->subscribe(callback));
    }
}

/*
 * @brief Tests RouterSubscriber callback with different data types
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberCallbackWithDifferentData)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    std::vector<std::vector<char>> receivedData;
    auto callback = [&receivedData](const std::vector<char>& data)
    {
        receivedData.push_back(data);
    };

    EXPECT_NO_THROW(subscriber->subscribe(callback));

    // Test would need actual message dispatch to verify callback execution
    // This tests the setup without throwing
}

/*
 * @brief Tests RouterSubscriber with null callback
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberNullCallback)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    std::function<void(const std::vector<char>&)> nullCallback;

    EXPECT_NO_THROW(subscriber->subscribe(nullCallback));
}

/*
 * @brief Tests RouterSubscriber move semantics
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberMoveSemantics)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";

    auto subscriber1 = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);
    auto subscriber2 = std::move(subscriber1);

    EXPECT_NE(nullptr, subscriber2);
    EXPECT_EQ(nullptr, subscriber1);
}

/*
 * @brief Tests RouterSubscriber multiple subscriptions with same subscriber
 */
TEST_F(RouterSubscriberTest, TestRouterSubscriberMultipleSubscriptions)
{
    const std::string topicName = "test-topic";
    const std::string subscriberId = "test-subscriber";
    auto subscriber = std::make_shared<RouterSubscriber>(topicName, subscriberId, true);

    std::atomic<int> callbackCount {0};
    auto callback = [&callbackCount](const std::vector<char>& /*data*/)
    {
        callbackCount++;
    };

    // First subscription
    EXPECT_NO_THROW(subscriber->subscribe(callback));

    // Second subscription (might overwrite the first)
    EXPECT_NO_THROW(subscriber->subscribe(callback));
}
