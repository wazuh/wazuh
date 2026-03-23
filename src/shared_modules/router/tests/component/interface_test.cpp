/*
 * Wazuh router - Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "interface_test.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <chrono>
#include <future>
#include <thread>

void RouterInterfaceTest::SetUp()
{
    RouterModule::instance().start();
};
void RouterInterfaceTest::TearDown()
{
    RouterModule::instance().stop();
};

TEST_F(RouterInterfaceTest, TestCreateProviderSubscriberSimple)
{
    auto provider {std::make_unique<RouterProvider>("test")};

    // Simulate call from specific provider in the same process
    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_NO_THROW({
        auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
}

TEST_F(RouterInterfaceTest, TestStopLocalProviderWithoutStart)
{
    auto provider {std::make_unique<RouterProvider>("test")};

    EXPECT_THROW(provider->stop(), std::runtime_error);
}

TEST_F(RouterInterfaceTest, TestCreateSubscriberWithoutProvider)
{
    EXPECT_NO_THROW({
        auto subscriber = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriber->subscribe([](const std::vector<char>&) {});
    });
}

TEST_F(RouterInterfaceTest, TestDoubleProviderInit)
{
    auto provider {std::make_unique<RouterProvider>("test")};

    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_NO_THROW({ provider->start(); });
}

/**
 * @brief Test that a subscriber can be created after a provider is started
 * double subscription is allowed and the second one replaces the first one.
 */
TEST_F(RouterInterfaceTest, TestDoubleSubscriberInit)
{
    auto provider {std::make_unique<RouterProvider>("test")};

    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    EXPECT_NO_THROW({ provider->start(); });

    EXPECT_NO_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); });

    EXPECT_NO_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); });

    EXPECT_NO_THROW({
        subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
}

TEST_F(RouterInterfaceTest, TestSendMessage)
{
    auto provider {std::make_unique<RouterProvider>("test")};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    EXPECT_NO_THROW({ provider->start(); });

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                // Count messages
                count++;
            });
    });

    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }

    provider->stop();
    provider.reset();

    EXPECT_EQ(count, MESSAGE_COUNT);
}

TEST_F(RouterInterfaceTest, TestSendMessageAfterSubscribeRemove)
{
    auto provider {std::make_unique<RouterProvider>("test")};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    EXPECT_NO_THROW({ provider->start(); });

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                // Count messages
                count++;
            });
        subscriptor.reset();
    });

    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }

    EXPECT_EQ(count, 0);
}

TEST_F(RouterInterfaceTest, TestSendMessageAfterProviderShutdown)
{
    auto provider {std::make_unique<RouterProvider>("test")};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    EXPECT_NO_THROW({ provider->start(); });

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                // Count messages
                count++;
            });
        provider->stop();
    });
    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_ANY_THROW({ provider->send(payload); });
    }

    EXPECT_EQ(count, 0);
}

///////////

TEST_F(RouterInterfaceTest, TestRemoteCreateProviderSubscriberSimple)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe([](const std::vector<char>&) {});
        subscriptor.reset();
    });
}

TEST_F(RouterInterfaceTest, TestStopRemoteProviderWithoutStart)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};

    EXPECT_THROW(provider->stop(), std::runtime_error);
}

TEST_F(RouterInterfaceTest, TestRemoteDoubleProviderInit)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_THROW({ provider->start(); }, std::runtime_error);
}

TEST_F(RouterInterfaceTest, TestRemoteDoubleSubscriberInit)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
    EXPECT_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); }, std::runtime_error);

    EXPECT_NO_THROW({ subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false); });
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessageFirstSubscribe)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};
    std::promise<void> promiseSubscriber;
    std::promise<void> promiseSubscriberConnected;

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                //  Count messages
                count++;
                if (count == MESSAGE_COUNT)
                {
                    promiseSubscriber.set_value();
                }
            },
            [&]() { promiseSubscriberConnected.set_value(); });

        promiseSubscriberConnected.get_future().wait();

        provider->start();

        for (int i = 0; i < MESSAGE_COUNT; i++)
        {
            EXPECT_NO_THROW({ provider->send(payload); });
        }
    });

    promiseSubscriber.get_future().wait_for(std::chrono::milliseconds(5000));

    provider->stop();
    provider.reset();

    EXPECT_EQ(count, MESSAGE_COUNT);
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessageFirstProvider)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};
    std::promise<void> promiseSubscriber;
    std::promise<void> promiseSubscriberConnected;

    EXPECT_NO_THROW({
        std::promise<void> promise;
        provider->start([&]() { promise.set_value(); });
        promise.get_future().wait();
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                //  Count messages
                count++;

                if (count == MESSAGE_COUNT)
                {
                    promiseSubscriber.set_value();
                }
            },
            [&]() { promiseSubscriberConnected.set_value(); });
    });
    promiseSubscriberConnected.get_future().wait();

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }
    promiseSubscriber.get_future().wait();

    provider->stop();
    provider.reset();

    EXPECT_EQ(count, MESSAGE_COUNT);
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessageAfterSubscribeRemove)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);
    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                // Count messages
                count++;
            });
        subscriptor.reset();
    });
    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }

    EXPECT_EQ(count, 0);
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessageAfterProviderShutdown)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);
    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 3);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "abc");
                // Count messages
                count++;
            });
        provider->stop();
    });
    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        // TO DO - If the provider is stopped, the message is not sent.
        // EXPECT_ANY_THROW({ provider->send(payload); });
    }

    EXPECT_EQ(count, 0);
}

TEST_F(RouterInterfaceTestNoBroker, ShutdownWithoutBrokerProvider)
{
    auto provider {std::make_unique<RouterProvider>("test", false)};

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 5;

    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    EXPECT_NO_THROW({ provider->start(); });

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }

    provider->stop();
    provider.reset();
}

TEST_F(RouterInterfaceTestNoBroker, ShutdownWithoutBrokerSubscriber)
{
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    EXPECT_NO_THROW({ subscriptor->subscribe([&](const std::vector<char>& message) {}); });

    subscriptor.reset();
}
