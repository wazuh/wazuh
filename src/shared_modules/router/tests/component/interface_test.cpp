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
#include <thread>

void RouterInterfaceTest::SetUp()
{
    RouterModule::instance().initialize(nullptr);
};
void RouterInterfaceTest::TearDown()
{
    RouterModule::instance().destroy();
};

TEST_F(RouterInterfaceTest, TestCreateProviderSubscriberSimple)
{
    auto provider = std::make_unique<RouterProvider>("test");

    // Simulate call from specific provider in the same process
    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_NO_THROW({
        auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
}

TEST_F(RouterInterfaceTest, TestDoubleProviderInit)
{
    auto provider = std::make_unique<RouterProvider>("test");

    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_THROW({ provider->start(); }, std::runtime_error);
}

TEST_F(RouterInterfaceTest, TestDoubleSubscriberInit)
{
    auto provider = std::make_unique<RouterProvider>("test");

    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    EXPECT_NO_THROW({ provider->start(); });

    EXPECT_NO_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); });

    EXPECT_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); }, std::runtime_error);

    EXPECT_NO_THROW({
        subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
}

TEST_F(RouterInterfaceTest, TestSendMessage)
{
    auto provider = std::make_unique<RouterProvider>("test");
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    static std::atomic<int> count = 0;
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

    provider.reset();

    EXPECT_EQ(count, MESSAGE_COUNT);
}

TEST_F(RouterInterfaceTest, TestSendMessageAfterSubscribeRemove)
{
    auto provider = std::make_unique<RouterProvider>("test");
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    static std::atomic<int> count = 0;
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
    auto provider = std::make_unique<RouterProvider>("test");
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    static std::atomic<int> count = 0;
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
        provider.reset();
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
    auto provider = std::make_unique<RouterProvider>("test", false);
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe([](const std::vector<char>&) {});
        subscriptor.reset();
    });
}

TEST_F(RouterInterfaceTest, TestRemoteDoubleProviderInit)
{
    auto provider = std::make_unique<RouterProvider>("test", false);
    EXPECT_NO_THROW({ provider->start(); });
    EXPECT_THROW({ provider->start(); }, std::runtime_error);
}

TEST_F(RouterInterfaceTest, TestRemoteDoubleSubscriberInit)
{
    auto provider = std::make_unique<RouterProvider>("test", false);
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    EXPECT_NO_THROW({
        provider->start();
        subscriptor->subscribe([](const std::vector<char>&) {});
    });
    EXPECT_THROW({ subscriptor->subscribe([](const std::vector<char>&) {}); }, std::runtime_error);

    EXPECT_NO_THROW({ subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false); });
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessage)
{
    auto provider = std::make_unique<RouterProvider>("test", false);
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);

    static std::atomic<int> count = 0;
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
                //  Count messages
                count++;
            });
    });
    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_NO_THROW({ provider->send(payload); });
    }

    provider.reset();

    EXPECT_EQ(count, MESSAGE_COUNT);
}

TEST_F(RouterInterfaceTest, TestRemoteSendMessageAfterSubscribeRemove)
{
    auto provider = std::make_unique<RouterProvider>("test", false);
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);
    static std::atomic<int> count = 0;
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
    auto provider = std::make_unique<RouterProvider>("test", false);
    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest", false);
    static std::atomic<int> count = 0;
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
        provider.reset();
    });
    auto payloadString = std::string("abc");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};

    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        EXPECT_ANY_THROW({ provider->send(payload); });
    }

    EXPECT_EQ(count, 0);
}
