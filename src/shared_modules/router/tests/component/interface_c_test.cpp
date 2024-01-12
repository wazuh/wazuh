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

#include "interface_c_test.hpp"
#include "remoteSubscriptionManager.hpp"
#include "router.h"
#include "routerSubscriber.hpp"
#include <chrono>
#include <filesystem>
#include <thread>

void RouterCInterfaceTest::SetUp()
{
    if (router_start() != 0)
    {
        FAIL() << "Failed to start router";
    }
};

void RouterCInterfaceTest::TearDown()
{
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
};

void RouterCInterfaceTestNoSetUp::TearDown() {};

TEST_F(RouterCInterfaceTest, DISABLED_TestDoubleProviderInit)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_create("test", false), nullptr);
}

TEST_F(RouterCInterfaceTest, TestDoubleSubscriberInit)
{
    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSend)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendNull)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, nullptr, 4), -1);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendZero)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 0), -1);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendAndDestroy)
{
    auto handle {router_provider_create("test", false)};

    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    EXPECT_NO_THROW(router_provider_destroy(handle));

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderWithEmptyTopicName)
{
    auto handle {router_provider_create("", false)};

    EXPECT_EQ(handle, nullptr);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestTwoProvidersWithTheSameTopicName)
{
    auto handle1 {router_provider_create("test-provider", false)};

    EXPECT_NE(handle1, nullptr);

    auto handle2 {router_provider_create("test-provider", false)};

    EXPECT_EQ(handle2, nullptr);

    // TODO - Add C interface for subscribers.
}

/**
 * @brief We simulate the crash of the broker and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestRemoveProviderWithServerDown)
{
    router_start();

    ROUTER_PROVIDER_HANDLE provider = router_provider_create("test", false);
    if (nullptr == provider)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    EXPECT_NO_THROW(router_provider_destroy(provider));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
}

/**
 * @brief We simulate send data to a provider after the broker crash and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestRemoveBrokerBeforeProvider)
{
    router_start();

    ROUTER_PROVIDER_HANDLE handle = router_provider_create("test", false);
    if (nullptr == handle)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }

    EXPECT_EQ(router_provider_send(handle, "test", 4), -1);
    EXPECT_EQ(router_provider_send(handle, "test", 4), -1);
}

/**
 * @brief We simulate send data to a provider after the broker crash and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestSendMessageAfterBrokerRestart)
{
    router_start();

    ROUTER_PROVIDER_HANDLE handle = router_provider_create("test", false);
    if (nullptr == handle)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }

    router_start();

    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 2;

    auto payloadString = std::string("test");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};
    std::promise<void> promiseSubscriber;
    std::promise<void> promiseSubscriberConnected;

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 4);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "test");
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

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);
    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    promiseSubscriber.get_future().wait();

    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
}
