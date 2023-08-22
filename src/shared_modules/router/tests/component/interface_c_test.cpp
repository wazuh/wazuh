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
#include "router.h"
#include <chrono>
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

TEST_F(RouterCInterfaceTest, TestProviderSubscriberSimple)
{
    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, DISABLED_TestDoubleProviderInit)
{
    auto handle = router_provider_create("test");
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_create("test"), nullptr);
}

TEST_F(RouterCInterfaceTest, TestDoubleSubscriberInit)
{
    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSend)
{
    auto handle = router_provider_create("test");
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendNull)
{
    auto handle = router_provider_create("test");
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, nullptr, 4), -1);

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendZero)
{
    auto handle = router_provider_create("test");
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 0), -1);

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendAndDestroy)
{
    auto handle = router_provider_create("test");

    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    EXPECT_NO_THROW(router_provider_destroy(handle));

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderWithEmptyTopicName)
{
    auto handle = router_provider_create("");

    EXPECT_EQ(handle, nullptr);

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestTwoProvidersWithTheSameTopicName)
{
    auto handle1 = router_provider_create("test-provider");

    EXPECT_NE(handle1, nullptr);

    auto handle2 = router_provider_create("test-provider");

    EXPECT_EQ(handle2, nullptr);

    // TO DO - Add C interface for subscribers.
}
