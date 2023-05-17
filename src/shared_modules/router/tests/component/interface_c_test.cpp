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
    router_start();
};

void RouterCInterfaceTest::TearDown()
{
    router_stop();
};

TEST_F(RouterCInterfaceTest, TestProviderSubscriberSimple)
{
    auto handle = router_provider_create("test");

    // TO DO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestDoubleProviderInit)
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

