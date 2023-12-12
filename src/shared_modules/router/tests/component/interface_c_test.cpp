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
#include "remoteStateHelper.hpp"
#include "router.h"
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

void RouterCInterfaceTestNoSetUp::TearDown()
{
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
};

TEST_F(RouterCInterfaceTest, TestProviderSubscriberSimple)
{
    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestDoubleSubscriberInit)
{
    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSend)
{
    EXPECT_EQ(router_provider_send("test", "test", 4), 0);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendNull)
{
    EXPECT_EQ(router_provider_send("test", nullptr, 4), -1);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendZero)
{
    EXPECT_EQ(router_provider_send("test", "test", 0), -1);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderSendAndDestroy)
{
    EXPECT_EQ(router_provider_send("test", "test", 4), 0);

    EXPECT_NO_THROW(router_provider_destroy("test"));

    // TODO - Add C interface for subscribers.
}

/**
 * @brief We simulate the crash of the broker and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestRemoveProviderWithServerDown)
{
    router_start();

    EXPECT_EQ(router_provider_send("test", "test", 4), 0);

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    EXPECT_NO_THROW(router_provider_destroy("test"));

    // It shouldn't hang here
}
