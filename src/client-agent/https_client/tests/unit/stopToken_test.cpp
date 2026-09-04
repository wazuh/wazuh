/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stopToken.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

using namespace std::chrono_literals;

TEST(StopTokenTest, WaitElapsesOnTheSteadyClock)
{
    Waiter waiter;
    const auto start {std::chrono::steady_clock::now()};

    EXPECT_TRUE(waiter.waitFor(150ms));

    EXPECT_GE(std::chrono::steady_clock::now() - start, 140ms);
    EXPECT_FALSE(waiter.stopRequested());
}

TEST(StopTokenTest, NotifyWakesAPendingWait)
{
    Waiter waiter;
    std::thread waker(
        [&waiter]
    {
        std::this_thread::sleep_for(50ms);
        waiter.notify();
    });

    const auto start {std::chrono::steady_clock::now()};
    const bool keepRunning {waiter.waitFor(30s)};
    const auto elapsed {std::chrono::steady_clock::now() - start};
    waker.join();

    EXPECT_TRUE(keepRunning);
    EXPECT_LT(elapsed, 5s);
}

TEST(StopTokenTest, RequestStopWakesAPendingWaitAndReportsStop)
{
    Waiter waiter;
    std::thread stopper(
        [&waiter]
    {
        std::this_thread::sleep_for(50ms);
        waiter.requestStop();
    });

    const auto start {std::chrono::steady_clock::now()};
    const bool keepRunning {waiter.waitFor(30s)};
    const auto elapsed {std::chrono::steady_clock::now() - start};
    stopper.join();

    EXPECT_FALSE(keepRunning);
    EXPECT_LT(elapsed, 5s);
    EXPECT_TRUE(waiter.stopRequested());
    EXPECT_TRUE(waiter.stopFlag()->load());
}

TEST(StopTokenTest, WaitReturnsAtOnceAfterStop)
{
    Waiter waiter;
    waiter.requestStop();

    const auto start {std::chrono::steady_clock::now()};

    EXPECT_FALSE(waiter.waitFor(30s));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
}

TEST(StopTokenTest, PendingNotifyIsConsumedByASingleWait)
{
    Waiter waiter;
    waiter.notify();

    auto start {std::chrono::steady_clock::now()};
    EXPECT_TRUE(waiter.waitFor(30s));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);

    start = std::chrono::steady_clock::now();
    EXPECT_TRUE(waiter.waitFor(100ms));
    EXPECT_GE(std::chrono::steady_clock::now() - start, 90ms);
}

TEST(StopTokenTest, NonPositiveTimeoutDoesNotBlock)
{
    Waiter waiter;
    const auto start {std::chrono::steady_clock::now()};

    EXPECT_TRUE(waiter.waitFor(0ms));
    EXPECT_TRUE(waiter.waitFor(-5ms));
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
}
