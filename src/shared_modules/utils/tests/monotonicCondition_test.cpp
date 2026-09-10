/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "monotonicCondition.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <thread>

using namespace std::chrono_literals;

// Regression pin: a future revert to std::condition_variable would still pass every
// stopToken_test.cpp case (none of them jump the system clock), but would fail this
// assertion, since only the pthread_condattr_setclock(CLOCK_MONOTONIC) path exists here.
TEST(MonotonicConditionTest, BindsToTheMonotonicClockOnLinux)
{
    MonotonicCondition condition;

    EXPECT_EQ(condition.clockId(), CLOCK_MONOTONIC);
}

TEST(MonotonicConditionTest, WaitForElapsesOnItsBoundClock)
{
    MonotonicCondition condition;
    std::mutex mutex;
    std::unique_lock<std::mutex> lock(mutex);
    const auto start {std::chrono::steady_clock::now()};

    EXPECT_FALSE(condition.waitFor(lock, 100ms, [] { return false; }));

    EXPECT_GE(std::chrono::steady_clock::now() - start, 90ms);
}

TEST(MonotonicConditionTest, NotifyOneWakesAPendingWait)
{
    MonotonicCondition condition;
    std::mutex mutex;
    bool ready {false};
    std::thread waker(
        [&]
        {
            std::this_thread::sleep_for(50ms);
            std::lock_guard<std::mutex> guard(mutex);
            ready = true;
            condition.notifyOne();
        });

    std::unique_lock<std::mutex> lock(mutex);
    const auto start {std::chrono::steady_clock::now()};
    const bool woken {condition.waitFor(lock, 30s, [&] { return ready; })};
    waker.join();

    EXPECT_TRUE(woken);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 5s);
}
