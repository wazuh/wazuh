/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/logThrottle.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

using remoted::common::LogThrottle;

// A window long enough that nothing expires mid-test.
constexpr auto LONG_WINDOW {std::chrono::seconds {60}};

// The first occurrence must be reported immediately: an operator should not have to wait a whole
// window for the first sign of trouble.
TEST(LogThrottleTest, FirstOccurrenceEmitsImmediately)
{
    LogThrottle throttle {LONG_WINDOW};

    const auto decision = throttle.record();

    EXPECT_TRUE(decision.emit);
    EXPECT_TRUE(static_cast<bool>(decision));
    EXPECT_EQ(decision.suppressed, 0U);
    EXPECT_EQ(decision.total, 1U);
    EXPECT_EQ(throttle.pending(), 0U);
}

// Everything after the first hit inside the same window stays quiet, but is still counted.
TEST(LogThrottleTest, SubsequentOccurrencesInsideTheWindowAreSuppressed)
{
    LogThrottle throttle {LONG_WINDOW};

    ASSERT_TRUE(throttle.record().emit);

    for (int i = 0; i < 99; ++i)
    {
        const auto decision = throttle.record();
        EXPECT_FALSE(decision.emit);
        EXPECT_EQ(decision.total, 0U); // a suppressed decision carries no count
    }

    EXPECT_EQ(throttle.pending(), 99U);
}

// Once the window elapses, the next occurrence is emitted and reports everything it stands for.
TEST(LogThrottleTest, NextWindowReportsTheAggregatedCount)
{
    LogThrottle throttle {std::chrono::milliseconds {50}};

    ASSERT_TRUE(throttle.record().emit);
    for (int i = 0; i < 99; ++i)
    {
        ASSERT_FALSE(throttle.record().emit);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds {80});

    const auto decision = throttle.record();
    EXPECT_TRUE(decision.emit);
    // 99 suppressed + the one that just triggered this emission.
    EXPECT_EQ(decision.total, 100U);
    EXPECT_EQ(decision.suppressed, 99U);
    EXPECT_EQ(throttle.pending(), 0U);
}

// suppressed is always total - 1, so a message rendering `total` reads correctly on the first hit
// ("1 occurrence(s)") as well as after a burst.
TEST(LogThrottleTest, TotalAlwaysExceedsSuppressedByExactlyOne)
{
    LogThrottle throttle {std::chrono::milliseconds {20}};

    for (int round = 0; round < 5; ++round)
    {
        const auto decision = throttle.record();
        ASSERT_TRUE(decision.emit) << "round " << round;
        EXPECT_EQ(decision.total, decision.suppressed + 1);
        std::this_thread::sleep_for(std::chrono::milliseconds {30});
    }
}

// The invariant that makes the aggregation trustworthy: every single record() is accounted for
// exactly once, either inside an emitted line's total or still pending. Nothing is lost, nothing
// is double-counted -- which is the whole reason the suppressed count is worth printing.
TEST(LogThrottleTest, ConcurrentRecordsNeitherLoseNorDoubleCount)
{
    constexpr int kThreads {8};
    constexpr int kPerThread {10000};

    // A tiny window so emissions actually race with the counting.
    LogThrottle throttle {std::chrono::microseconds {50}};
    std::atomic<std::uint64_t> reported {0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&throttle, &reported]
            {
                for (int i = 0; i < kPerThread; ++i)
                {
                    if (const auto decision = throttle.record())
                    {
                        reported.fetch_add(decision.total, std::memory_order_relaxed);
                    }
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(reported.load() + throttle.pending(), static_cast<std::uint64_t>(kThreads) * kPerThread);
}
