/*
 * Wazuh inventory sync server module - unit tests
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
#include <thread>
#include <vector>

using invsync::common::LogThrottle;

// An operator must not have to wait a whole window for the first sign of trouble.
TEST(LogThrottleTest, TheFirstOccurrenceAlwaysEmits)
{
    LogThrottle throttle;

    const auto decision = throttle.record();
    EXPECT_TRUE(decision.emit);
    EXPECT_TRUE(static_cast<bool>(decision));
    EXPECT_EQ(1U, decision.total);
    EXPECT_EQ(0U, decision.suppressed);
}

TEST(LogThrottleTest, SubsequentOccurrencesWithinTheWindowAreSuppressed)
{
    LogThrottle throttle;

    ASSERT_TRUE(throttle.record().emit);
    for (int i = 0; i < 100; ++i)
    {
        EXPECT_FALSE(throttle.record().emit);
    }
    EXPECT_EQ(100U, throttle.pending());
}

// The emitted line has to be able to say how many occurrences it stands for, or the suppression
// silently loses information.
TEST(LogThrottleTest, TheEmittedLineReportsEverySuppressedOccurrence)
{
    LogThrottle throttle {std::chrono::milliseconds {50}};

    ASSERT_TRUE(throttle.record().emit);
    for (int i = 0; i < 9; ++i)
    {
        ASSERT_FALSE(throttle.record().emit);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds {80});

    const auto decision = throttle.record();
    ASSERT_TRUE(decision.emit);
    EXPECT_EQ(10U, decision.total) << "9 suppressed plus this one";
    EXPECT_EQ(9U, decision.suppressed);
    EXPECT_EQ(0U, throttle.pending()) << "the counter must be drained by the emission";
}

TEST(LogThrottleTest, AnotherWindowEmitsAgain)
{
    LogThrottle throttle {std::chrono::milliseconds {30}};

    EXPECT_TRUE(throttle.record().emit);
    EXPECT_FALSE(throttle.record().emit);

    std::this_thread::sleep_for(std::chrono::milliseconds {50});
    EXPECT_TRUE(throttle.record().emit);
}

TEST(LogThrottleTest, TheWindowSecondsConstantMatchesTheWindow)
{
    // The rendered "in the last N s" must never drift from the period actually enforced.
    EXPECT_EQ(90, LogThrottle::kDefaultWindowSeconds);
    EXPECT_EQ(std::chrono::seconds {90}, std::chrono::duration_cast<std::chrono::seconds>(LogThrottle::kDefaultWindow));
}

// Exactly one caller per window may emit, and no occurrence may be lost or double-counted.
TEST(LogThrottleTest, ExactlyOneThreadEmitsPerWindowAndNothingIsLost)
{
    constexpr int THREADS {16};
    constexpr int PER_THREAD {1000};

    LogThrottle throttle; // the full 90 s window: only the very first record() may emit
    std::atomic<int> emissions {0};
    std::atomic<std::uint64_t> reported {0};

    std::vector<std::thread> workers;
    workers.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t)
    {
        workers.emplace_back(
            [&throttle, &emissions, &reported]
            {
                for (int i = 0; i < PER_THREAD; ++i)
                {
                    if (const auto decision = throttle.record())
                    {
                        emissions.fetch_add(1);
                        reported.fetch_add(decision.total);
                    }
                }
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_EQ(1, emissions.load()) << "at most one emission per window, whatever the contention";
    // Everything recorded is either reported by that one line or still pending -- never dropped.
    EXPECT_EQ(static_cast<std::uint64_t>(THREADS * PER_THREAD), reported.load() + throttle.pending());
}
