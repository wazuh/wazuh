/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <uds_http_server/logThrottle.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using wazuh::uds_http::LogThrottle;

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
    // The window an operator is told about must never drift from the period actually enforced.
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

// The emitted line must be able to say what period its count really covers: suppressed
// occurrences are only reported by the next one, which can arrive long after the window, so a
// message that printed the window length would misattribute them.
TEST(LogThrottleTest, EmissionReportsTheRealTimeSinceThePreviousOne)
{
    LogThrottle throttle {std::chrono::seconds {1}};

    const auto first = throttle.record();
    ASSERT_TRUE(first.emit);
    EXPECT_EQ(first.secondsSinceLastEmit, -1) << "the first emission has no previous one";

    ASSERT_FALSE(throttle.record().emit);
    std::this_thread::sleep_for(std::chrono::milliseconds {1200});

    const auto second = throttle.record();
    ASSERT_TRUE(second.emit);
    EXPECT_EQ(second.total, 2U);
    EXPECT_GE(second.secondsSinceLastEmit, 1);
    EXPECT_LT(second.secondsSinceLastEmit, 30);

    EXPECT_EQ(throttle.record().secondsSinceLastEmit, -1) << "a suppressed decision carries no period";
}

// The wording every throttled line uses for its count: never the window length, which is wrong on
// the first emission (it covers only itself) and after any quiet stretch longer than the window.
TEST(LogThrottleTest, PeriodNamesTheRealSpanNotTheWindow)
{
    LogThrottle::Decision first {true, 0, 1, -1};
    EXPECT_EQ(first.period(), "so far");

    LogThrottle::Decision later {true, 4, 5, 312};
    EXPECT_EQ(later.period(), "in the last 312 s");

    LogThrottle throttle;
    EXPECT_EQ(throttle.record().period(), "so far") << "the first real emission";
}
