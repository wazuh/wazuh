/*
 * Wazuh remoted module - Control metrics unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/metrics.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

using namespace remoted::control;

// Zero-value default: all counters start at 0. Guards against a future refactor
// that initialises them non-atomically or with a non-zero default.
TEST(ControlMetricsTest, DefaultsToZero)
{
    ControlMetrics m;
    EXPECT_EQ(m.startupCount.load(), 0U);
    EXPECT_EQ(m.notifyCount.load(), 0U);
    EXPECT_EQ(m.shutdownCount.load(), 0U);
    EXPECT_EQ(m.wdbErrorCount.load(), 0U);
    EXPECT_EQ(m.taskFetchCount.load(), 0U);
    EXPECT_EQ(m.taskFetchErrorCount.load(), 0U);
}

// Each inc helper touches exactly its own counter; a regression in the wrong
// counter (copy-paste bug) would break exactly one of the six sub-cases.
TEST(ControlMetricsTest, IncHelpersEachTouchOneCounter)
{
    ControlMetrics m;
    incStartup(m);
    EXPECT_EQ(m.startupCount.load(), 1U);
    EXPECT_EQ(m.notifyCount.load() + m.shutdownCount.load() + m.wdbErrorCount.load() + m.taskFetchCount.load() +
                  m.taskFetchErrorCount.load(),
              0U);
    incNotify(m);
    EXPECT_EQ(m.notifyCount.load(), 1U);
    incShutdown(m);
    EXPECT_EQ(m.shutdownCount.load(), 1U);
    incWdbError(m);
    EXPECT_EQ(m.wdbErrorCount.load(), 1U);
    incTaskFetch(m);
    EXPECT_EQ(m.taskFetchCount.load(), 1U);
    incTaskFetchError(m);
    EXPECT_EQ(m.taskFetchErrorCount.load(), 1U);
}

// The counters are documented as thread-safe via std::atomic. This test makes
// that contract explicit: 8 threads each incrementing 1000 times must not lose
// a single write. If someone ever swaps std::atomic for a plain uint64_t, this
// fires under -fsanitize=thread.
TEST(ControlMetricsTest, IncIsThreadSafe)
{
    constexpr int threads = 8;
    constexpr int perThread = 1000;

    ControlMetrics m;
    std::vector<std::thread> ts;
    ts.reserve(threads);
    for (int i = 0; i < threads; ++i)
    {
        ts.emplace_back(
            [&m]
            {
                for (int j = 0; j < perThread; ++j)
                {
                    incStartup(m);
                }
            });
    }
    for (auto& t : ts)
    {
        t.join();
    }

    EXPECT_EQ(m.startupCount.load(), static_cast<uint64_t>(threads * perThread));
}
