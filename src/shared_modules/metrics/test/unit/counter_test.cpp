/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include <wazuh_metrics/atomicCounter.hpp>

using namespace wazuh::metrics;

TEST(CounterTest, BasicOperations)
{
    AtomicCounter counter("test.counter");

    EXPECT_EQ(counter.name(), "test.counter");
    EXPECT_EQ(counter.type(), MetricType::COUNTER);
    EXPECT_TRUE(counter.isEnabled());

    // Initial value
    EXPECT_EQ(counter.get(), 0U);

    // Increment by default delta (1)
    counter.add();
    EXPECT_EQ(counter.get(), 1U);

    // Add 10
    counter.add(10);
    EXPECT_EQ(counter.get(), 11U);

    // Add 0 (should still work)
    counter.add(0);
    EXPECT_EQ(counter.get(), 11U);
}

TEST(CounterTest, Reset)
{
    AtomicCounter counter("test.counter");

    counter.add(100);
    EXPECT_EQ(counter.get(), 100U);

    counter.reset();
    EXPECT_EQ(counter.get(), 0U);
}

TEST(CounterTest, EnableDisable)
{
    AtomicCounter counter("test.counter");

    // Enabled by default
    counter.add(5);
    EXPECT_EQ(counter.get(), 5U);

    // Disable
    counter.disable();
    EXPECT_FALSE(counter.isEnabled());

    // Updates should be ignored
    counter.add(10);
    EXPECT_EQ(counter.get(), 5U); // Still 5

    // value() also reports 0 while disabled
    EXPECT_DOUBLE_EQ(counter.value(), 0.0);

    // Re-enable
    counter.enable();
    EXPECT_TRUE(counter.isEnabled());

    counter.add(10);
    EXPECT_EQ(counter.get(), 15U);
    EXPECT_DOUBLE_EQ(counter.value(), 15.0);
}

TEST(CounterTest, ThreadSafety)
{
    AtomicCounter counter("test.counter");

    constexpr int NUM_THREADS = 10;
    constexpr int INCREMENTS_PER_THREAD = 10000;

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [&counter]()
            {
                for (int j = 0; j < INCREMENTS_PER_THREAD; ++j)
                {
                    counter.add();
                }
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(counter.get(), static_cast<uint64_t>(NUM_THREADS) * INCREMENTS_PER_THREAD);
}

TEST(CounterTest, MultiThreadedMixedOperations)
{
    AtomicCounter counter("test.counter");

    std::thread t1(
        [&counter]()
        {
            for (int i = 0; i < 1000; ++i) counter.add(1);
        });

    std::thread t2(
        [&counter]()
        {
            for (int i = 0; i < 1000; ++i) counter.add(2);
        });

    std::thread t3(
        [&counter]()
        {
            for (int i = 0; i < 1000; ++i) counter.add(3);
        });

    t1.join();
    t2.join();
    t3.join();

    // Expected: 1000*1 + 1000*2 + 1000*3 = 6000
    EXPECT_EQ(counter.get(), 6000U);
}
