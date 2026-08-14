/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Validates the count-based DeferredWorkLimiter: acquire up to the capacity, the next
// acquire fails, RAII/move release frees slots, capacity 0 disables the limit, and the
// accounting stays consistent under concurrency.
#include "downstream/deferredWorkLimiter.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

using remoted::downstream::DeferredWorkLimiter;

TEST(DeferredWorkLimiter, AcquireUpToCapacityThenFail)
{
    DeferredWorkLimiter limiter(2);
    EXPECT_TRUE(limiter.enabled());
    EXPECT_EQ(limiter.capacity(), 2U);
    EXPECT_EQ(limiter.inFlight(), 0U);

    auto a = limiter.tryAcquire();
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(static_cast<bool>(*a));
    EXPECT_EQ(limiter.inFlight(), 1U);

    auto b = limiter.tryAcquire();
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(limiter.inFlight(), 2U);

    auto c = limiter.tryAcquire(); // capacity reached
    EXPECT_FALSE(c.has_value());
    EXPECT_EQ(limiter.inFlight(), 2U); // the rejected attempt did not count
}

TEST(DeferredWorkLimiter, ReleaseFreesASlot)
{
    DeferredWorkLimiter limiter(1);

    {
        auto a = limiter.tryAcquire();
        ASSERT_TRUE(a.has_value());
        EXPECT_FALSE(limiter.tryAcquire().has_value()); // full
        EXPECT_EQ(limiter.inFlight(), 1U);
    }

    // The scoped slot released -> capacity available again.
    EXPECT_EQ(limiter.inFlight(), 0U);
    EXPECT_TRUE(limiter.tryAcquire().has_value());
}

TEST(DeferredWorkLimiter, MoveTransfersOwnershipAndReleasesOnce)
{
    DeferredWorkLimiter limiter(1);

    auto a = limiter.tryAcquire();
    ASSERT_TRUE(a.has_value());

    DeferredWorkLimiter::Slot moved = std::move(*a);
    EXPECT_FALSE(static_cast<bool>(*a)); // source emptied
    EXPECT_TRUE(static_cast<bool>(moved));
    EXPECT_EQ(limiter.inFlight(), 1U); // still exactly one

    a.reset(); // destroy the emptied source -> no double release
    EXPECT_EQ(limiter.inFlight(), 1U);

    {
        DeferredWorkLimiter::Slot sink = std::move(moved);
        EXPECT_EQ(limiter.inFlight(), 1U);
    }
    EXPECT_EQ(limiter.inFlight(), 0U); // sink destroyed -> released
}

TEST(DeferredWorkLimiter, DisabledAlwaysAcquiresButCounts)
{
    DeferredWorkLimiter limiter(0);
    EXPECT_FALSE(limiter.enabled());

    auto a = limiter.tryAcquire();
    auto b = limiter.tryAcquire();
    auto c = limiter.tryAcquire();
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(limiter.inFlight(), 3U);

    a.reset();
    EXPECT_EQ(limiter.inFlight(), 2U);
}

TEST(DeferredWorkLimiter, ConcurrentAcquireReleaseIsConsistent)
{
    constexpr std::size_t capacity = 32;
    DeferredWorkLimiter limiter(capacity);

    constexpr int threadCount = 8;
    constexpr int itersPerThread = 5000;
    std::atomic<std::size_t> maxObserved {0};

    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int t = 0; t < threadCount; ++t)
    {
        threads.emplace_back(
            [&limiter, &maxObserved]
            {
                for (int i = 0; i < itersPerThread; ++i)
                {
                    if (auto slot = limiter.tryAcquire())
                    {
                        const auto now = limiter.inFlight();
                        auto prev = maxObserved.load(std::memory_order_relaxed);
                        while (now > prev && !maxObserved.compare_exchange_weak(prev, now))
                        {
                        }
                        // slot releases at end of scope
                    }
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(limiter.inFlight(), 0U);       // everything released, nothing leaked
    EXPECT_LE(maxObserved.load(), capacity); // the cap was never exceeded
}
