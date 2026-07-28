/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <thread>
#include <utility>
#include <vector>

using remoted::http::InFlightBudget;

TEST(InFlightBudget, ReserveDecrementsAndReleaseRestores)
{
    InFlightBudget budget(100);
    EXPECT_TRUE(budget.enabled());
    EXPECT_EQ(budget.availableBytes(), 100U);
    EXPECT_EQ(budget.inFlightCount(), 0U);

    {
        auto a = budget.tryReserve(40);
        ASSERT_TRUE(a.has_value());
        EXPECT_TRUE(static_cast<bool>(*a));
        EXPECT_EQ(a->bytes(), 40U);
        EXPECT_EQ(budget.availableBytes(), 60U);
        EXPECT_EQ(budget.inFlightCount(), 1U);

        auto b = budget.tryReserve(60);
        ASSERT_TRUE(b.has_value());
        EXPECT_EQ(budget.availableBytes(), 0U);
        EXPECT_EQ(budget.inFlightCount(), 2U);
    }

    // Both reservations destroyed -> budget fully restored, counter back to zero.
    EXPECT_EQ(budget.availableBytes(), 100U);
    EXPECT_EQ(budget.inFlightCount(), 0U);
}

TEST(InFlightBudget, TryReserveFailsWhenItWouldExceed)
{
    InFlightBudget budget(100);

    auto a = budget.tryReserve(100);
    ASSERT_TRUE(a.has_value());

    auto b = budget.tryReserve(1); // nothing left
    EXPECT_FALSE(b.has_value());
    EXPECT_EQ(budget.availableBytes(), 0U);
    EXPECT_EQ(budget.inFlightCount(), 1U); // the rejected attempt did not count
}

TEST(InFlightBudget, ExactFitSucceedsOversizeFails)
{
    InFlightBudget budget(10);
    EXPECT_FALSE(budget.tryReserve(11).has_value());
    EXPECT_TRUE(budget.tryReserve(10).has_value());
}

TEST(InFlightBudget, MoveConstructTransfersOwnershipAndReleasesOnce)
{
    InFlightBudget budget(100);

    auto a = budget.tryReserve(30);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(budget.availableBytes(), 70U);

    InFlightBudget::Reservation moved = std::move(*a);
    EXPECT_FALSE(static_cast<bool>(*a)); // source emptied by the move
    EXPECT_TRUE(static_cast<bool>(moved));
    EXPECT_EQ(budget.availableBytes(), 70U); // moving must not release
    EXPECT_EQ(budget.inFlightCount(), 1U);

    a.reset(); // destroy the emptied source -> must NOT double-release
    EXPECT_EQ(budget.availableBytes(), 70U);
    EXPECT_EQ(budget.inFlightCount(), 1U);

    {
        InFlightBudget::Reservation sink = std::move(moved);
        EXPECT_EQ(budget.inFlightCount(), 1U);
    }
    // sink destroyed -> the single reservation is finally released.
    EXPECT_EQ(budget.availableBytes(), 100U);
    EXPECT_EQ(budget.inFlightCount(), 0U);
}

TEST(InFlightBudget, MoveAssignReleasesPreviousReservation)
{
    InFlightBudget budget(100);

    auto a = budget.tryReserve(30).value();
    auto b = budget.tryReserve(50).value();
    EXPECT_EQ(budget.availableBytes(), 20U);
    EXPECT_EQ(budget.inFlightCount(), 2U);

    a = std::move(b); // a's 30 bytes released, a now holds b's 50; b emptied
    EXPECT_EQ(budget.availableBytes(), 50U);
    EXPECT_EQ(budget.inFlightCount(), 1U);
    EXPECT_FALSE(static_cast<bool>(b));
}

TEST(InFlightBudget, DisabledBudgetAdmitsAllButStillCounts)
{
    InFlightBudget budget(0);
    EXPECT_FALSE(budget.enabled());

    auto a = budget.tryReserve(1000000);
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(static_cast<bool>(*a));
    EXPECT_EQ(a->bytes(), 0U); // disabled -> tracks 0 bytes
    EXPECT_EQ(budget.inFlightCount(), 1U);

    auto b = budget.tryReserve(9999999);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(budget.inFlightCount(), 2U);

    a.reset();
    EXPECT_EQ(budget.inFlightCount(), 1U);
    b.reset();
    EXPECT_EQ(budget.inFlightCount(), 0U);
}

TEST(InFlightBudget, ConcurrentReserveReleaseIsConsistent)
{
    constexpr std::size_t total = 1024U * 1024U;
    InFlightBudget budget(total);

    constexpr int threadCount = 8;
    constexpr int itersPerThread = 5000;

    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int t = 0; t < threadCount; ++t)
    {
        threads.emplace_back(
            [&budget]
            {
                for (int i = 0; i < itersPerThread; ++i)
                {
                    // Reserve and immediately release at scope end. tryReserve is atomic,
                    // so the running total never dips below zero or overflows.
                    auto reservation = budget.tryReserve(128);
                    (void)reservation;
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Every reservation was released: the budget is fully restored and nothing leaked.
    EXPECT_EQ(budget.availableBytes(), total);
    EXPECT_EQ(budget.inFlightCount(), 0U);
}
