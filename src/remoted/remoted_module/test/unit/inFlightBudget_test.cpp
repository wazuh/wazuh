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
#include <optional>
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

TEST(InFlightBudget, GrowAddsToAnExistingReservation)
{
    InFlightBudget budget(100);

    auto reservation = budget.tryReserve(0);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_EQ(reservation->bytes(), 0U);
    EXPECT_EQ(budget.availableBytes(), 100U);

    ASSERT_TRUE(reservation->grow(30));
    EXPECT_EQ(reservation->bytes(), 30U);
    EXPECT_EQ(budget.availableBytes(), 70U);

    ASSERT_TRUE(reservation->grow(70)); // exact fit
    EXPECT_EQ(reservation->bytes(), 100U);
    EXPECT_EQ(budget.availableBytes(), 0U);
}

TEST(InFlightBudget, GrowBeyondCapacityIsRefusedAndLeavesTheReservationUntouched)
{
    InFlightBudget budget(100);

    auto reservation = budget.tryReserve(60);
    ASSERT_TRUE(reservation.has_value());

    EXPECT_FALSE(reservation->grow(41)); // 60 + 41 > 100
    // Refused, not partially applied: both the reservation and the budget are exactly as before.
    EXPECT_EQ(reservation->bytes(), 60U);
    EXPECT_EQ(budget.availableBytes(), 40U);

    EXPECT_TRUE(reservation->grow(40)); // what does fit still works afterwards
    EXPECT_EQ(reservation->bytes(), 100U);
    EXPECT_EQ(budget.availableBytes(), 0U);
}

TEST(InFlightBudget, GrownBytesAreAllReleasedTogether)
{
    InFlightBudget budget(100);
    {
        auto reservation = budget.tryReserve(10);
        ASSERT_TRUE(reservation.has_value());
        ASSERT_TRUE(reservation->grow(20));
        ASSERT_TRUE(reservation->grow(30));
        EXPECT_EQ(budget.availableBytes(), 40U);
    }
    // One release covers the initial reservation plus every grow() on top of it.
    EXPECT_EQ(budget.availableBytes(), 100U);
    EXPECT_EQ(budget.inFlightCount(), 0U);
}

TEST(InFlightBudget, GrowOnADisabledBudgetAlwaysSucceedsWithoutTracking)
{
    InFlightBudget budget(0); // disabled

    auto reservation = budget.tryReserve(0);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_TRUE(reservation->grow(1024 * 1024));
    EXPECT_EQ(reservation->bytes(), 0U); // admitted, but nothing is tracked
}

TEST(InFlightBudget, GrowOnAMovedFromReservationIsRefused)
{
    InFlightBudget budget(100);

    auto reservation = budget.tryReserve(10);
    ASSERT_TRUE(reservation.has_value());
    InFlightBudget::Reservation moved {std::move(*reservation)};

    // The moved-from token owns nothing now, so it must not be able to charge the budget.
    EXPECT_FALSE(reservation->grow(10));
    EXPECT_EQ(budget.availableBytes(), 90U); // unchanged: only `moved`'s 10 bytes are held
    EXPECT_TRUE(moved.grow(10));             // the new owner still can
    EXPECT_EQ(budget.availableBytes(), 80U);
}

TEST(InFlightBudget, ConcurrentGrowNeverOvershootsTheBudget)
{
    // grow() runs a compare-exchange loop against the same atomic tryReserve() uses, so several
    // threads growing at once must never hand out more than the budget holds -- the exact
    // mechanism that stops N concurrent decompressions from each independently deciding there is
    // room and together blowing past it.
    constexpr std::size_t total = 64U * 1024U;
    constexpr std::size_t step = 64U;
    InFlightBudget budget(total);

    constexpr int threadCount = 8;
    std::vector<std::thread> threads;
    std::vector<std::size_t> grantedPerThread(threadCount, 0);
    // The reservations live HERE, not inside the threads: they must all still be held when the
    // assertions run. If each thread dropped its own on exit, an early-finishing thread would hand
    // capacity back to the ones still looping, and the running total over time would legitimately
    // exceed the budget -- which says nothing about whether the budget was ever overshot at once.
    std::vector<std::optional<InFlightBudget::Reservation>> reservations(threadCount);
    threads.reserve(threadCount);

    for (int t = 0; t < threadCount; ++t)
    {
        threads.emplace_back(
            [&budget, &grantedPerThread, &reservations, t]
            {
                const auto slot = static_cast<std::size_t>(t);
                // Each thread owns one slot, and the vector is never resized, so no synchronization
                // is needed around the slots themselves -- only grow() is contended, which is the point.
                reservations[slot] = budget.tryReserve(0);
                while (reservations[slot]->grow(step))
                {
                    grantedPerThread[slot] += step;
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    std::size_t totalGranted = 0;
    for (const auto granted : grantedPerThread)
    {
        totalGranted += granted;
    }

    // Every thread grew until refused and every reservation is still held, so between them they
    // hold the entire budget and not one byte more. A racy CAS loop would show up here as a total
    // above `total` (with availableBytes() having wrapped around past zero).
    EXPECT_EQ(totalGranted, total);
    EXPECT_EQ(budget.availableBytes(), 0U);

    reservations.clear(); // release them all
    EXPECT_EQ(budget.availableBytes(), total);
    EXPECT_EQ(budget.inFlightCount(), 0U);
}
