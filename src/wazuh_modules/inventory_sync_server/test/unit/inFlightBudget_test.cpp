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

#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

using invsync::http::InFlightBudget;

TEST(InFlightBudgetTest, ReservesAndReleasesAutomatically)
{
    InFlightBudget budget {1000};

    {
        auto reservation = budget.tryReserve(400);
        ASSERT_TRUE(reservation.has_value());
        EXPECT_EQ(400U, reservation->bytes());
        EXPECT_EQ(600U, budget.availableBytes());
        EXPECT_EQ(1U, budget.inFlightCount());
    }

    EXPECT_EQ(1000U, budget.availableBytes());
    EXPECT_EQ(0U, budget.inFlightCount());
}

TEST(InFlightBudgetTest, RefusesAReservationThatWouldExceedTheBudget)
{
    InFlightBudget budget {1000};

    auto first = budget.tryReserve(900);
    ASSERT_TRUE(first.has_value());

    EXPECT_FALSE(budget.tryReserve(200).has_value());
    EXPECT_EQ(100U, budget.availableBytes()) << "a refused reservation must not consume anything";
    EXPECT_EQ(1U, budget.inFlightCount()) << "a refused reservation must not be counted";
}

TEST(InFlightBudgetTest, AReservationExactlyAtTheLimitIsAdmitted)
{
    InFlightBudget budget {1000};
    auto reservation = budget.tryReserve(1000);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_EQ(0U, budget.availableBytes());
    EXPECT_FALSE(budget.tryReserve(1).has_value());
}

TEST(InFlightBudgetTest, ReleasingFreesTheBudgetForTheNextRequest)
{
    InFlightBudget budget {1000};

    {
        auto reservation = budget.tryReserve(1000);
        ASSERT_TRUE(reservation.has_value());
        EXPECT_FALSE(budget.tryReserve(1).has_value());
    }

    EXPECT_TRUE(budget.tryReserve(1000).has_value());
}

// The move is what lets a reservation travel with its payload through queues; releasing twice would
// corrupt the accounting in exactly the way that is hardest to notice.
TEST(InFlightBudgetTest, MovingAReservationTransfersOwnershipAndReleasesOnce)
{
    InFlightBudget budget {1000};

    {
        auto original = budget.tryReserve(300);
        ASSERT_TRUE(original.has_value());

        auto moved = std::move(*original);
        EXPECT_TRUE(static_cast<bool>(moved));
        EXPECT_FALSE(static_cast<bool>(*original)) << "the source must no longer own the bytes";
        EXPECT_EQ(700U, budget.availableBytes());
    }

    EXPECT_EQ(1000U, budget.availableBytes()) << "the bytes must be released exactly once";
    EXPECT_EQ(0U, budget.inFlightCount());
}

TEST(InFlightBudgetTest, MoveAssignmentReleasesTheOverwrittenReservation)
{
    InFlightBudget budget {1000};

    auto first = budget.tryReserve(300);
    auto second = budget.tryReserve(200);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(500U, budget.availableBytes());

    *first = std::move(*second);

    EXPECT_EQ(800U, budget.availableBytes()) << "the overwritten 300-byte reservation must be released";
    EXPECT_EQ(1U, budget.inFlightCount());
}

// A budget of 0 disables the byte limit but keeps counting, so the observability path still works
// when an operator turns the limit off.
TEST(InFlightBudgetTest, ZeroDisablesTheByteLimitButKeepsCounting)
{
    InFlightBudget budget {0};
    EXPECT_FALSE(budget.enabled());

    auto huge = budget.tryReserve(1024U * 1024U * 1024U);
    ASSERT_TRUE(huge.has_value());
    EXPECT_EQ(0U, huge->bytes());
    EXPECT_EQ(1U, budget.inFlightCount());

    huge.reset();
    EXPECT_EQ(0U, budget.inFlightCount());
}

TEST(InFlightBudgetTest, AccountingStaysExactUnderConcurrency)
{
    constexpr int THREADS {16};
    constexpr int PER_THREAD {500};

    InFlightBudget budget {THREADS * 64};
    std::atomic<int> admitted {0};

    std::vector<std::thread> workers;
    workers.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t)
    {
        workers.emplace_back(
            [&budget, &admitted]
            {
                for (int i = 0; i < PER_THREAD; ++i)
                {
                    if (auto reservation = budget.tryReserve(64))
                    {
                        admitted.fetch_add(1);
                    }
                }
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_GT(admitted.load(), 0);
    EXPECT_EQ(0U, budget.inFlightCount()) << "every reservation must have been released";
    EXPECT_EQ(static_cast<std::size_t>(THREADS * 64), budget.availableBytes())
        << "the budget must return to exactly its initial value";
}
