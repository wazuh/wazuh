/*
 * Wazuh Syscheckd — tests for when the container FIM stale-row sweep may run.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The rule under test authorises a DELETION, so a wrong "yes" costs a live
 * container its whole FIM baseline rather than costing latency. It was wrong
 * once already: sweeping the moment a cursor resync was seen deleted six
 * containers' rows on a real node, 801 of them still running, because
 * container_instances answers `list` before its first enumeration has
 * finished. ResyncDebtWaitsWhileTheListIsStillMoving is that regression.
 */

#include "reconcile_floor.hpp"

#include <gtest/gtest.h>

using fim_container_events::planReconcileFloor;
using fim_container_events::RESYNC_SETTLE;

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr auto kInterval = std::chrono::milliseconds {3600000}; // the 1 h default
    const auto kSettle = std::chrono::duration_cast<std::chrono::milliseconds>(RESYNC_SETTLE);

    /* A fixed instant, so nothing here depends on how long the test takes. */
    const Clock::time_point kNow = Clock::time_point {} + std::chrono::hours {24};
} // namespace

/* --- the cadence ---------------------------------------------------------- */

TEST(ReconcileFloor, NothingSweepsWhileTheCadenceIsDisabled)
{
    /* <reconcile_interval>0</reconcile_interval> turns the sweep off. */
    const auto decision = planReconcileFloor(/*enabled=*/false,
                                             /*owed_after_resync=*/true,
                                             kNow,
                                             /*next_floor=*/kNow - std::chrono::hours {1},
                                             /*last_list_change=*/kNow - std::chrono::hours {1},
                                             kInterval,
                                             kSettle);

    EXPECT_FALSE(decision.sweep) << "disabled must mean disabled, debt or no debt";
    EXPECT_FALSE(decision.clear_resync_debt) << "the debt stays owed, so enabling it later still pays";
}

TEST(ReconcileFloor, TheCadenceSweepsWhenItFallsDueAndRearms)
{
    const auto decision = planReconcileFloor(true,
                                             /*owed_after_resync=*/false,
                                             kNow,
                                             /*next_floor=*/kNow,
                                             /*last_list_change=*/kNow - std::chrono::hours {2},
                                             kInterval,
                                             kSettle);

    EXPECT_TRUE(decision.sweep);
    EXPECT_EQ(decision.next_floor, kNow + kInterval);
}

TEST(ReconcileFloor, TheCadenceDoesNotSweepBeforeItIsDue)
{
    const auto next = kNow + std::chrono::minutes {5};

    const auto decision = planReconcileFloor(true,
                                             false,
                                             kNow,
                                             next,
                                             /*last_list_change=*/kNow - std::chrono::hours {2},
                                             kInterval,
                                             kSettle);

    EXPECT_FALSE(decision.sweep);
    EXPECT_EQ(decision.next_floor, next) << "a deadline that has not arrived must not move";
}

TEST(ReconcileFloor, TheCadenceIsNotBlockedByAChurningNode)
{
    /* The asymmetry that keeps the sweep alive where it is needed most. A node
     * with steady container churn moves its list constantly; if the cadence
     * waited for silence the way the resync debt does, that node would never
     * sweep — and it is exactly the node whose stale rows fill the table. */
    const auto decision = planReconcileFloor(true,
                                             /*owed_after_resync=*/false,
                                             kNow,
                                             /*next_floor=*/kNow,
                                             /*last_list_change=*/kNow, // moved this very instant
                                             kInterval,
                                             kSettle);

    EXPECT_TRUE(decision.sweep);
}

/* --- the debt a container_instances restart leaves ------------------------ */

TEST(ReconcileFloor, ResyncDebtWaitsWhileTheListIsStillMoving)
{
    /* THE regression test. container_instances answers `list` as soon as its
     * socket is bound, before its first enumeration has finished, so sweeping
     * on the resync itself deletes the rows of containers it has not got round
     * to reporting yet. */
    const auto decision = planReconcileFloor(true,
                                             /*owed_after_resync=*/true,
                                             kNow,
                                             /*next_floor=*/kNow + std::chrono::hours {1},
                                             /*last_list_change=*/kNow - std::chrono::seconds {1},
                                             kInterval,
                                             kSettle);

    EXPECT_FALSE(decision.sweep) << "a list that moved a second ago is a list still being built";
    EXPECT_FALSE(decision.clear_resync_debt) << "and the debt must survive to be paid later";
}

TEST(ReconcileFloor, ResyncDebtIsPaidOnceTheListGoesQuiet)
{
    const auto decision = planReconcileFloor(true,
                                             true,
                                             kNow,
                                             /*next_floor=*/kNow + std::chrono::hours {1},
                                             /*last_list_change=*/kNow - RESYNC_SETTLE,
                                             kInterval,
                                             kSettle);

    EXPECT_TRUE(decision.sweep);
    EXPECT_TRUE(decision.clear_resync_debt);
}

TEST(ReconcileFloor, EachNewContainerPushesTheDebtDeadlineOut)
{
    /* Walks the shape of a real restart: the module comes back, reports
     * containers one after another, and only the silence after the last one
     * releases the sweep. */
    auto last_change = kNow;

    for (int reported = 0; reported < 5; ++reported)
    {
        last_change = kNow + std::chrono::seconds {reported * 10};

        const auto during = planReconcileFloor(true,
                                               true,
                                               last_change + std::chrono::seconds {1},
                                               kNow + std::chrono::hours {1},
                                               last_change,
                                               kInterval,
                                               kSettle);

        EXPECT_FALSE(during.sweep) << "still enumerating after " << reported << " container(s)";
    }

    const auto after = planReconcileFloor(true,
                                          true,
                                          last_change + RESYNC_SETTLE,
                                          kNow + std::chrono::hours {1},
                                          last_change,
                                          kInterval,
                                          kSettle);

    EXPECT_TRUE(after.sweep) << "the list has been quiet for the settle window";
}

TEST(ReconcileFloor, PayingTheDebtRearmsTheCadenceSoNoTwoSweepsRunBackToBack)
{
    /* Both can be ready at the same instant. Two sweeps in a row would read the
     * same list twice for nothing. */
    const auto decision = planReconcileFloor(true,
                                             /*owed_after_resync=*/true,
                                             kNow,
                                             /*next_floor=*/kNow, // the cadence is due as well
                                             /*last_list_change=*/kNow - RESYNC_SETTLE,
                                             kInterval,
                                             kSettle);

    EXPECT_TRUE(decision.sweep);
    EXPECT_TRUE(decision.clear_resync_debt);
    EXPECT_EQ(decision.next_floor, kNow + kInterval);
}

TEST(ReconcileFloor, ADebtDoesNotSuppressACadenceThatIsAlreadyDue)
{
    /* The debt is not yet payable, but the ordinary cadence has come round.
     * That sweep is safe — the connector warmed up an interval ago — and
     * withholding it would make a producer restart DELAY the cleanup it is
     * supposed to trigger. */
    const auto decision = planReconcileFloor(true,
                                             /*owed_after_resync=*/true,
                                             kNow,
                                             /*next_floor=*/kNow,
                                             /*last_list_change=*/kNow, // still moving
                                             kInterval,
                                             kSettle);

    EXPECT_TRUE(decision.sweep);
    EXPECT_FALSE(decision.clear_resync_debt) << "the debt is unpaid: this sweep may have read a "
                                                "list that is still incomplete";
    EXPECT_EQ(decision.next_floor, kNow + kInterval);
}

TEST(ReconcileFloor, TheSettleWindowMatchesTheProducersRemovalGrace)
{
    /* Not a magic number: 60 s is the scale on which container_instances itself
     * decides a container is gone, so it is the scale on which its list may be
     * believed. */
    EXPECT_EQ(RESYNC_SETTLE, std::chrono::seconds {60});
}
