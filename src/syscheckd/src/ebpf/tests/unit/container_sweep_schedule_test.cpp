/*
 * Wazuh Syscheckd — unit tests for the container reconciliation floor's
 * schedule (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The floor is what catches removals a notification cannot report: one that
 * happened across a resync, and a container the module never learned about.
 * Both failures are silent — the rows and context of a container that no
 * longer exists simply stay in the database — so every case here is a
 * regression that would not announce itself in production.
 */

#include "container_sweep_schedule.hpp"

#include <gtest/gtest.h>

using namespace fim_container_events;
using Clock = SweepSchedule::Clock;
using Ms = std::chrono::milliseconds;

namespace
{
/* A fixed origin rather than Clock::now(), so nothing here depends on how long
 * the test itself takes to run. */
const Clock::time_point T0 {};
} // namespace

TEST(SweepScheduleTest, NothingIsDueBeforeTheIntervalHasElapsed)
{
    SweepSchedule schedule {300000};
    schedule.restart(T0);

    EXPECT_FALSE(schedule.due(T0));
    EXPECT_FALSE(schedule.due(T0 + Ms {299999}));
}

TEST(SweepScheduleTest, TheDeadlineFiresOnTheInterval)
{
    SweepSchedule schedule {300000};
    schedule.restart(T0);

    EXPECT_TRUE(schedule.due(T0 + Ms {300000}));
    EXPECT_TRUE(schedule.due(T0 + Ms {900000}));
}

TEST(SweepScheduleTest, ADueSweepStaysDueUntilItIsPerformed)
{
    // due() consumes nothing on purpose. If the caller is somehow unable to
    // act on it, the next pass asks again — a sweep repeated is cheap and
    // visible, a sweep skipped leaves a removed container's rows in place with
    // nothing to say so.
    SweepSchedule schedule {300000};
    schedule.restart(T0);

    EXPECT_TRUE(schedule.due(T0 + Ms {300000}));
    EXPECT_TRUE(schedule.due(T0 + Ms {300001}));

    schedule.restart(T0 + Ms {300001});
    EXPECT_FALSE(schedule.due(T0 + Ms {300002}));
}

TEST(SweepScheduleTest, APeriodRunsFromTheLastSweepNotTheLastDeadline)
{
    // The drain restarts the period after an out-of-band sweep too, so a
    // resync arriving just before a deadline does not produce two whole-node
    // passes back to back.
    SweepSchedule schedule {300000};
    schedule.restart(T0);

    schedule.restart(T0 + Ms {200000}); // an out-of-band sweep happened here

    EXPECT_FALSE(schedule.due(T0 + Ms {300000}));
    EXPECT_TRUE(schedule.due(T0 + Ms {500000}));
}

TEST(SweepScheduleTest, NothingIsDueBeforeTheFirstPeriodHasBeenStarted)
{
    // The constructor deliberately sets no deadline: it would be measured from
    // whenever the drain was built, which is before the engine was opened.
    SweepSchedule schedule {300000};

    EXPECT_FALSE(schedule.due(T0 + Ms {86400000}));
}

TEST(SweepScheduleTest, AnIntervalOfZeroMeansNoPeriodicDeadlineAtAll)
{
    // Out-of-band sweeps are unaffected by this, and that is the point: they
    // raise the staging marker directly and never consult this class, so no
    // value here can suppress them. Syscollector's own floor CAN —
    // container_baseline_interval == 0, its default, makes its lifecycle
    // notification inert — which is the shape this one is built not to have.
    SweepSchedule schedule {0};
    schedule.restart(T0);

    EXPECT_FALSE(schedule.periodic());
    EXPECT_FALSE(schedule.due(T0 + Ms {86400000}));
}

TEST(SweepScheduleTest, ANegativeIntervalIsNoFloorRatherThanAPermanentlyOverdueOne)
{
    // Not reachable from DrainConfig's default, but "already due, forever"
    // would mean a container list and a distinct-id scan on every resolver
    // pass — a far worse failure than no floor at all.
    SweepSchedule schedule {-1};
    schedule.restart(T0);

    EXPECT_FALSE(schedule.periodic());
    EXPECT_FALSE(schedule.due(T0));
    EXPECT_FALSE(schedule.due(T0 + Ms {1000}));
}

TEST(SweepScheduleTest, ThePollBoundIsWhicheverDeadlineComesFirst)
{
    SweepSchedule schedule {300000};
    schedule.restart(T0);

    // The ordinary case: the container list refresh is due long before the
    // floor, so it is the one that bounds the wait.
    EXPECT_EQ(T0 + Ms {5000}, schedule.soonerOf(T0 + Ms {5000}));

    // And the case the bound exists for: a refresh further out than the floor
    // must not be allowed to delay it.
    EXPECT_EQ(T0 + Ms {300000}, schedule.soonerOf(T0 + Ms {900000}));
}

TEST(SweepScheduleTest, WithNoFloorThePollBoundIsLeftAlone)
{
    SweepSchedule schedule {0};
    schedule.restart(T0);

    EXPECT_EQ(T0 + Ms {5000}, schedule.soonerOf(T0 + Ms {5000}));
}

TEST(SweepScheduleTest, AnUnstartedScheduleDoesNotBoundThePollEither)
{
    SweepSchedule schedule {300000};

    EXPECT_EQ(T0 + Ms {5000}, schedule.soonerOf(T0 + Ms {5000}));
}
