/*
 * Wazuh Syscheckd — unit tests for the container resolver's wait decision
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Small surface, but it decides how the resolver spends its time, and both
 * ways of getting it wrong are expensive in production and invisible in review:
 * a negative value makes poll() block forever, which reads as a hang, and a
 * zero one on a loop that cannot progress spins a core.
 */

#include "resolver_wait.hpp"

#include <gtest/gtest.h>

using namespace fim_container_events;
using Ms = std::chrono::milliseconds;

TEST(ResolverWaitTest, WaitsUntilTheScheduledRefreshWhenThereIsNothingElseToDo)
{
    // The common case under the kernel filter: everything is attributed, no
    // cgroup is awaiting identification, and nothing needs doing until either a
    // notification arrives or the floor comes round.
    EXPECT_EQ(5000, resolverWaitMs(Ms {5000}, false));
}

TEST(ResolverWaitTest, UnresolvedCgroupsCapTheWaitAtTheirOwnPacing)
{
    // These are waiting on an IPC answer, not on anything container_instances
    // will announce, so no notification is coming for them. Sleeping until the
    // floor would leave them unidentified for the whole interval.
    EXPECT_EQ(RESOLVE_PACING_MS, resolverWaitMs(Ms {5000}, true));
}

TEST(ResolverWaitTest, ARefreshDueSoonerThanThePacingStillWins)
{
    // The cap is a ceiling, not a floor: whichever comes first wins.
    EXPECT_EQ(50, resolverWaitMs(Ms {50}, true));
}

TEST(ResolverWaitTest, AnOverdueRefreshWakesImmediatelyRatherThanBlockingForever)
{
    // A deadline in the past yields a NEGATIVE duration, and poll() reads a
    // negative timeout as "no timeout" — the resolver would then sleep until a
    // notification or shutdown, and the floor that exists to catch what
    // notifications cannot report would simply stop running.
    EXPECT_EQ(0, resolverWaitMs(Ms {-1}, false));
    EXPECT_EQ(0, resolverWaitMs(Ms {-10000}, true));
}

TEST(ResolverWaitTest, AFloorOfZeroDoesNotBecomeAnInfiniteWait)
{
    EXPECT_EQ(0, resolverWaitMs(Ms {0}, false));
    EXPECT_EQ(0, resolverWaitMs(Ms {0}, true));
}

TEST(ResolverWaitTest, ALongFloorIsHonouredSoAQuietHostDoesNotWakeForNothing)
{
    // The interval is intended to relax to tens of seconds once notifications
    // carry discovery. If anything silently clamped the wait, a quiet host
    // would keep paying a full container list every few hundred milliseconds —
    // the cost this change exists to remove.
    EXPECT_EQ(30000, resolverWaitMs(Ms {30000}, false));
}
