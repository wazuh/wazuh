/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "execution/ownership.hpp"
#include "model/taskId.hpp"
#include "schedule/cadence.hpp"
#include "testDoubles.hpp"

#include <gtest/gtest.h>

#include <unistd.h>

using namespace task_manager;
using namespace task_manager::schedule;
using namespace task_manager::execution;
using namespace task_manager::test;

// ---- identity ---------------------------------------------------------------------------------

/*
 * Golden vectors, not round trips. These ids are written into a database that survives restarts and
 * are the mechanism behind two idempotency guarantees -- the spawn loop's crash safety and authd
 * treating a collision as "already recorded" -- so a refactor that changed the hashed string while
 * still hashing SOMETHING consistently would break both and pass a round-trip test.
 */
TEST(TaskId, ScheduledRunIdMatchesItsGoldenVector)
{
    EXPECT_EQ(taskId::forScheduledRun("agent_delete_old", 1700000000),
              "6b74b099b261fb4d2bc2f56a578a8d0bd8b74034a27f686824403ba14c1ad623");
}

TEST(TaskId, ScheduledRunIdIsKeyedOnTheSlotSoARetryReDerivesIt)
{
    // This is the whole of the spawn loop's crash safety: a crash between the insert and the
    // NEXT_RUN_AT advance re-derives the same id, and the primary-key collision makes the
    // double-spawn a no-op.
    EXPECT_EQ(taskId::forScheduledRun("s", 1000), taskId::forScheduledRun("s", 1000));
    EXPECT_NE(taskId::forScheduledRun("s", 1000), taskId::forScheduledRun("s", 1001));
}

TEST(TaskId, AgentTaskIdMatchesItsGoldenVectors)
{
    // Without a source id.
    EXPECT_EQ(taskId::forAgentTask("", "001", "agent_restart", 1700000000), "2d6a55b2-b99f-d3df-f07e-e64d2f08dc54");

    // With one -- Active Response passes the document id.
    EXPECT_EQ(taskId::forAgentTask("ar-doc", "001", "active_response", 1700000000),
              "8c6248ee-6ef8-7dcb-ffe3-fb36776c30d1");
}

TEST(TaskId, AnAbsentAndAnEmptySourceIdAlias)
{
    // Pre-existing behaviour on a shipping path, reproduced deliberately rather than fixed:
    // changing it would change ids for tasks already in flight across an upgrade.
    EXPECT_EQ(taskId::forAgentTask("", "001", "agent_restart", 1000),
              taskId::forAgentTask(std::string {}, "001", "agent_restart", 1000));
}

TEST(TaskId, AgentTaskIdKeepsTheLegacyUuidShape)
{
    const auto id {taskId::forAgentTask("", "001", "agent_restart", 1000)};
    ASSERT_EQ(id.size(), 36U);
    EXPECT_EQ(id[8], '-');
    EXPECT_EQ(id[13], '-');
    EXPECT_EQ(id[18], '-');
    EXPECT_EQ(id[23], '-');
}

TEST(TaskId, ManagerTaskIdsAreAlwaysSixtyFourHexCharacters)
{
    const auto id {taskId::forScheduledRun("s", 1)};
    EXPECT_EQ(id.size(), 64U);
    EXPECT_EQ(id.find_first_not_of("0123456789abcdef"), std::string::npos);
}

// ---- interval cadence -------------------------------------------------------------------------

TEST(Cadence, AScheduleThatHasNeverRunStartsOneIntervalOut)
{
    // Starting at `now` is how a restart loop becomes a sweep loop.
    EXPECT_EQ(nextIntervalRun(0, 1000, std::chrono::seconds {900}), 1900);
}

TEST(Cadence, AFutureSlotIsLeftAlone)
{
    EXPECT_EQ(nextIntervalRun(5000, 1000, std::chrono::seconds {900}), 5000);
}

TEST(Cadence, MissedRunsCoalesceIntoOne)
{
    // A manager down for a week owes 672 disconnection slots, and it owes ONE run, not 672.
    const auto weekAgo {1000};
    const auto now {weekAgo + 604800};
    const auto next {nextIntervalRun(weekAgo, now, std::chrono::seconds {900})};

    EXPECT_GT(next, now);
    EXPECT_LE(next - now, 900) << "the next slot must be within one interval, not a week of catch-up";
}

TEST(Cadence, ANonPositiveIntervalYieldsNoSlot)
{
    EXPECT_EQ(nextIntervalRun(1000, 2000, std::chrono::seconds {0}), 0);
}

// ---- daily cadence ----------------------------------------------------------------------------

TEST(Cadence, TheDailySlotIsAlwaysInTheFutureAndWithinADay)
{
    constexpr Timestamp now {1700000000};
    const auto slot {nextDailyRun(now, std::chrono::seconds {10})};

    EXPECT_GT(slot, now);
    EXPECT_LE(slot - now, DAY_SECONDS);
}

TEST(Cadence, TheDailyOffsetIsClampedBelowAFullDay)
{
    constexpr Timestamp now {1700000000};

    // An offset of a whole day or more would place the slot outside the day it was derived from.
    const auto slot {nextDailyRun(now, std::chrono::seconds {DAY_SECONDS + 500})};
    EXPECT_GT(slot, now);
    EXPECT_LE(slot - now, DAY_SECONDS + 1);
}

TEST(Cadence, ConsecutiveDailySlotsAreStrictlyIncreasing)
{
    // The property DST would break if the slot were computed by arithmetic on `now` rather than by
    // re-breaking the calendar: subtracting a modulus can place a slot BEFORE the previous one.
    Timestamp cursor {1700000000};
    Timestamp previous {0};

    for (int day = 0; day < 400; ++day)
    {
        const auto slot {nextDailyRun(cursor, std::chrono::seconds {10})};
        EXPECT_GT(slot, previous) << "day " << day;
        previous = slot;
        cursor = slot + 1;
    }
}

// ---- startup reconciliation -------------------------------------------------------------------

namespace
{
    Schedule intervalSchedule(const bool enabled, const int interval = 900)
    {
        Schedule schedule;
        schedule.definition = {"s", "t", NodeScope::Any, Cadence::Interval};
        schedule.interval = std::chrono::seconds {interval};
        schedule.enabled = enabled;
        return schedule;
    }
} // namespace

TEST(StartupNextRun, ANewScheduleGetsAFreshSlot)
{
    const auto schedule {intervalSchedule(true)};
    EXPECT_EQ(startupNextRun(schedule, false, 0, false, 1000), 1900);
}

TEST(StartupNextRun, AStoredSlotSurvivesAnOrdinaryRestart)
{
    const auto schedule {intervalSchedule(true)};
    EXPECT_EQ(startupNextRun(schedule, true, 1500, true, 1000), 1500);
}

TEST(StartupNextRun, ReEnablingRecomputesTheSlot)
{
    // Otherwise a schedule switched back on after a week carries a week-old value, missed-run
    // coalescing sees an overdue slot, and it fires immediately -- for a destructive,
    // disabled-by-default retention sweep, an instant purge on flipping the switch. Disabled time
    // is not downtime.
    const auto schedule {intervalSchedule(true)};
    EXPECT_EQ(startupNextRun(schedule, true, 100, false, 1000), 1900);
}

TEST(StartupNextRun, AShrunkIntervalIsDetectedByItsConsequence)
{
    // The interval is not persisted -- it belongs to the code -- so it is detected by a stored slot
    // further out than one whole interval from now. Without this an operator who lowers
    // agents_disconnection_time still waits out the old, longer one.
    const auto schedule {intervalSchedule(true, 60)};
    EXPECT_EQ(startupNextRun(schedule, true, 5000, true, 1000), 1060);
}

TEST(StartupNextRun, AGrownIntervalNeedsNoHandling)
{
    // The stored slot merely falls sooner than the new interval would place it, so it fires once
    // early and re-anchors on the next advance.
    const auto schedule {intervalSchedule(true, 3600)};
    EXPECT_EQ(startupNextRun(schedule, true, 1500, true, 1000), 1500);
}

// ---- node scope -------------------------------------------------------------------------------

TEST(NodeScope, AnyScopeRunsEverywhere)
{
    EXPECT_TRUE(nodeAllows(NodeScope::Any, 1));
    EXPECT_TRUE(nodeAllows(NodeScope::Any, 0));
    EXPECT_TRUE(nodeAllows(NodeScope::Any, -1));
}

TEST(NodeScope, MasterScopeRequiresAnExplicitMasterAndUnknownIsNotOne)
{
    EXPECT_TRUE(nodeAllows(NodeScope::Master, 0));
    EXPECT_FALSE(nodeAllows(NodeScope::Master, 1));

    // The retired monitord fell through to master when the cluster config failed to parse, which
    // is why a broken config silently behaved as a master there.
    EXPECT_FALSE(nodeAllows(NodeScope::Master, -1));
}

// ---- ownership --------------------------------------------------------------------------------

TEST(Ownership, TheOwnerStringRoundTrips)
{
    OwnerIdentity identity;
    identity.pid = 4242;
    identity.startTime = 987654;
    identity.workerIndex = 3;

    const auto text {identity.toString()};
    EXPECT_EQ(text, "4242:987654:w3");

    const auto parsed {parseOwner(text)};
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->pid, 4242);
    EXPECT_EQ(parsed->startTime, 987654U);
    EXPECT_EQ(parsed->workerIndex, 3);
}

TEST(Ownership, MalformedOwnersAreRejectedRatherThanGuessedAt)
{
    EXPECT_FALSE(parseOwner("").has_value());
    EXPECT_FALSE(parseOwner("4242").has_value());
    EXPECT_FALSE(parseOwner("4242:987654").has_value());
    EXPECT_FALSE(parseOwner("4242:987654:3").has_value()) << "the worker part must carry its 'w'";
    EXPECT_FALSE(parseOwner("not:a:w1").has_value());
}

TEST(Ownership, ThisProcessReadsItsOwnStartTime)
{
    const auto self {selfIdentity(0)};
    EXPECT_EQ(self.pid, static_cast<std::int32_t>(::getpid()));

    // Field 22 of /proc/<pid>/stat. Zero would mean the parse failed, which would make every
    // owner comparison meaningless.
    EXPECT_GT(self.startTime, 0U);
}

TEST(Ownership, ARecycledPidIsNotTheSameProcess)
{
    auto self {selfIdentity(0)};

    OwnerIdentity recycled {self};
    recycled.startTime = self.startTime + 1;

    // A pid alone is reused by the kernel, so without the start time a crashed manager's rows
    // could be judged "still owned by a live process".
    EXPECT_EQ(classifyOwner(recycled.toString(), self), OwnerKind::Dead);
}

TEST(Ownership, AnUnparseableOwnerIsReclaimable)
{
    // A row whose owner this build cannot read would be reclaimed by no other rule, and would sit
    // unclaimable forever while counting against the row ceiling.
    ReclaimQuery query;
    query.owner = "garbage";
    query.rowTaskId = "task";
    query.claimTime = 0;
    query.now = 1000;

    EXPECT_TRUE(isReclaimable(query, selfIdentity(0)));
}

TEST(Ownership, AnIdleWorkerOfThisProcessIsReclaimedPastTheGrace)
{
    const auto self {selfIdentity(0)};

    // Same process, a different worker index, that worker idle, well past the grace.
    const auto owner {std::to_string(self.pid) + ":" + std::to_string(self.startTime) + ":w9"};

    ReclaimQuery query;
    query.owner = owner;
    query.rowTaskId = "task";
    query.workerInflightTaskId = "";
    query.claimTime = 0;
    query.now = 100000;
    query.claimGrace = std::chrono::seconds {30};

    EXPECT_TRUE(isReclaimable(query, self));
}

TEST(Ownership, ALiveForeignProcessIsNeverReclaimedFrom)
{
    const auto self {selfIdentity(0)};

    // A live process that is not this one. Reading its REAL start time is what makes this a genuine
    // Foreign rather than a Dead: a fabricated start time would classify as a recycled pid.
    const LiveForeignProcess other;
    ASSERT_TRUE(other.valid()) << "/proc must be readable for this test to mean anything";

    const auto owner {other.owner()};
    ASSERT_EQ(classifyOwner(owner, self), OwnerKind::Foreign);

    ReclaimQuery query;
    query.owner = owner;
    query.rowTaskId = "task";
    query.workerInflightTaskId = "";
    query.claimTime = 0;
    query.now = 1'000'000; // arbitrarily far past any grace
    query.claimGrace = std::chrono::seconds {30};

    // Under a systemd restart with an overlapping old process, or an operator starting a second
    // modulesd, those workers may still be mid-call. Inferring death from "not my pid" is what
    // would cause two processes to rotate the same log file at once.
    EXPECT_FALSE(isReclaimable(query, self));
}

TEST(Ownership, AWorkerRunningTheRowIsNeverReclaimedHoweverLongItHasBeen)
{
    const auto self {selfIdentity(0)};

    ReclaimQuery query;
    const auto owner {self.toString()};
    query.owner = owner;
    query.rowTaskId = "task-a";
    query.workerInflightTaskId = "task-a";
    query.claimTime = 0;
    query.now = 1'000'000; // far past any grace
    query.claimGrace = std::chrono::seconds {30};

    // What bounds a long-running handler is its own deadline, not the sweep. Reclaiming here would
    // flip the row to pending while the handler is still executing -- double execution from the
    // very mechanism meant to prevent it.
    EXPECT_FALSE(isReclaimable(query, self));
}

TEST(Ownership, TheGraceCoversTheWindowBetweenClaimingAndPublishing)
{
    const auto self {selfIdentity(0)};
    const auto owner {self.toString()};

    ReclaimQuery query;
    query.owner = owner;
    query.rowTaskId = "task-a";
    query.workerInflightTaskId = ""; // claimed, not yet published
    query.claimTime = 1000;
    query.claimGrace = std::chrono::seconds {30};

    // Inside the grace: the worker has the row and is about to publish it.
    query.now = 1020;
    EXPECT_FALSE(isReclaimable(query, self));

    // Past it: the worker demonstrably is not running this row.
    query.now = 1031;
    EXPECT_TRUE(isReclaimable(query, self));
}
