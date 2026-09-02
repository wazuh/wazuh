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

#include "handlers/localHandlers.hpp"
#include "testDoubles.hpp"

#include <gtest/gtest.h>

#include <ctime>
#include <numeric>

using namespace task_manager;
using namespace task_manager::handlers;
using namespace task_manager::test;

namespace
{
    ClaimedTask claimedTask(const std::string& payload = "{}")
    {
        ClaimedTask task;
        task.taskId = "task-1";
        task.taskType = "test_type";
        task.payload = payload;
        return task;
    }

    LocalConfig defaultLocalConfig()
    {
        LocalConfig config;
        config.disconnectionTime = std::chrono::seconds {900};
        config.deleteOldAgents = 10;
        config.monitorAgents = true;
        config.disconnectLogMax = 200;
        config.disconnectLogBudget = std::chrono::seconds {30};
        config.deleteOldBatch = 200;
        config.deleteOldBudget = std::chrono::seconds {30};
        return config;
    }
} // namespace

// ---- the disconnection sweep -------------------------------------------------------------------

TEST(DisconnectSweep, CompletesWhenTheTransitionSucceeds)
{
    FakeHostOps hostOps;
    hostOps.disconnected = std::vector<int> {1, 2, 3};

    StopToken stop;
    DisconnectSweepHandler handler {hostOps, defaultLocalConfig()};

    const auto result {handler.run(claimedTask(), stop)};

    EXPECT_EQ(result.outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.disconnectCalls.load(), 1) << "the transition is ONE query";
}

TEST(DisconnectSweep, RetriesWhenTheTransitionDidNotComplete)
{
    FakeHostOps hostOps;
    hostOps.disconnected = std::nullopt;

    StopToken stop;
    DisconnectSweepHandler handler {hostOps, defaultLocalConfig()};

    // Reading a failure as "no agents" would silently turn a wedged wazuh-db into a successful
    // no-op sweep.
    const auto result {handler.run(claimedTask(), stop)};
    EXPECT_EQ(result.outcome, Outcome::Retryable);
}

TEST(DisconnectSweep, DoesNotTouchWazuhDbOnceShutdownIsRequested)
{
    // wazuh-db is signalled to stop in the same pass of the init script that signals modulesd, so
    // by the time this handler could run during a stop the socket is routinely already gone. Going
    // ahead anyway is what made an ordinary `systemctl stop wazuh-manager` print ERRORs about an
    // unreachable database -- indistinguishable, to any log-based alert, from wazuh-db crashing.
    FakeHostOps hostOps;
    hostOps.disconnected = std::vector<int> {1, 2, 3};

    StopToken stop;
    stop.requestStop();

    DisconnectSweepHandler handler {hostOps, defaultLocalConfig()};

    const auto result {handler.run(claimedTask(), stop)};

    EXPECT_EQ(hostOps.disconnectCalls.load(), 0) << "the query must not be issued at all";

    // NotReady, not Retryable: a stop is the same "the consumer is not there" condition as the boot
    // race, so it costs a deferral rather than an attempt and cannot walk a schedule toward its
    // dead-letter bound across a few restarts.
    EXPECT_EQ(result.outcome, Outcome::NotReady);
    EXPECT_TRUE(task_manager::isNoFault(result.outcome));
}

TEST(DisconnectSweep, BoundsThePerAgentDiagnosticLookups)
{
    FakeHostOps hostOps;
    std::vector<int> agents(5000);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.disconnected = agents;

    auto config {defaultLocalConfig()};
    config.disconnectLogMax = 50;

    StopToken stop;
    DisconnectSweepHandler handler {hostOps, config};

    const auto result {handler.run(claimedTask(), stop)};

    // The transition already happened for all 5000. What is bounded is the DIAGNOSTIC pass, at one
    // round trip per agent -- which on a partition is minutes of occupancy for log lines nobody
    // reads individually at that volume.
    EXPECT_EQ(result.outcome, Outcome::Ok);
    EXPECT_LE(hostOps.infoCalls.load(), 50);
}

TEST(DisconnectSweep, DropsTheRemainderRatherThanReturningIncomplete)
{
    FakeHostOps hostOps;
    std::vector<int> agents(1000);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.disconnected = agents;

    auto config {defaultLocalConfig()};
    config.disconnectLogMax = 10;

    StopToken stop;
    DisconnectSweepHandler handler {hostOps, config};

    // Incomplete would be the wrong shape: the ids exist only inside this call's return value, so a
    // resumed attempt would have no list to resume from and would re-run a transition with nothing
    // left to transition.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
}

TEST(DisconnectSweep, TurningLoggingOffSkipsTheRoundTripsEntirely)
{
    FakeHostOps hostOps;
    hostOps.disconnected = std::vector<int> {1, 2, 3, 4, 5};

    auto config {defaultLocalConfig()};
    config.monitorAgents = false;

    StopToken stop;
    DisconnectSweepHandler handler {hostOps, config};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);

    // The flag silences the log lines and nothing else -- the transition above ran regardless --
    // and with logging off there is no reason to pay a lookup per agent.
    EXPECT_EQ(hostOps.disconnectCalls.load(), 1);
    EXPECT_EQ(hostOps.infoCalls.load(), 0);
}

TEST(DisconnectSweep, StopsLoggingWhenShutdownIsRequested)
{
    FakeHostOps hostOps;
    std::vector<int> agents(500);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.disconnected = agents;

    StopToken stop;

    // Stopped mid-sweep, not before it: a token already stopped at entry never reaches the
    // diagnostic pass at all -- it takes the pre-flight bail above and returns NotReady. The stop
    // lands once the transition has been written, which is the state a real shutdown leaves behind.
    hostOps.afterDisconnectAgents = [&stop]
    {
        stop.requestStop();
    };

    DisconnectSweepHandler handler {hostOps, defaultLocalConfig()};

    // Ok, not Incomplete: the transition -- the part with a side effect -- did complete for all 500,
    // and only the per-agent log lines were dropped. See DropsTheRemainderRatherThanReturningIncomplete.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.disconnectCalls.load(), 1);
    EXPECT_EQ(hostOps.infoCalls.load(), 0) << "not one round trip is spent logging during a stop";
}

// ---- the retention deletion --------------------------------------------------------------------

TEST(DeleteOldAgents, CompletesImmediatelyWhenTheOptionIsOff)
{
    FakeHostOps hostOps;
    auto config {defaultLocalConfig()};
    config.deleteOldAgents = 0;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, config};

    // Reachable only through a row that outlived the option being turned off. Completing is right:
    // failing would dead-letter a row over a configuration change.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.candidateCalls.load(), 0);
}

TEST(DeleteOldAgents, RetriesWhenTheCandidateQueryFails)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::nullopt;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Retryable);
}

TEST(DeleteOldAgents, DoesNotTouchWazuhDbOnceShutdownIsRequested)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3};

    StopToken stop;
    stop.requestStop();

    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    const auto result {handler.run(claimedTask(), stop)};

    EXPECT_EQ(hostOps.candidateCalls.load(), 0) << "the candidate query must not be issued at all";
    EXPECT_EQ(result.outcome, Outcome::NotReady);
}

TEST(DeleteOldAgents, RemovesOnlyAgentsPastTheWholeWindow)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3};

    // Well inside the window: disconnected, but not yet old enough to delete.
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr));

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.removeCalls.load(), 0);
}

TEST(DeleteOldAgents, RemovesAgentsPastTheWindow)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3};
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.removeCalls.load(), 3);
    EXPECT_EQ(hostOps.removed, (std::vector<int> {1, 2, 3}));
}

TEST(DeleteOldAgents, ReturnsIncompleteWhenTheBatchBoundIsReached)
{
    FakeHostOps hostOps;
    std::vector<int> agents(100);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.candidates = agents;
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;

    auto config {defaultLocalConfig()};
    config.deleteOldBatch = 10;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, config};

    // Neither success nor failure: completing would retire the row with the sweep half done, and
    // consuming an attempt would dead-letter a fleet that simply needs more batches.
    const auto result {handler.run(claimedTask(R"({"scheduled_run_at":5000})"), stop)};
    EXPECT_EQ(result.outcome, Outcome::Incomplete);
    EXPECT_EQ(hostOps.removeCalls.load(), 10);
}

TEST(DeleteOldAgents, ResumesFromTheCursorWithinOneRun)
{
    FakeHostOps hostOps;
    std::vector<int> agents(30);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.candidates = agents;
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;

    auto config {defaultLocalConfig()};
    config.deleteOldBatch = 10;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, config};

    const auto payload {R"({"scheduled_run_at":5000})"};

    ASSERT_EQ(handler.run(claimedTask(payload), stop).outcome, Outcome::Incomplete);
    EXPECT_EQ(hostOps.lastCursor, 0) << "the first attempt starts at the beginning";

    ASSERT_EQ(handler.run(claimedTask(payload), stop).outcome, Outcome::Incomplete);

    // Resumed IN THE QUERY, not by skipping client-side: the underlying query is `WHERE id > ?`, so
    // handing it the cursor costs nothing, while skipping client-side would make a full walk
    // quadratic in the number of disconnected agents.
    EXPECT_EQ(hostOps.lastCursor, 10);

    // The third pass takes the last ten and runs off the end of the page, so the walk is exhausted
    // and the row completes -- the batch bound is only reached when candidates REMAIN.
    EXPECT_EQ(handler.run(claimedTask(payload), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.lastCursor, 20);
    EXPECT_EQ(hostOps.removeCalls.load(), 30);
}

TEST(DeleteOldAgents, ADifferentSlotRestartsTheWalk)
{
    FakeHostOps hostOps;
    std::vector<int> agents(30);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.candidates = agents;
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;

    auto config {defaultLocalConfig()};
    config.deleteOldBatch = 10;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, config};

    ASSERT_EQ(handler.run(claimedTask(R"({"scheduled_run_at":5000})"), stop).outcome, Outcome::Incomplete);
    ASSERT_EQ(handler.run(claimedTask(R"({"scheduled_run_at":5000})"), stop).outcome, Outcome::Incomplete);
    ASSERT_EQ(hostOps.lastCursor, 10);

    // A different slot is a different RUN. Equal slots are attempts at one run, which is what the
    // cursor is for.
    handler.run(claimedTask(R"({"scheduled_run_at":9999})"), stop);
    EXPECT_EQ(hostOps.lastCursor, 0);
}

TEST(DeleteOldAgents, StopsTheSweepOnAnAuthdCapacityRefusal)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3, 4, 5};
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;
    hostOps.nextAuthdError = host::AUTHD_DELETE_BACKLOG;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    const auto result {handler.run(claimedTask(), stop)};

    // Both reachable causes -- a full backlog and an unreachable authd -- are about authd's
    // capacity, not about this agent, so the next candidate would answer the same way and each
    // attempt costs a connect.
    EXPECT_EQ(result.outcome, Outcome::Retryable);
    EXPECT_EQ(hostOps.removeCalls.load(), 1) << "it must not walk on after a capacity refusal";
}

TEST(DeleteOldAgents, AnAlreadyDeletedAgentDoesNotStopTheSweep)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3};
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;
    hostOps.nextAuthdError = host::AUTHD_NO_SUCH_ID;

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    // "Already gone" is success. Treating it as a failure is exactly what would make this handler
    // non-idempotent, and it must tolerate being re-run after a lost outcome write.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.removeCalls.load(), 3);
}

TEST(DeleteOldAgents, SkipsAnAgentWhoseRowCannotBeRead)
{
    FakeHostOps hostOps;
    hostOps.candidates = std::vector<int> {1, 2, 3};
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;
    hostOps.missingInfoFor = {2};

    StopToken stop;
    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    // Not fatal to the sweep, and not retried for that agent: the next run reads it again.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.removed, (std::vector<int> {1, 3}));
}

TEST(DeleteOldAgents, YieldsWhenShutdownIsRequested)
{
    FakeHostOps hostOps;
    std::vector<int> agents(100);
    std::iota(agents.begin(), agents.end(), 1);
    hostOps.candidates = agents;
    hostOps.lastKeepalive = static_cast<Timestamp>(std::time(nullptr)) - 100000;

    StopToken stop;

    // Stopped after the candidate query, so the walk is what observes it. Stopping before run()
    // instead is DoesNotTouchWazuhDbOnceShutdownIsRequested, and returns NotReady.
    hostOps.afterCandidateQuery = [&stop]
    {
        stop.requestStop();
    };

    DeleteOldAgentsHandler handler {hostOps, defaultLocalConfig()};

    // Cooperative cancellation is all that is available; what it buys is that the 30 s shutdown
    // budget is honoured mid-sweep rather than only between tasks. Incomplete rather than Ok because
    // candidates DO remain -- the cursor stays put and the next run resumes from it.
    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Incomplete);
    EXPECT_EQ(hostOps.removeCalls.load(), 0) << "the check is at the head of the loop, so no agent is removed";
}

// ---- daily rotation ----------------------------------------------------------------------------

TEST(LogRotate, CompletesWhenTheHostRotates)
{
    FakeHostOps hostOps;
    StopToken stop;
    LogRotateHandler handler {hostOps, defaultLocalConfig()};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Ok);
    EXPECT_EQ(hostOps.dailyRotations.load(), 1);
}

TEST(LogRotate, RetriesWhenTheRotationDidNotComplete)
{
    FakeHostOps hostOps;
    hostOps.dailyRotationSucceeds = false;

    StopToken stop;
    LogRotateHandler handler {hostOps, defaultLocalConfig()};

    EXPECT_EQ(handler.run(claimedTask(), stop).outcome, Outcome::Retryable);
}

TEST(LogRotate, DefersRatherThanFailingWhenShuttingDown)
{
    FakeHostOps hostOps;
    StopToken stop;
    stop.requestStop();

    LogRotateHandler handler {hostOps, defaultLocalConfig()};

    // Nothing was attempted, so this must not cost the row an attempt.
    const auto result {handler.run(claimedTask(), stop)};
    EXPECT_EQ(result.outcome, Outcome::NotReady);
    EXPECT_EQ(hostOps.dailyRotations.load(), 0);
}
