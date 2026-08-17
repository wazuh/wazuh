/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventorySyncServerTestHooks.hpp"
#include "inventory_sync_server.h"
#include "testIndexerConnectorFakes.hpp"
#include "testLogRecorder.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using invsync::test::LogRecorder;
using invsync::test::testLogCallback;

namespace
{
    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/isg_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    inventory_sync_server_config_t makeConfig(const std::string& socketPath)
    {
        inventory_sync_server_config_t config {};
        std::snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", "test-cluster");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        // One pipeline worker, deterministically: 0 would resolve to half the machine's cores and
        // these tests count connector builds (the pipeline builds one per EXTRA worker).
        config.sync_workers = 1;
        return config;
    }

    /// The worker thread's first attempt races the assertions, so wait for the count rather than
    /// assuming it has already run.
    bool waitForCount(const std::atomic<int>& counter, int expected)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        while (counter.load() < expected && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds {10});
        }
        return counter.load() >= expected;
    }
} // namespace

class IndexerGatingTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        LogRecorder::clear();
    }

    void TearDown() override
    {
        inventory_sync_server_stop();
        // An override made by one test must never leak into the next.
        invsync::test::resetIndexerConnectorFactoriesToProduction();
    }
};

/**
 * No fake injected: the REAL IndexerSession constructor validates config synchronously and throws
 * "No hosts found in the configuration" for the default, empty <indexer> block. That check now runs
 * before anything else, so this stays fast AND never opens `queue/keystore`.
 *
 * The socket must never open, and the failure must be attributed to the indexer, not the socket path.
 */
TEST_F(IndexerGatingTest, BadIndexerConfigWithNoHostsBlocksSocketFromOpening)
{
    const auto path = uniqueSocketPath("nohosts");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    EXPECT_FALSE(LogRecorder::waitForMessageContaining("listening on", std::chrono::milliseconds {500}))
        << "the socket must never open with an invalid indexer configuration";
    EXPECT_FALSE(std::filesystem::exists(path));

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("indexer session"))
        << "the failure must name the indexer session, not the socket";
    EXPECT_FALSE(LogRecorder::sawMessageContaining("socket_path"))
        << "a config-validity failure must not be blamed on the socket";
}

TEST_F(IndexerGatingTest, ValidIndexerConfigUnblocksTheSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("valid");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));
}

/// All three objects must exist before the socket accepts anything -- catches "only some got wired up".
TEST_F(IndexerGatingTest, SessionAndBothConnectorsAreConstructedBeforeTheSocketOpens)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("allthree");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    EXPECT_EQ(1, events->m_sessionBuilds.load());
    // 2 = the facade's slot (admission checks + pipeline worker 0) + the VD scan lane's own worker.
    EXPECT_EQ(2, events->m_syncBuilds.load());
    EXPECT_EQ(1, events->m_asyncBuilds.load());
}

TEST_F(IndexerGatingTest, SessionFailureBlocksTheSocketAndNamesTheSession)
{
    auto events = invsync::test::installFakeIndexersWithFailingSession("simulated session failure");

    const auto path = uniqueSocketPath("sessionfail");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("indexer session"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("simulated session failure"));
    EXPECT_FALSE(std::filesystem::exists(path));

    // Nothing downstream of the failing stage may be attempted.
    EXPECT_EQ(0, events->m_syncBuilds.load());
    EXPECT_EQ(0, events->m_asyncBuilds.load());
}

TEST_F(IndexerGatingTest, SyncConnectorFailureBlocksTheSocketAndNamesTheSyncConnector)
{
    auto events = invsync::test::installFakeIndexersWithFailingSync("simulated sync failure");

    const auto path = uniqueSocketPath("syncfail");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("sync indexer connector"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("async indexer connector"))
        << "the failing half must be named exactly";
    EXPECT_FALSE(std::filesystem::exists(path));

    EXPECT_EQ(0, events->m_asyncBuilds.load()) << "the async half must not be attempted after sync failed";
}

/**
 * The second half of the gate: a healthy session and sync connector are NOT enough. Without this,
 * a broken async configuration would silently let the module serve traffic it cannot handle.
 */
TEST_F(IndexerGatingTest, AsyncConnectorFailureBlocksTheSocketAndNamesTheAsyncConnector)
{
    auto events = invsync::test::installFakeIndexersWithFailingAsync("simulated async failure");

    const auto path = uniqueSocketPath("asyncfail");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("async indexer connector"));
    EXPECT_FALSE(std::filesystem::exists(path)) << "a failing async connector must still gate the socket";

    EXPECT_EQ(1, events->m_sessionBuilds.load());
    EXPECT_EQ(1, events->m_syncBuilds.load());
}

/**
 * reportFailedStart() increments one shared attempt counter that drives the escalation cadence
 * ("60 attempts is about an hour"). Reporting more than once per attempt would halve that clock.
 */
/// The heartbeat's health poll is the only production caller of isAvailable(); its TRANSITIONS are
/// the operator's only record of the indexer going away and coming back. Steady state must stay
/// silent, or sixty lines an hour would say nothing new.
TEST_F(IndexerGatingTest, IndexerAvailabilityTransitionsAreLoggedOncePerChange)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("health");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // First observation: available -> one INFO (the worker's own first heartbeat may already have
    // emitted it; either way it must be there).
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable"));

    LogRecorder::clear();
    events->m_asyncAvailable.store(false);
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("No configured indexer host is currently reachable"));

    // Steady state: a second poll in the same state must not repeat the line.
    LogRecorder::clear();
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));

    events->m_asyncAvailable.store(true);
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable"))
        << "recovery must be as visible as the outage";
}

TEST_F(IndexerGatingTest, OneHeartbeatProducesExactlyOneFailedAttempt)
{
    invsync::test::installFakeIndexersWithFailingAsync("simulated async failure");

    const auto path = uniqueSocketPath("onereport");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));

    // The first-attempt ERROR is emitted exactly once; every later attempt takes the debug branch.
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("could not start"));

    invsync::test_hooks::forceRetryForTests();

    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("could not start"))
        << "the first-attempt ERROR must not be re-emitted on later attempts";
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("start attempt 2 failed"));
}

/**
 * Once an object is built, it is a "configuration is valid" signal that cannot change without a
 * restart, so it must never be rebuilt -- not on the heartbeat, not on a forced retry.
 *
 * Driven from a SUCCESSFUL start rather than the unbindable path this used to use: an unusable socket
 * path is now rejected before the worker is even spawned (it is fatal, see
 * InventorySyncServerModuleTest), so it can no longer be used to hold a later stage failing. The
 * invariant is the same one, and it now also covers the early-out that makes a retry a no-op once the
 * server is up.
 */
TEST_F(IndexerGatingTest, EachSlotIsConstructedOnlyOnceAcrossRetries)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    auto config = makeConfig(uniqueSocketPath("memo"));

    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config));
    ASSERT_TRUE(waitForCount(events->m_asyncBuilds, 1));

    // Two more full retries, forced synchronously instead of waiting out the real 60 s heartbeat.
    invsync::test_hooks::forceRetryForTests();
    invsync::test_hooks::forceRetryForTests();

    EXPECT_EQ(1, events->m_sessionBuilds.load()) << "a successful construction must never be repeated";
    // 2 = the slot + the VD scan lane's worker; both memoised, neither repeated across retries.
    EXPECT_EQ(2, events->m_syncBuilds.load());
    EXPECT_EQ(1, events->m_asyncBuilds.load());
}

/// Per-slot memoisation: the slots that already succeeded stay put while the failing one retries,
/// and the socket opens as soon as it finally succeeds.
TEST_F(IndexerGatingTest, TheSucceedingSlotsAreNotRebuiltWhileAnotherRetries)
{
    auto events = invsync::test::installFakeIndexersWithAsyncFailingTimes(2);

    const auto path = uniqueSocketPath("partialretry");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    ASSERT_TRUE(waitForCount(events->m_asyncBuilds, 1));

    invsync::test_hooks::forceRetryForTests(); // async attempt 2: still fails
    invsync::test_hooks::forceRetryForTests(); // async attempt 3: succeeds

    EXPECT_EQ(1, events->m_sessionBuilds.load());
    // The slot built on attempt 1 and stayed put; the lane's worker connector only builds after
    // the async slot finally succeeds (attempt 3) -- hence 2, not 3+.
    EXPECT_EQ(2, events->m_syncBuilds.load());
    EXPECT_EQ(3, events->m_asyncBuilds.load());

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));
}

/**
 * Also guards the /stats and /config handlers' WEAK hold on the async connector, which is not obvious
 * from the assertion. This test waits for "listening on", so the routes are registered and their
 * captures are live inside the transport's route table by the time stop() runs. If a handler captured
 * the connector strongly, phase 2's reset would no longer destroy it -- the route table would keep it
 * alive until phase 3 -- and the recorded order would come out {"sync", "session", "async"} instead.
 * Verified by mutation: making the capture strong fails exactly this test plus two endpoint ones.
 */
TEST_F(IndexerGatingTest, StopTearsDownEverythingInReverseOrder)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("teardown");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    inventory_sync_server_stop();

    // The scan lane goes down FIRST (its worker connector with it), then the async slot, the sync
    // slot and the session -- reverse construction order with the lane on top.
    const std::vector<std::string> expected {"sync", "async", "sync", "session"};
    EXPECT_EQ(expected, events->destroyed());
}

/**
 * The leak scenario a single-slot suite cannot express: the gate legitimately leaves only SOME of the
 * three built, and stop() must still tear down what exists. Gating one reset on another's pointer
 * would leak that object's background threads on every stop() in this state.
 */
TEST_F(IndexerGatingTest, StopTearsDownWhatExistsEvenWhenLaterStagesNeverRan)
{
    auto events = invsync::test::installFakeIndexersWithFailingSync("simulated sync failure");

    const auto path = uniqueSocketPath("partialstop");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    ASSERT_TRUE(waitForCount(events->m_sessionBuilds, 1));

    inventory_sync_server_stop();

    const std::vector<std::string> expected {"session"};
    EXPECT_EQ(expected, events->destroyed()) << "the session was built and must be torn down";
}

/**
 * @brief The escalation ladder: one ERROR, then debug, then one WARN per hour.
 *
 * Pure logging logic with no test at all until now, which is exactly the kind of code that rots: the
 * ladder is what stops a permanent misconfiguration from either being invisible (all debug) or flooding
 * wazuh-manager.log (all ERROR), and it is what an operator's incident timeline is built from.
 *
 * Driven with forceRetryForTests() rather than the real 60 s heartbeat, so 60 attempts take
 * milliseconds instead of an hour.
 */
TEST_F(IndexerGatingTest, TheEscalationLadderErrorsOnceThenWarnsOncePerHourAndDebugsInBetween)
{
    // ATTEMPTS_PER_ESCALATION in the facade. The 60th failure is the one that must escalate.
    constexpr int ATTEMPTS_PER_ESCALATION {60};

    auto events = invsync::test::installFakeIndexersWithFailingAsync("permanently broken");

    auto config = makeConfig(uniqueSocketPath("ladder"));

    // Attempt 1: the ERROR that names the stage and what to check.
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config))
        << "an indexer failure must NOT be fatal: the indexer may come up after modulesd";
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("async indexer connector"))
        << "the first failure must name which stage is blocking";
    EXPECT_EQ(0U, LogRecorder::countMessagesContaining("still not running after"))
        << "the hourly WARN must not fire on the first attempt";

    // Attempts 2..60, forced synchronously.
    for (int attempt = 2; attempt <= ATTEMPTS_PER_ESCALATION; ++attempt)
    {
        invsync::test_hooks::forceRetryForTests();
    }

    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("still not running after"))
        << "attempt " << ATTEMPTS_PER_ESCALATION << " must escalate to exactly one WARN";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("60 attempt(s)"));

    // The intervening attempts stayed at debug rather than repeating the ERROR.
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("could not start"))
        << "the ERROR is emitted once per incident, not once per attempt";

    // A successful construction is still never repeated, even across 60 failures of a later stage.
    EXPECT_EQ(1, events->m_sessionBuilds.load());
    EXPECT_EQ(1, events->m_syncBuilds.load());

    inventory_sync_server_stop();
}
