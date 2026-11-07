/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
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
#include "testRealIndexer.hpp"
#include "udsTestClient.hpp"

#include <indexer_client/runtime.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
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
        // One pipeline worker and one VD scan-lane worker, deterministically: 0 would resolve to
        // half the machine's cores on both knobs, and these tests count connector builds (the
        // pipeline builds one per EXTRA worker, the VD lane builds one per worker of its own).
        config.sync_workers = 1;
        config.vd_workers = 1;
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

/// A real indexer_client runtime on an in-process fake indexer (health, `_bulk` and the by-query routes answered):
/// what modulesd publishes to the module through `indexer_runtime`. Started and shut down on the test's own
/// thread, the owner thread. @p extraOptions are more internal-options lines (e.g. a small global quota).
class RealRuntime
{
public:
    explicit RealRuntime(const std::string& extraOptions = "")
    {
        m_real.startRuntime(extraOptions);
    }

    RealRuntime(const RealRuntime&) = delete;
    RealRuntime& operator=(const RealRuntime&) = delete;

    bool started() const
    {
        return m_real.runtimeStarted;
    }

    /// What goes into `config.indexer_runtime`.
    const void* published() const
    {
        return &m_real.ref;
    }

    const indexer_client::RuntimeRef& ref() const
    {
        return m_real.ref;
    }

    invsync::test::RealIndexer& real()
    {
        return m_real;
    }

private:
    invsync::test::RealIndexer m_real;
};

/// POST /_internal/agents/delete with the bytes the Task Manager's dispatcher puts on the wire.
static std::string deleteRequestFor(const std::string& agentId)
{
    const std::string body = "{\"agent_id\":\"" + agentId + "\"}";
    return "POST /_internal/agents/delete HTTP/1.1\r\nHost: localhost\r\n"
           "Content-Type: application/json\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
}

/// Threads of this process: a sweeper thread that outlives stop() would show here.
static std::size_t threadCount()
{
    std::size_t count {0};
    if (auto* dir = ::opendir("/proc/self/task"))
    {
        while (const auto* entry = ::readdir(dir))
        {
            count += entry->d_name[0] != '.' ? 1 : 0;
        }
        ::closedir(dir);
    }
    return count;
}

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
        // The runtime outlives the module that borrowed it: shut down only after the stop above.
        m_runtime.reset();
        // An override made by one test must never leak into the next.
        invsync::test::resetIndexerConnectorFactoriesToProduction();
    }

    std::optional<RealRuntime> m_runtime;
};

TEST_F(IndexerGatingTest, ValidIndexerConfigUnblocksTheSocket)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("valid");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));
}

/**
 * CA-E7c-7: ONE Client with TWO bucket specs -- `inventory` and `agent-state` -- is built before the socket
 * accepts anything, and both sync connectors (the facade's slot and the VD lane's) run on it.
 */
TEST_F(IndexerGatingTest, OneClientTwoBuckets)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("onetwo");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    EXPECT_EQ(1, events->m_clientBuilds.load());
    // 2 = the facade's slot (admission checks + pipeline worker 0) + the VD scan lane's own worker.
    EXPECT_EQ(2, events->m_syncBuilds.load());

    std::lock_guard<std::mutex> lock(events->m_mutex);
    ASSERT_EQ(1U, events->m_clientBucketSpecs.size());
    const auto& specs = events->m_clientBucketSpecs.front();
    ASSERT_EQ(2U, specs.size());
    EXPECT_EQ(invsync::indexer::INVENTORY_BUCKET, specs[0].name);
    EXPECT_FALSE(specs[0].ordered);
    EXPECT_EQ(invsync::indexer::AGENT_STATE_BUCKET, specs[1].name);
    EXPECT_TRUE(specs[1].ordered) << "the agent-state bucket orders a delete behind the reports of its key";
    EXPECT_EQ(indexer_client::Overflow::Kind::Reject, specs[1].overflow.kind);
}

/**
 * CA-E7c-7: whatever the operator set, the `agent-state` spec the facade derives is one the library accepts and
 * in which a whole-agent deletion's Group of two deletes fits (no GroupTooLarge). Each case runs a REAL
 * RuntimeRef::client() on a runtime with that global quota, the module's own derivation (agent-state first,
 * inventory from the rest), and one by-id delete Group on it.
 */
TEST_F(IndexerGatingTest, AgentStateSpecAlwaysValid)
{
    struct Case
    {
        const char* name;
        std::uint64_t global;
        long long maxQueueBytes;
        int bulkMaxBytes;
        bool warns;
    };
    constexpr std::uint64_t MIB {1024ULL * 1024ULL};
    const std::vector<Case> cases {
        {"defaults", 256 * MIB, 0, -1, false},
        {"bulk 100 MiB", 256 * MIB, 0, 100 * 1024 * 1024, true},
        // The queue is raised to hold one bulk, silently: nothing the operator asked for was cut.
        {"queue smaller than the bulk", 256 * MIB, 1 * 1024 * 1024, 4 * 1024 * 1024, false},
        {"max_queue_bytes 1024", 256 * MIB, 1024, -1, false},
        {"global 16 KiB", 16 * 1024, 0, -1, true},
        {"global 64 MiB", 64 * MIB, 0, -1, false},
    };

    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.name);
        RealRuntime runtime {"wazuh_modules.indexer_client_global_quota_bytes=" + std::to_string(testCase.global) +
                             "\n"};
        ASSERT_TRUE(runtime.started()) << runtime.real().startError;

        auto config = invsync::test::RealIndexer::noOpinionConfig();
        config.indexer_async_max_queue_bytes = testCase.maxQueueBytes;
        config.indexer_async_bulk_max_bytes = testCase.bulkMaxBytes;

        std::string warning;
        invsync::test::RealIndexer::Specs specs;
        specs.agentState = invsync::indexer::agentStateBucketSpec(config, testCase.global, &warning);
        EXPECT_EQ(testCase.warns, !warning.empty()) << "warning: " << warning;
        std::string inventoryWarning;
        specs.inventory = invsync::indexer::inventoryBucketSpec(
            config, testCase.global - specs.agentState.quotaBytes, std::chrono::seconds {2}, &inventoryWarning);

        ASSERT_TRUE(runtime.real().makeClient(specs)) << runtime.real().startError;

        // A deletion's by-id half: one Group of the two deletes, tagged with the agent.
        auto writer = runtime.real().agentStateWriter();
        ASSERT_NE(nullptr, writer);
        auto group = writer->group();
        for (const auto* index : {"wazuh-agent-config", "wazuh-agent-stats"})
        {
            indexer_client::Op op;
            op.kind = indexer_client::Op::Kind::Delete;
            op.index = index;
            op.id = "007";
            op.tag = "007";
            ASSERT_EQ(indexer_client::Cause::None, group.add(std::move(op))) << group.lastAddReason();
        }
        const auto results = group.commit().wait(std::chrono::steady_clock::now() + std::chrono::seconds {5});
        ASSERT_TRUE(results.ok()) << indexer_client::toString(results.cause) << ": " << results.reason;
        for (const auto& result : results.value)
        {
            EXPECT_EQ(indexer_client::Status::Ok, result.status) << indexer_client::toString(result.cause);
        }
    }
}

/**
 * CA-E7c-7: a Client that hands out no `agent-state` writer, or no query, fails the gate -- named, retried by the
 * heartbeat, the socket never opened -- instead of passing it with nothing to write through.
 */
TEST_F(IndexerGatingTest, ClientWithoutWriterOrQueryFailsTheGate)
{
    {
        auto events = invsync::test::installAlwaysAvailableFakeIndexers();
        events->m_agentStateWriter.reset(); // writer("agent-state") answers nullptr

        const auto path = uniqueSocketPath("nowriter");
        const auto config = makeConfig(path);
        inventory_sync_server_start(testLogCallback, &config);

        ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
        EXPECT_TRUE(LogRecorder::sawMessageContaining("the indexer client configuration is invalid"));
        EXPECT_FALSE(std::filesystem::exists(path));
        EXPECT_EQ(0, events->m_syncBuilds.load()) << "nothing downstream of the writer may be built";
        inventory_sync_server_stop();
    }

    LogRecorder::clear();
    {
        auto events = invsync::test::installAlwaysAvailableFakeIndexers();
        events->m_query.reset(); // query() answers nullptr

        const auto path = uniqueSocketPath("noquery");
        const auto config = makeConfig(path);
        inventory_sync_server_start(testLogCallback, &config);

        ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
        EXPECT_TRUE(LogRecorder::sawMessageContaining("the indexer client configuration is invalid"));
        EXPECT_FALSE(std::filesystem::exists(path));
        EXPECT_EQ(0, events->m_syncBuilds.load()) << "nothing downstream of the query may be built";
    }
}

TEST_F(IndexerGatingTest, ClientFailureBlocksTheSocketAndNamesTheSyncConnector)
{
    auto events = invsync::test::installFakeIndexersWithFailingClient("simulated client failure");

    const auto path = uniqueSocketPath("clientfail");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("the indexer client configuration is invalid"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("simulated client failure"));
    EXPECT_FALSE(std::filesystem::exists(path));

    // Nothing downstream of the failing stage may be attempted.
    EXPECT_EQ(0, events->m_syncBuilds.load());
}

TEST_F(IndexerGatingTest, SyncConnectorFailureBlocksTheSocketAndNamesTheSyncConnector)
{
    auto events = invsync::test::installFakeIndexersWithFailingSync("simulated sync failure");

    const auto path = uniqueSocketPath("syncfail");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("the indexer client configuration is invalid"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("simulated sync failure"));
    EXPECT_FALSE(std::filesystem::exists(path));

    EXPECT_EQ(1, events->m_clientBuilds.load()) << "the Client built before it is published and kept";
}

/**
 * reportFailedStart() increments one shared attempt counter that drives the escalation cadence
 * ("60 attempts is about an hour"). Reporting more than once per attempt would halve that clock.
 */
/// The heartbeat's health poll reads the Client's HealthView (health().anyUsable(), I151); its TRANSITIONS are
/// the operator's only record of the indexer going away and coming back. Steady state must stay
/// silent, or sixty lines an hour would say nothing new.
TEST_F(IndexerGatingTest, HealthLogFromClient)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("health");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // First observation: usable -> one INFO (the worker's own first heartbeat may already have
    // emitted it; either way it must be there).
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable"));

    LogRecorder::clear();
    events->m_clientUsable.store(false);
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("No configured indexer host is currently reachable"));

    // Steady state: a second poll in the same state must not repeat the line.
    LogRecorder::clear();
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));

    events->m_clientUsable.store(true);
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable"))
        << "recovery must be as visible as the outage";
}

/// A3 (E12 A/B): every node is born Down with no reason until the Client's first probe round (I190b). A heartbeat
/// that lands before that round must not log "unreachable" -- the indexer is not known yet -- and must not latch
/// the state, so the first heartbeat after the round still logs the real one, whichever it is.
TEST_F(IndexerGatingTest, HealthLogIsSilentBeforeTheFirstProbeRound)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    events->m_clientUsable.store(false);
    events->m_clientProbed.store(false);

    const auto path = uniqueSocketPath("health-unprobed");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // The worker's own first heartbeat follows the startup that logged "listening on" and sees the same unprobed
    // node; this poll stands in for it deterministically.
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("indexer is reachable"));

    // The round ends with the node usable: the first state logged is "reachable", with no outage before it.
    events->m_clientUsable.store(true);
    events->m_clientProbed.store(true);
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));

    inventory_sync_server_stop();
}

/// The other outcome of the first round: Down WITH a reason is a real outage and is logged at once.
TEST_F(IndexerGatingTest, HealthLogReportsUnreachableOnceTheFirstRoundFails)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    events->m_clientUsable.store(false);
    events->m_clientProbed.store(false);

    const auto path = uniqueSocketPath("health-down");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    invsync::test_hooks::pollIndexerHealthForTests();
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));

    events->m_clientProbed.store(true);
    invsync::test_hooks::pollIndexerHealthForTests();
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("No configured indexer host is currently reachable"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("indexer is reachable"));

    inventory_sync_server_stop();
}

/// While the first probe round is pending the worker looks again every second instead of a whole heartbeat (60 s)
/// later: "reachable" follows the end of the round by about a second, with no test hook polling for it.
TEST_F(IndexerGatingTest, HeartbeatRepollsUntilTheFirstProbeRoundEnds)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    events->m_clientUsable.store(false);
    events->m_clientProbed.store(false);

    const auto path = uniqueSocketPath("health-repoll");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    std::this_thread::sleep_for(std::chrono::milliseconds {1500}); // at least one re-poll before the round ends
    EXPECT_FALSE(LogRecorder::sawMessageContaining("No configured indexer host"));

    events->m_clientUsable.store(true);
    events->m_clientProbed.store(true);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("indexer is reachable", std::chrono::seconds {5}))
        << "the worker waited out the whole heartbeat";

    inventory_sync_server_stop();
}

TEST_F(IndexerGatingTest, OneHeartbeatProducesExactlyOneFailedAttempt)
{
    invsync::test::installFakeIndexersWithFailingSync("simulated sync failure");

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
    ASSERT_TRUE(waitForCount(events->m_clientBuilds, 1));
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    // Two more full retries, forced synchronously instead of waiting out the real 60 s heartbeat.
    invsync::test_hooks::forceRetryForTests();
    invsync::test_hooks::forceRetryForTests();

    EXPECT_EQ(1, events->m_clientBuilds.load()) << "a successful construction must never be repeated";
    // 2 = the slot + the VD scan lane's worker; both memoised, neither repeated across retries.
    EXPECT_EQ(2, events->m_syncBuilds.load());
}

/// Per-slot memoisation: the slots that already succeeded (the Client, the writer, the sweeper) stay put while
/// the failing one retries, and the socket opens as soon as it finally succeeds.
TEST_F(IndexerGatingTest, TheSucceedingSlotsAreNotRebuiltWhileAnotherRetries)
{
    auto events = invsync::test::installFakeIndexersWithSyncFailingTimes(2);

    const auto path = uniqueSocketPath("partialretry");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    ASSERT_TRUE(waitForCount(events->m_syncBuilds, 1));

    invsync::test_hooks::forceRetryForTests(); // sync attempt 2: still fails
    invsync::test_hooks::forceRetryForTests(); // sync attempt 3: succeeds

    EXPECT_EQ(1, events->m_clientBuilds.load()) << "the Client built on attempt 1 is not rebuilt";
    // Attempts 1 and 2 failed, attempt 3 built the slot and the lane's worker connector followed: 4, not 6+.
    EXPECT_EQ(4, events->m_syncBuilds.load());

    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_TRUE(std::filesystem::exists(path));
}

/**
 * Also guards the endpoint handlers' WEAK hold on the Client and the writer, which is not obvious from the
 * assertion. This test waits for "listening on", so the routes are registered and their captures are live inside
 * the transport's route table by the time stop() runs. If a handler captured the Client strongly, phase 2's reset
 * would no longer destroy it -- the route table would keep it alive until phase 3 -- and the recorded order would
 * come out with the Client last of a later phase instead of right after the connectors.
 */
TEST_F(IndexerGatingTest, StopTearsDownEverythingInReverseOrder)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("teardown");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    inventory_sync_server_stop();

    // The scan lane goes down FIRST (its worker connector with it), then the sync slot, then the Client --
    // reverse construction order with the lane on top.
    const std::vector<std::string> expected {"sync", "sync", "client"};
    EXPECT_EQ(expected, events->destroyed());
}

/**
 * The leak scenario a single-slot suite cannot express: the gate legitimately leaves only SOME slots built (here
 * the Client, the writer and the sweeper's thread), and stop() must still tear down what exists. Gating one reset
 * on another's pointer would leak that object's background threads on every stop() in this state.
 */
TEST_F(IndexerGatingTest, StopTearsDownWhatExistsEvenWhenLaterStagesNeverRan)
{
    auto events = invsync::test::installFakeIndexersWithFailingSync("simulated sync failure");

    const auto path = uniqueSocketPath("partialstop");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    ASSERT_TRUE(waitForCount(events->m_clientBuilds, 1));

    inventory_sync_server_stop();

    const std::vector<std::string> expected {"client"};
    EXPECT_EQ(expected, events->destroyed()) << "the Client was built and must be torn down";
    EXPECT_GE(events->m_clientCloses.load(), 1) << "stop() closes the Client's admission before anything else";
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

    // The scan lane is the LAST stage of the gate: the Client, the writer, the sweeper, the sync connector and the
    // pipeline all succeed on attempt 1 and must not be rebuilt across the 59 retries that follow.
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    invsync::test_hooks::setVdScannerFactoryForTests([](bool) -> std::shared_ptr<invsync::vd::IVdScanner>
                                                     { throw std::runtime_error("permanently broken"); });

    auto config = makeConfig(uniqueSocketPath("ladder"));

    // Attempt 1: the ERROR that names the stage and what to check.
    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config))
        << "an indexer failure must NOT be fatal: the indexer may come up after modulesd";
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("VD scan lane"))
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
    EXPECT_EQ(1, events->m_clientBuilds.load());
    EXPECT_EQ(1, events->m_syncBuilds.load());

    inventory_sync_server_stop();
}

/**
 * The lane-only-fails permutation: the first attempt publishes client + writer + sweeper + sync + pipeline
 * and leaves ONLY the lane missing, so the retry exercises the construction path with every other slot
 * flag false. The lane's connector factory must still be handed a live Client and a usable chunk cap.
 */
TEST_F(IndexerGatingTest, TheLaneRetriesWithAUsableClientAndCap)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    struct Seen
    {
        bool client {false};
        std::size_t cap {0};
        std::string tag;
    };
    auto seen = std::make_shared<std::vector<Seen>>();
    auto seenMutex = std::make_shared<std::mutex>();
    invsync::test_hooks::setIndexerConnectorSyncFactoryForTests(
        [events, seen, seenMutex](std::shared_ptr<indexer_client::IClient> client,
                                  const invsync::indexer::AdapterOptions& options,
                                  std::shared_ptr<const std::atomic<bool>>,
                                  const std::string& tag) -> std::unique_ptr<invsync::indexer::IIndexerConnectorSync>
        {
            {
                std::lock_guard<std::mutex> lock(*seenMutex);
                seen->push_back({client != nullptr, options.capBytes, tag});
            }
            events->m_syncBuilds.fetch_add(1);
            return std::make_unique<invsync::test::FakeIndexerConnectorSync>(events, "sync");
        });

    // The scanner factory fails the FIRST lane attempt only. The scanner is built before the
    // lane's own connectors, so attempt 1 fails the lane stage without consuming the sync stage.
    auto scannerAttempts = std::make_shared<std::atomic<int>>(0);
    invsync::test_hooks::setVdScannerFactoryForTests(
        [events, scannerAttempts](bool) -> std::shared_ptr<invsync::vd::IVdScanner>
        {
            if (scannerAttempts->fetch_add(1) == 0)
            {
                throw std::runtime_error("scanner not ready yet");
            }
            return std::make_shared<invsync::test::FakeVdScanner>(events);
        });

    const auto path = uniqueSocketPath("laneretry");
    auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));

    invsync::test_hooks::forceRetryForTests();

    // The lane comes up on the retry and the socket opens.
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"))
        << "a lane-only retry must succeed: the lane's connector factory needs the Client and a cap";
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(1, events->m_clientBuilds.load()) << "the Client built on attempt 1 is not rebuilt on the retry";

    // Every connector build -- the lane's retry included -- received a Client and a positive cap.
    std::lock_guard<std::mutex> lock(*seenMutex);
    ASSERT_EQ(2U, seen->size());
    for (const auto& build : *seen)
    {
        EXPECT_TRUE(build.client) << "a connector was built without a Client (" << build.tag << ")";
        EXPECT_GT(build.cap, 0U) << "a connector was built without a chunk cap (" << build.tag << ")";
    }
}

/**
 * Every sync connector the module builds -- the admission slot (and pipeline worker 0) and the VD lane's --
 * gets its own cancellation tag and the same chunk cap: the bucket's quota shared out over the pipeline
 * and scan-lane workers (I137b). There is no flush timer to configure any more: the workers own every
 * flush and the client library owns the transport.
 */
TEST_F(IndexerGatingTest, PipelineConnectorsAreBuiltWithATagAndTheLaneShareOfTheQuota)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();

    const auto path = uniqueSocketPath("chunkcap");
    const auto config = makeConfig(path);

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    std::lock_guard<std::mutex> lock(events->m_mutex);
    // 2 = the facade's slot (admission checks + pipeline worker 0) + the VD scan lane's worker.
    ASSERT_EQ(2U, events->m_syncTags.size());
    EXPECT_EQ("w0", events->m_syncTags[0]);
    EXPECT_EQ("vd0", events->m_syncTags[1]);
    // The default bucket (64 MiB: no runtime is published, so the fallback global quota applies) over
    // one pipeline worker plus one lane worker.
    const auto expected = invsync::indexer::chunkCap(64U * 1024U * 1024U, 2);
    for (const auto cap : events->m_syncCaps)
    {
        EXPECT_EQ(expected, cap);
    }
}

/**
 * CA-E7b-10, CA-E7c-7: with no runtime published (`indexer_runtime` NULL) the gate fails with a log line that
 * names the stage; nothing after it is built, the socket never opens, and the heartbeat retries.
 */
TEST_F(IndexerGatingTest, NullRuntimeFailsGate)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    // The production Client factory over a NULL runtime: the check the facade's own factory makes.
    invsync::test_hooks::setIndexerClientFactoryForTests(invsync::test::productionIndexerClientFactory());

    const auto path = uniqueSocketPath("noruntime");
    const auto config = makeConfig(path); // indexer_runtime stays NULL

    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config))
        << "a missing runtime is not fatal: the heartbeat retries";
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("the indexer client configuration is invalid"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("no indexer_client runtime was published"));
    EXPECT_FALSE(std::filesystem::exists(path));

    // Nothing downstream of the failing stage was attempted.
    EXPECT_EQ(0, events->m_syncBuilds.load());

    // One ERROR for the incident, then the heartbeat keeps trying.
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("could not start"));
    invsync::test_hooks::forceRetryForTests();
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("start attempt 2 failed"));
    EXPECT_FALSE(std::filesystem::exists(path));
}

/**
 * D73, D78: stop() lets go of the Client. The test installs an IndexerClientFactory that wraps the
 * production one and keeps a weak_ptr to what it built; the sync connectors are the real adapters, so any
 * holder of the Client left alive after stop() -- an adapter, the metrics slot, the facade -- shows.
 */
TEST_F(IndexerGatingTest, StopReleasesClient)
{
    m_runtime.emplace();
    ASSERT_TRUE(m_runtime->started());

    invsync::test::installFakeIndexersOverRealClient();
    auto built = std::make_shared<std::weak_ptr<indexer_client::IClient>>();
    auto production = invsync::test::productionIndexerClientFactory();
    invsync::test_hooks::setIndexerClientFactoryForTests(
        [production, built](const void* runtime, const std::vector<indexer_client::BucketSpec>& buckets)
            -> std::shared_ptr<indexer_client::IClient>
        {
            auto client = production(runtime, buckets);
            *built = client;
            return client;
        });

    const auto path = uniqueSocketPath("release");
    auto config = makeConfig(path);
    config.indexer_runtime = m_runtime->published();

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    ASSERT_FALSE(built->expired()) << "the module never built its Client";

    const auto usageErrorsBefore = indexer_client::detail::testing::usageErrors();
    inventory_sync_server_stop();

    EXPECT_TRUE(built->expired()) << "something still holds the module's Client after stop()";

    // The consumer name is free again: a second client() on the same runtime is accepted.
    auto again =
        m_runtime->ref().client(invsync::indexer::INDEXER_CLIENT_CONSUMER,
                                std::vector<indexer_client::BucketSpec> {invsync::indexer::inventoryBucketSpec(
                                    inventory_sync_server_config_t {}, 256ULL << 20, std::chrono::seconds {2})});
    EXPECT_TRUE(again.ok()) << indexer_client::toString(again.cause) << ": " << again.reason;
    if (again.value)
    {
        again.value->requestClose();
        again.value->awaitClosed(std::chrono::steady_clock::now() + std::chrono::seconds {3});
    }
    again.value.reset();

    EXPECT_EQ(usageErrorsBefore, indexer_client::detail::testing::usageErrors())
        << "stopping the module closed the Client in a way the library counts as a usage error";
}

/**
 * I138: the sync request timeout is the client runtime's now, so a value other than modulesd's default
 * is an option that does nothing -- the operator is told ONCE, at start, not on every heartbeat.
 */
TEST_F(IndexerGatingTest, IgnoredSyncOptionWarns)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    auto config = makeConfig(uniqueSocketPath("ignored"));
    config.indexer_sync_request_timeout_seconds = 99;

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("indexer_sync_request_timeout_seconds"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("has no effect"));

    invsync::test_hooks::forceRetryForTests();
    invsync::test_hooks::forceRetryForTests();
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("indexer_sync_request_timeout_seconds"))
        << "the warning belongs to start(), not to each retry";

    // The default value is left alone: nothing to warn about.
    inventory_sync_server_stop();
    LogRecorder::clear();
    config.indexer_sync_request_timeout_seconds = 60;
    config.socket_path[0] = '\0';
    std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", uniqueSocketPath("ignored2").c_str());
    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("indexer_sync_request_timeout_seconds"));
}

/**
 * I149: the `indexer_async_*` and monitoring options that no longer act warn ONCE, at start, naming each tuned one;
 * a default (or <= 0) value is silent.
 */
TEST_F(IndexerGatingTest, IgnoredAsyncOptionWarns)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    auto config = makeConfig(uniqueSocketPath("asyncignored"));
    config.indexer_async_flush_interval_seconds = 99;
    config.indexer_monitoring_interval_seconds = 33;
    config.indexer_async_request_timeout_seconds = 60; // its default: not named

    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));

    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("indexer_async_flush_interval_seconds"));
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("indexer_monitoring_interval_seconds"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("indexer_async_request_timeout_seconds"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("no effect since the indexer client replaced"));

    invsync::test_hooks::forceRetryForTests();
    invsync::test_hooks::forceRetryForTests();
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("indexer_async_flush_interval_seconds"))
        << "the warning belongs to start(), not to each retry";

    // Every option at its default: nothing to warn about.
    inventory_sync_server_stop();
    LogRecorder::clear();
    auto quiet = makeConfig(uniqueSocketPath("asyncquiet"));
    quiet.indexer_async_flush_interval_seconds = 20;
    quiet.indexer_async_logger_queue_size = 8;
    quiet.indexer_monitoring_interval_seconds = 10;
    inventory_sync_server_start(testLogCallback, &quiet);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("no effect since the indexer client replaced"));
}

/**
 * CA-E7c-7: stop() stops the sweeper and joins its thread. The sweeper owns a thread from construction, so one
 * left behind would outlive the module (and its Client, whose query it holds): the process's thread count after
 * stop() is the one before start().
 */
TEST_F(IndexerGatingTest, StopStopsSweeper)
{
    invsync::test::installAlwaysAvailableFakeIndexers();

    const auto before = threadCount();
    const auto path = uniqueSocketPath("sweeperstop");
    const auto config = makeConfig(path);
    inventory_sync_server_start(testLogCallback, &config);
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("listening on"));
    EXPECT_GT(threadCount(), before) << "the module's threads are up";

    inventory_sync_server_stop();

    EXPECT_TRUE(invsync::test::waitUntil([&] { return threadCount() <= before; }, std::chrono::seconds {3}))
        << "threads before start: " << before << ", after stop: " << threadCount();
}
