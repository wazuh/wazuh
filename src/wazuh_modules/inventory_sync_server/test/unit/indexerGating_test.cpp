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

#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>

#include "fakeIndexer.hpp"
#include "healthRules.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
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

/// A real indexer_client runtime on an in-process fake indexer (health only): what modulesd publishes to
/// the module through `indexer_runtime`. Started and shut down on the test's own thread, the owner thread.
class RealRuntime
{
public:
    RealRuntime()
        : m_fake(std::make_unique<indexer_client::testing::FakeIndexer>())
    {
        m_fake->addRule(indexer_client::testing::healthRule("green"));
        m_fake->start();
        const std::string text = "wazuh_modules.indexer_client_network_threads=1\n"
                                 "wazuh_modules.indexer_client_cpu_threads=2\n"
                                 "wazuh_modules.indexer_client_probe_interval_ms=200\n";
        const std::string json = "{\"hosts\":[\"" + m_fake->baseUrl() + "\"]}";
        auto source = indexer_client::KeyValueConfigSource::parse(text, json, indexer_client::Credentials {"a", "b"});
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
        if (started.ok())
        {
            m_ref = started.value;
            m_started = true;
        }
    }

    ~RealRuntime()
    {
        if (m_started)
        {
            indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + std::chrono::seconds {5});
            indexer_client::RuntimeOwner::shutdown();
        }
    }

    RealRuntime(const RealRuntime&) = delete;
    RealRuntime& operator=(const RealRuntime&) = delete;

    bool started() const
    {
        return m_started;
    }

    /// What goes into `config.indexer_runtime`.
    const void* published() const
    {
        return &m_ref;
    }

    const indexer_client::RuntimeRef& ref() const
    {
        return m_ref;
    }

private:
    std::unique_ptr<indexer_client::testing::FakeIndexer> m_fake;
    indexer_client::RuntimeRef m_ref;
    bool m_started {false};
};

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
    // The sync half's Client is built once, before every connector that runs on it.
    EXPECT_EQ(1, events->m_clientBuilds.load());
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

/**
 * The lane-only-fails permutation: the first attempt publishes session + client + sync + async + pipeline
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
 * CA-E7b-10: with no runtime published (`indexer_runtime` NULL) the sync stage of the gate fails with a
 * log line that names it; nothing after it is built, the socket never opens, and the heartbeat retries.
 */
TEST_F(IndexerGatingTest, NullRuntimeFailsSyncGate)
{
    auto events = invsync::test::installAlwaysAvailableFakeIndexers();
    // The production Client factory over a NULL runtime: the check the facade's own factory makes.
    invsync::test_hooks::setIndexerClientFactoryForTests(invsync::test::productionIndexerClientFactory());

    const auto path = uniqueSocketPath("noruntime");
    const auto config = makeConfig(path); // indexer_runtime stays NULL

    ASSERT_EQ(0, inventory_sync_server_start(testLogCallback, &config))
        << "a missing runtime is not fatal: the heartbeat retries";
    ASSERT_TRUE(LogRecorder::waitForMessageContaining("could not start"));
    EXPECT_TRUE(LogRecorder::sawMessageContaining("sync indexer connector"));
    EXPECT_FALSE(LogRecorder::sawMessageContaining("async indexer connector"));
    EXPECT_FALSE(std::filesystem::exists(path));

    // Nothing downstream of the failing stage was attempted.
    EXPECT_EQ(0, events->m_syncBuilds.load());
    EXPECT_EQ(0, events->m_asyncBuilds.load());

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
        [production, built](const void* runtime,
                            const indexer_client::BucketSpec& bucket) -> std::shared_ptr<indexer_client::IClient>
        {
            auto client = production(runtime, bucket);
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
