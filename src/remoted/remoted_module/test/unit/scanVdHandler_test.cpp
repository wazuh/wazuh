/*
 * Wazuh remoted module - ScanVdHandlerImpl unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the queue/dedup/backoff state machine end-to-end against a real VdClient and a real
 * FakeVdServer (see fakeVdServer.hpp) standing in for VD's /offset and /scan endpoints. The
 * immediate accept/reject decision (handleVdScan's callback) is synchronous; the actual scan
 * trigger, retries and execution-time re-validation happen on background worker threads, so most
 * tests here poll metrics/counters with a generous timeout rather than asserting immediately.
 */

#include "common/vdClient.hpp"
#include "fakeVdServer.hpp"
#include "scanvd/scanVdHandler.hpp"
#include "scanvd/scanVdMetrics.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <json.hpp>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using remoted::common::VdClient;
using remoted::endpoints::scanvd::ScanVdOutcome;
using remoted::endpoints::scanvd::ScanVdResponse;
using remoted::scanvd::makeScanVdMetrics;
using remoted::scanvd::ScanVdHandlerImpl;
using remoted::scanvd::ScanVdMetrics;
using remoted::test::FakeVdServer;
using remoted::test::makeUniqueVdSocketPath;

namespace
{
    constexpr auto VDCLIENT_TTL = 30ms;
    constexpr auto VDCLIENT_FAILURE_RETRY = 30ms;
    constexpr auto POLL_TIMEOUT = 5s;
    constexpr auto POLL_INTERVAL = 10ms;

    template<typename Predicate>
    bool waitUntil(Predicate predicate, std::chrono::milliseconds timeout = POLL_TIMEOUT)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (predicate())
            {
                return true;
            }
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
        return predicate();
    }

    ScanVdResponse callSync(ScanVdHandlerImpl& handler, uint32_t agentId, uint64_t offset)
    {
        ScanVdResponse result {};
        handler.handleVdScan(agentId, offset, [&result](const ScanVdResponse& r) { result = r; });
        return result;
    }

    // A scan handler that blocks every call indefinitely until release() is called, at which
    // point it opens permanently (every blocked and future call passes straight through). Unlike
    // RecordingSlowScanHandler's fixed sleep, this gives full, wall-clock-independent control
    // over exactly when an in-flight attempt is allowed to complete -- essential for tests that
    // need a guarantee like "this many workers are busy" regardless of how long test setup
    // (e.g. a long, synchronous submission loop) happens to take on a loaded machine.
    class GatedScanHandler
    {
    public:
        void operator()(const httplib::Request& req, httplib::Response& res)
        {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_waitingCount++;
                // Bounded on purpose: a passing test releases within milliseconds, and a FAILING
                // one must degrade to a clean assertion failure -- an unbounded wait here turns
                // any missed release() into pool threads parked forever and a teardown that never
                // returns (the server can't join its pool).
                m_cv.wait_for(lock, std::chrono::seconds(10), [this] { return m_released; });
            }
            {
                std::lock_guard<std::mutex> idLock(m_idMutex);
                try
                {
                    m_agentIds.push_back(nlohmann::json::parse(req.body).value("agent_id", std::string {}));
                }
                catch (...)
                {
                    m_agentIds.push_back("<unparseable>");
                }
            }
            res.set_content("{}", "application/json");
        }

        // Polls until at least `n` calls are currently blocked at the gate.
        bool waitForWaiters(size_t n, std::chrono::milliseconds timeout)
        {
            return waitUntil(
                [&]
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    return m_waitingCount >= n;
                },
                timeout);
        }

        // Opens the gate permanently.
        void release()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_released = true;
            m_cv.notify_all();
        }

        size_t count(const std::string& agentId) const
        {
            std::lock_guard<std::mutex> lock(m_idMutex);
            return static_cast<size_t>(std::count(m_agentIds.begin(), m_agentIds.end(), agentId));
        }

    private:
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_released {false};
        size_t m_waitingCount {0};
        mutable std::mutex m_idMutex;
        std::vector<std::string> m_agentIds;
    };

    // Opens the gate on scope exit so an ASSERT_* early return can never leave handler workers
    // (or server pool threads) parked behind it during teardown. Declare it AFTER the handler
    // under test: destruction runs in reverse, so the release happens before the handler's
    // destructor joins its workers.
    struct GateReleaser
    {
        GatedScanHandler& gate;
        ~GateReleaser()
        {
            gate.release();
        }
    };
} // namespace

TEST(ScanVdHandlerTest, VersionMismatchRejectsWithoutEverTriggeringAScan)
{
    const auto socketPath = makeUniqueVdSocketPath("mismatch");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 1, 50 /* stale offset */);

    EXPECT_EQ(response.outcome, ScanVdOutcome::VersionMismatch);
    EXPECT_EQ(response.currentOffset, 100u);

    // Give any (incorrect) background trigger a chance to happen before asserting it didn't.
    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(server.scanRequestCount(), 0u);
    EXPECT_EQ(metrics.accepted->get(), 0u);
    EXPECT_EQ(metrics.versionMismatch->get(), 1u);
}

TEST(ScanVdHandlerTest, ZeroAgentIdIsRejectedAsInvalidAgent)
{
    const auto socketPath = makeUniqueVdSocketPath("invalidagent");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 0, 100);

    EXPECT_EQ(response.outcome, ScanVdOutcome::InvalidAgent);
    EXPECT_EQ(metrics.invalidAgent->get(), 1u);

    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(server.scanRequestCount(), 0u);
}

TEST(ScanVdHandlerTest, AcceptedRequestTriggersExactlyOneSuccessfulScan)
{
    const auto socketPath = makeUniqueVdSocketPath("happypath");
    FakeVdServer server(socketPath);
    server.setOffset(100);
    server.setScanHandler([](const httplib::Request&, httplib::Response& res)
                          { res.set_content("{}", "application/json"); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(metrics.accepted->get(), 1u);

    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceeded->get() == 1; }));
    EXPECT_EQ(server.scanRequestCount(), 1u);

    // Give it a further window to make sure success doesn't spuriously retry.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(server.scanRequestCount(), 1u);
    EXPECT_EQ(metrics.scanRetried->get(), 0u);
}

TEST(ScanVdHandlerTest, RetryableFailureIsRetriedAndEventuallySucceeds)
{
    const auto socketPath = makeUniqueVdSocketPath("retry");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    std::atomic<int> attempt {0};
    server.setScanHandler(
        [&attempt](const httplib::Request&, httplib::Response& res)
        {
            if (attempt.fetch_add(1) == 0)
            {
                res.status = 503;
                res.set_content(R"({"error":"scanner_not_ready","retryable":true})", "application/json");
            }
            else
            {
                res.set_content("{}", "application/json");
            }
        });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 8, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);

    // First backoff is 1s (see MAX_RETRIES/backoff in scanVdHandler.cpp), so this needs real time.
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceeded->get() == 1; }, 3s));
    EXPECT_EQ(metrics.scanRetried->get(), 1u);
    EXPECT_EQ(attempt.load(), 2);
}

TEST(ScanVdHandlerTest, PermanentFailureIsNotRetried)
{
    const auto socketPath = makeUniqueVdSocketPath("permanent");
    FakeVdServer server(socketPath);
    server.setOffset(100);
    server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 404;
            res.set_content(R"({"error":"agent_not_found","retryable":false})", "application/json");
        });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 9, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);

    ASSERT_TRUE(waitUntil([&] { return metrics.scanPermanentFailure->get() == 1; }));

    // Must not have retried: exactly one request, ever.
    std::this_thread::sleep_for(1200ms);
    EXPECT_EQ(server.scanRequestCount(), 1u);
    EXPECT_EQ(metrics.scanRetried->get(), 0u);
}

TEST(ScanVdHandlerTest, QueueFullRejectsWhenTrackingTableIsAtCapacity)
{
    const auto socketPath = makeUniqueVdSocketPath("queuefull");

    // Gated so agents 1 and 2 are provably still "tracked" (their attempt hasn't finished, so
    // their AgentScanState hasn't been erased yet) at the exact moment agent 3 is submitted --
    // not just "probably, if submission was fast enough." Declared before the server: pool
    // threads reference the gate, so it must outlive them.
    GatedScanHandler gate;
    FakeVdServer server(socketPath);
    server.setOffset(100);
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(
        std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath, /*maxTrackedAgents=*/2);
    GateReleaser releaser {gate};

    EXPECT_EQ(callSync(handler, 1, 100).outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(callSync(handler, 2, 100).outcome, ScanVdOutcome::Accepted);
    ASSERT_TRUE(gate.waitForWaiters(2, 2s)) << "both agents must be genuinely in flight before agent 3 is submitted";

    // Table is now at capacity (2/2); a third, different agent must be rejected.
    const auto response = callSync(handler, 3, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::QueueFull);
    EXPECT_EQ(metrics.queueFull->get(), 1u);

    // Once agents 1 and 2 finish, capacity frees up again.
    gate.release();
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceeded->get() == 2; }, 2s));
    EXPECT_EQ(callSync(handler, 3, 100).outcome, ScanVdOutcome::Accepted);
}

TEST(ScanVdHandlerTest, OffsetChangeDuringInFlightAttemptTriggersImmediateRescanWithNewOffset)
{
    const auto socketPath = makeUniqueVdSocketPath("inflightchange");

    // The gate gives an exact, wall-clock-independent signal for "the first attempt has actually
    // started and is in flight" -- no fixed sleep to guess at. Declared before the server so it
    // outlives the pool threads that reference it.
    GatedScanHandler gate;
    FakeVdServer server(socketPath);
    server.setOffset(100);
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);
    GateReleaser releaser {gate};

    ASSERT_EQ(callSync(handler, 42, 100).outcome, ScanVdOutcome::Accepted);

    // Wait until the worker is provably blocked inside the (in-flight) first attempt, then let
    // VdClient's cache expire before moving the feed forward.
    ASSERT_TRUE(gate.waitForWaiters(1, 2s));
    std::this_thread::sleep_for(VDCLIENT_TTL + 20ms);
    server.setOffset(200);
    ASSERT_EQ(callSync(handler, 42, 200).outcome, ScanVdOutcome::Accepted);

    // Now let the first (offset=100) attempt complete successfully. finishAttempt() must notice
    // the agent's pendingOffset moved on to 200 and re-queue immediately instead of treating this
    // as done -- so a second attempt (this time for offset=200) must follow automatically, and
    // since the gate is now open permanently, it sails straight through.
    gate.release();

    ASSERT_TRUE(waitUntil([&] { return gate.count("42") >= 2; }, 3s));
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceeded->get() == 1; }))
        << "the agent's final state must resolve as a single successful scan, not two independent "
           "successes or a discard";
}

TEST(ScanVdHandlerTest, StaleQueuedTaskIsDiscardedWhenOffsetChangesBeforeExecution)
{
    const auto socketPath = makeUniqueVdSocketPath("discard");

    // Just enough fillers to saturate every real worker thread (scanWorkerPoolSize() ==
    // cpp_get_nproc(), which can never exceed hardware_concurrency()) plus a small margin, so the
    // target agent is guaranteed to still be sitting untouched in the internal queue once all
    // workers are confirmed blocked -- by construction, not by racing a fixed sleep against
    // however long this test's (synchronous, network-round-trip-per-call) submission loop takes.
    const unsigned fillerCount = std::max(2U, std::thread::hardware_concurrency()) + 4U;
    GatedScanHandler gate;
    // The server pool must EXCEED the fillers: both endpoints share one httplib pool, and this
    // test parks up to workerCount scans in the gate. With the default pool (max(8, hw-1)) a
    // >=8-core machine ends up with every server thread parked, /offset unanswerable, and the
    // pre-warm assertion below failing on a stale cached offset.
    FakeVdServer server(socketPath, /*poolThreads=*/fillerCount + 4);
    server.setOffset(100);
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}),
                              metrics,
                              socketPath,
                              /*maxTrackedAgents=*/fillerCount + 10);
    GateReleaser releaser {gate};

    // Park the workers ONE AT A TIME: submit a filler, then wait until it is provably blocked in
    // the gate before submitting the next. Submitting them in a burst looks equivalent but is
    // not: every worker then connect()s to the fake server at once, httplib's listen backlog is
    // a compile-time 5, and on a UDS socket an over-backlog connect fails IMMEDIATELY with
    // EAGAIN -- which triggerVdScan correctly treats as a retryable failure, FREEING that worker
    // to dequeue further (a freed worker reaching agent 999 before the offset moves is exactly
    // the flake this ordering removes). Serialized, there is never more than one pending connect,
    // so every dequeued filler deterministically parks. Once the pool is exhausted (one bounded
    // wait times out), the remaining fillers -- at least 4, since fillerCount > workerCount by
    // construction -- just queue up, guaranteeing agent 999 sits behind queued work no worker is
    // free to reach.
    unsigned parked = 0;
    for (unsigned i = 1; i <= fillerCount; ++i)
    {
        ASSERT_EQ(callSync(handler, i, 100).outcome, ScanVdOutcome::Accepted);
        if (parked == i - 1 && gate.waitForWaiters(i, 2s))
        {
            parked = i;
        }
    }
    ASSERT_GE(parked, 2u) << "no worker pool to saturate -- the fixture can't exercise the queue";
    ASSERT_LT(parked, fillerCount) << "every filler got a worker: nothing is left queued to shield agent 999";
    ASSERT_EQ(callSync(handler, 999, 100).outcome, ScanVdOutcome::Accepted);

    // Move the feed forward. No new request is made for agent 999, so its pendingOffset stays at
    // 100 -- exactly the "feed updated, but this agent's request predates it" scenario. Every
    // filler still queued when this lands will *also* see the new offset and get discarded (not
    // just agent 999) -- that's expected, not a bug, so the assertion below can't require an
    // exact discard count of 1; it targets agent 999 specifically instead.
    std::this_thread::sleep_for(VDCLIENT_TTL + 20ms);
    server.setOffset(200);

    // Force VdClient's cache to be freshly (and singly) populated with the new offset *before*
    // releasing the gate. Without this, releasing unblocks up to workerCount() fillers at once,
    // and they all call vdClient.getOffset() at roughly the same moment right as the cache
    // expires -- only one becomes VdClient's single-flight "refresher" and gets the fresh value;
    // every other concurrent caller correctly (by VdClient's own contract, see vdClient_test.cpp)
    // gets the last-known-good *stale* value instead of blocking. That's fine for VdClient's own
    // contract, but it would make agent 999 flakily "get lucky" and see the old offset purely by
    // however the thread-scheduling race lands -- not what this test is trying to isolate.
    // Pre-warming the cache here, alone, ensures every subsequent getOffset() call during the
    // burst is a plain cache hit for the correct value, with no race at all.
    ASSERT_EQ(vdClient.getOffset(), 200u);
    gate.release();

    // Wait for every agent (fillers + target) to reach a terminal state, then check the one thing
    // that actually matters: agent 999 itself was never scanned.
    const size_t totalAgents = static_cast<size_t>(fillerCount) + 1;
    ASSERT_TRUE(
        waitUntil([&] { return metrics.scanSucceeded->get() + metrics.scanDiscarded->get() >= totalAgents; }, 5s));

    EXPECT_GE(metrics.scanDiscarded->get(), 1u) << "the offset-moved-on-while-queued mechanism must have fired";
    EXPECT_EQ(gate.count("999"), 0u) << "a stale-offset task must never actually reach VD's /scan endpoint";
}
