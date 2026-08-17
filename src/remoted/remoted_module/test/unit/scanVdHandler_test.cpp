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
                m_cv.wait(lock, [this] { return m_released; });
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
} // namespace

TEST(ScanVdHandlerTest, VersionMismatchRejectsWithoutEverTriggeringAScan)
{
    const auto socketPath = makeUniqueVdSocketPath("mismatch");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 1, 50 /* stale offset */);

    EXPECT_EQ(response.outcome, ScanVdOutcome::VersionMismatch);
    EXPECT_EQ(response.currentOffset, 100u);

    // Give any (incorrect) background trigger a chance to happen before asserting it didn't.
    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(server.scanRequestCount(), 0u);
    EXPECT_EQ(metrics.acceptedCount.load(), 0u);
    EXPECT_EQ(metrics.versionMismatchCount.load(), 1u);
}

TEST(ScanVdHandlerTest, ZeroAgentIdIsRejectedAsInvalidAgent)
{
    const auto socketPath = makeUniqueVdSocketPath("invalidagent");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 0, 100);

    EXPECT_EQ(response.outcome, ScanVdOutcome::InvalidAgent);
    EXPECT_EQ(metrics.invalidAgentCount.load(), 1u);

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
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(metrics.acceptedCount.load(), 1u);

    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceededCount.load() == 1; }));
    EXPECT_EQ(server.scanRequestCount(), 1u);

    // Give it a further window to make sure success doesn't spuriously retry.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(server.scanRequestCount(), 1u);
    EXPECT_EQ(metrics.scanRetriedCount.load(), 0u);
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
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 8, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);

    // First backoff is 1s (see MAX_RETRIES/backoff in scanVdHandler.cpp), so this needs real time.
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceededCount.load() == 1; }, 3s));
    EXPECT_EQ(metrics.scanRetriedCount.load(), 1u);
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
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

    const auto response = callSync(handler, 9, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);

    ASSERT_TRUE(waitUntil([&] { return metrics.scanPermanentFailureCount.load() == 1; }));

    // Must not have retried: exactly one request, ever.
    std::this_thread::sleep_for(1200ms);
    EXPECT_EQ(server.scanRequestCount(), 1u);
    EXPECT_EQ(metrics.scanRetriedCount.load(), 0u);
}

TEST(ScanVdHandlerTest, QueueFullRejectsWhenTrackingTableIsAtCapacity)
{
    const auto socketPath = makeUniqueVdSocketPath("queuefull");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    // Gated so agents 1 and 2 are provably still "tracked" (their attempt hasn't finished, so
    // their AgentScanState hasn't been erased yet) at the exact moment agent 3 is submitted --
    // not just "probably, if submission was fast enough."
    GatedScanHandler gate;
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(
        std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath, /*maxTrackedAgents=*/2);

    EXPECT_EQ(callSync(handler, 1, 100).outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(callSync(handler, 2, 100).outcome, ScanVdOutcome::Accepted);
    ASSERT_TRUE(gate.waitForWaiters(2, 2s)) << "both agents must be genuinely in flight before agent 3 is submitted";

    // Table is now at capacity (2/2); a third, different agent must be rejected.
    const auto response = callSync(handler, 3, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::QueueFull);
    EXPECT_EQ(metrics.queueFullCount.load(), 1u);

    // Once agents 1 and 2 finish, capacity frees up again.
    gate.release();
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceededCount.load() == 2; }, 2s));
    EXPECT_EQ(callSync(handler, 3, 100).outcome, ScanVdOutcome::Accepted);
}

TEST(ScanVdHandlerTest, OffsetChangeDuringInFlightAttemptTriggersImmediateRescanWithNewOffset)
{
    const auto socketPath = makeUniqueVdSocketPath("inflightchange");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    // The gate gives an exact, wall-clock-independent signal for "the first attempt has actually
    // started and is in flight" -- no fixed sleep to guess at.
    GatedScanHandler gate;
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}), metrics, socketPath);

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
    ASSERT_TRUE(waitUntil([&] { return metrics.scanSucceededCount.load() == 1; }))
        << "the agent's final state must resolve as a single successful scan, not two independent "
           "successes or a discard";
}

TEST(ScanVdHandlerTest, StaleQueuedTaskIsDiscardedWhenOffsetChangesBeforeExecution)
{
    const auto socketPath = makeUniqueVdSocketPath("discard");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    // Just enough fillers to saturate every real worker thread (scanWorkerPoolSize() ==
    // cpp_get_nproc(), which can never exceed hardware_concurrency()) plus a small margin, so the
    // target agent is guaranteed to still be sitting untouched in the internal queue once all
    // workers are confirmed blocked -- by construction, not by racing a fixed sleep against
    // however long this test's (synchronous, network-round-trip-per-call) submission loop takes.
    const unsigned fillerCount = std::max(2U, std::thread::hardware_concurrency()) + 4U;
    GatedScanHandler gate;
    server.setScanHandler([&gate](const httplib::Request& req, httplib::Response& res) { gate(req, res); });

    VdClient vdClient(socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY);
    ScanVdMetrics metrics;
    ScanVdHandlerImpl handler(std::shared_ptr<VdClient>(&vdClient, [](auto*) {}),
                              metrics,
                              socketPath,
                              /*maxTrackedAgents=*/fillerCount + 10);

    for (unsigned i = 1; i <= fillerCount; ++i)
    {
        ASSERT_EQ(callSync(handler, i, 100).outcome, ScanVdOutcome::Accepted);
    }

    // The target agent is queued behind all fillers. Confirm every worker is genuinely occupied
    // (blocked in the gate) before proceeding -- at that point agent 999 cannot possibly have
    // been dequeued yet, since there are more fillers than workers.
    ASSERT_TRUE(gate.waitForWaiters(1, 2s)) << "no worker ever reached the scan handler at all";
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
    ASSERT_TRUE(waitUntil(
        [&] { return metrics.scanSucceededCount.load() + metrics.scanDiscardedCount.load() >= totalAgents; }, 5s));

    EXPECT_GE(metrics.scanDiscardedCount.load(), 1u) << "the offset-moved-on-while-queued mechanism must have fired";
    EXPECT_EQ(gate.count("999"), 0u) << "a stale-offset task must never actually reach VD's /scan endpoint";
}
