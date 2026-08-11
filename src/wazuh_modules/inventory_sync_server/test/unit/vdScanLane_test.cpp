/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vd/vdScanLane.hpp"

#include "sync/fullSessionValidator.hpp"
#include "sync/syncPipeline.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"
#include "vd/agentInFlightRegistry.hpp"
#include "vd/serverScanCoordinator.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <json.hpp>
#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::sync::SyncPipeline;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::FakeVdScanner;
using invsync::test::SessionSpec;
using invsync::test::ValueSpec;
using invsync::vd::AgentInFlightRegistry;
using invsync::vd::VdScanLane;
using invsync::vd::VdScanLaneConfig;

namespace
{
    constexpr auto CLUSTER {"test-cluster"};
    constexpr auto WAIT {std::chrono::seconds {10}};

    class FutureResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_sent.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
        }

        HttpResponse get()
        {
            auto future = m_promise.get_future();
            if (future.wait_for(WAIT) != std::future_status::ready)
            {
                ADD_FAILURE() << "no response arrived within the deadline";
                return HttpResponse {0, "", {}};
            }
            return future.get();
        }

        bool answered() const
        {
            return m_sent.load();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_sent {false};
    };

    SyncPipeline::Item makeItem(std::string body, std::shared_ptr<FutureResponder> responder, const char* agent = "1")
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = std::move(body);

        auto result = invsync::sync::validateFullSession(request->body, agent, CLUSTER);
        auto* session = std::get_if<invsync::sync::ValidatedSession>(&result);
        if (session == nullptr)
        {
            throw std::runtime_error {"test session failed validation"};
        }
        return SyncPipeline::Item {request, std::move(responder), std::move(*session)};
    }

    std::string vdDeltaBody(const char* docId = "doc-1",
                            invsync::test::fb::Option option = invsync::test::fb::Option_VDFirst,
                            const char* agentId = "1",
                            std::uint64_t feedOffset = 0)
    {
        SessionSpec spec;
        spec.option = option;
        spec.agentId = agentId;
        spec.feedOffset = feedOffset;
        ValueSpec value;
        value.id = docId;
        return invsync::test::buildSyncDataSession(spec, {value});
    }

    bool waitFor(const std::function<bool()>& condition)
    {
        const auto deadline = std::chrono::steady_clock::now() + WAIT;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (condition())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {5});
        }
        return false;
    }

    struct LaneUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<AgentInFlightRegistry> registry {std::make_shared<AgentInFlightRegistry>()};
        std::shared_ptr<VdScanLane> lane;

        explicit LaneUnderTest(VdScanLaneConfig config = {})
        {
            lane = std::make_shared<VdScanLane>(config,
                                                std::make_shared<FakeVdScanner>(events),
                                                std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
                                                    std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
                                                registry,
                                                CLUSTER);
        }

        ~LaneUnderTest()
        {
            // A test that failed an ASSERT may leave a worker parked at a closed gate; the lane's
            // stop() would then join forever. Opening the gates first makes teardown unconditional.
            events->openScanGate();
            events->openFlushGate();
        }
    };
} // namespace

/**
 * THE D22 contract in one test: the scan runs FIRST, and only its success lets the inventory
 * reach the indexer -- in that order, then the 200.
 */
TEST(VdScanLaneTest, ScanOkIndexesAndAnswers200InThatOrder)
{
    LaneUnderTest fixture;
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted, fixture.lane->tryEnqueue(makeItem(vdDeltaBody(), responder)));

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("scan", std::get<0>(ops[0])) << "the scan gates the indexing, so it must come first";
    EXPECT_EQ("001", std::get<1>(ops[0]));
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "the 200 must mean flushed";
}

TEST(VdScanLaneTest, AFailedScanAnswers500WithZeroDocumentsIndexed)
{
    LaneUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "scan";
    }
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted, fixture.lane->tryEnqueue(makeItem(vdDeltaBody(), responder)));

    const auto response = responder->get();
    EXPECT_EQ(500, response.status);
    EXPECT_NE(std::string::npos, response.body.find("vulnerability scan failed"));
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "the gating of D22: a failed scan indexes NOTHING";
    EXPECT_EQ(0, fixture.events->m_syncFlushes.load());
}

TEST(VdScanLaneTest, ALegitimateSkipStillIndexesAndAnswers200)
{
    LaneUnderTest fixture;
    fixture.events->m_vdScanSkip.store(true);
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted, fixture.lane->tryEnqueue(makeItem(vdDeltaBody(), responder)));

    EXPECT_EQ(200, responder->get().status);
    const auto ops = fixture.events->syncOps();
    // The feed-update fleet scan reads packages FROM THE INDEXER, so a skipped session must still
    // deliver its inventory.
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("scan", std::get<0>(ops[0]));
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
}

TEST(VdScanLaneTest, AFullQueueRefusesAtAdmission)
{
    VdScanLaneConfig config;
    config.workers = 1;
    config.queueSlots = 1;
    LaneUnderTest fixture {config};
    fixture.events->closeScanGate();

    // First session occupies the worker (parked inside its scan); second fills the single slot;
    // the third must bounce.
    auto first = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1"), first)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    auto second = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-2", invsync::test::fb::Option_VDFirst, "2"), second, "2")));

    auto third = std::make_shared<FutureResponder>();
    EXPECT_EQ(
        VdScanLane::Admission::Full,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-3", invsync::test::fb::Option_VDFirst, "3"), third, "3")));
    EXPECT_FALSE(third->answered()) << "the caller answers a refused admission, not the lane";

    fixture.events->openScanGate();
    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(200, second->get().status);
}

TEST(VdScanLaneTest, FeedTurningUnreadyBetweenAdmissionAndDispatchAnswers503WithRetryAfter)
{
    VdScanLaneConfig config;
    config.retryAfterSeconds = 99;
    LaneUnderTest fixture {config};
    fixture.events->closeScanGate(); // hold the worker so we can flip the feed under a QUEUED item

    auto first = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1"), first)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    auto queued = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-2", invsync::test::fb::Option_VDFirst, "2"), queued, "2")));

    fixture.events->m_vdFeedReady.store(false);
    fixture.events->openScanGate();

    EXPECT_EQ(200, first->get().status);
    const auto response = queued->get();
    EXPECT_EQ(503, response.status);
    bool hasRetryAfter {false};
    for (const auto& [name, value] : response.headers)
    {
        if (name == "Retry-After")
        {
            hasRetryAfter = true;
            EXPECT_EQ("99", value);
        }
    }
    EXPECT_TRUE(hasRetryAfter) << "the D17 re-check at dispatch must carry the Retry-After too";
    // Only doc-1 was scanned+indexed; doc-2 was rejected without processing.
    EXPECT_EQ(1, fixture.events->m_syncFlushes.load());
}

TEST(VdScanLaneTest, TheRegistrySerializesTwoSessionsOfTheSameAgent)
{
    VdScanLaneConfig config;
    config.workers = 2; // two workers, but the same agent must never scan twice concurrently
    config.queueSlots = 8;
    LaneUnderTest fixture {config};
    fixture.events->closeScanGate();

    auto first = std::make_shared<FutureResponder>();
    auto second = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1"), first)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-2", invsync::test::fb::Option_VDFirst, "1"), second)));

    // Give the second worker every chance to (wrongly) dispatch the same agent.
    std::this_thread::sleep_for(std::chrono::milliseconds {100});
    EXPECT_EQ(1, fixture.events->m_scanEntered.load())
        << "the second session of agent 001 must wait for the first scan (legacy dedup, done right)";

    fixture.events->openScanGate();
    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(200, second->get().status);
    EXPECT_EQ(2, fixture.events->m_scanEntered.load());
}

TEST(VdScanLaneTest, ThePipelineParksItemsOfAnAgentWhoseScanIsInFlight)
{
    LaneUnderTest fixture;
    fixture.events->closeScanGate();

    // Same registry on both lanes: this is the cross-lane exclusion of D22.
    invsync::sync::SyncPipelineConfig pipelineConfig;
    auto pipeline = std::make_shared<invsync::sync::SyncPipeline>(
        pipelineConfig,
        std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
            std::make_shared<FakeIndexerConnectorSync>(fixture.events, "sync")},
        CLUSTER,
        fixture.registry);

    // Park agent 001 inside its scan…
    auto scanResponder = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(
                  makeItem(vdDeltaBody("doc-vd", invsync::test::fb::Option_VDFirst, "1"), scanResponder)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    // …then feed the pipeline one item of the SAME agent and one of another.
    auto blocked = std::make_shared<FutureResponder>();
    SessionSpec sameAgent;
    ValueSpec blockedValue;
    blockedValue.id = "doc-after-scan";
    ASSERT_TRUE(pipeline->enqueue(makeItem(invsync::test::buildSyncDataSession(sameAgent, {blockedValue}), blocked)));

    auto other = std::make_shared<FutureResponder>();
    SessionSpec otherAgent;
    otherAgent.agentId = "2";
    ValueSpec otherValue;
    otherValue.id = "doc-other";
    ASSERT_TRUE(pipeline->enqueue(makeItem(invsync::test::buildSyncDataSession(otherAgent, {otherValue}), other, "2")));

    // The OTHER agent flows while agent 001 is fenced; 001's item stays parked.
    EXPECT_EQ(200, other->get().status);
    std::this_thread::sleep_for(std::chrono::milliseconds {50});
    EXPECT_FALSE(blocked->answered()) << "an agent mid-scan must not have pipeline items applied";

    // Scan finishes -> the release wakes the shard -> the parked item flows.
    fixture.events->openScanGate();
    EXPECT_EQ(200, scanResponder->get().status);
    EXPECT_EQ(200, blocked->get().status);

    // Ordering on the shared timeline: the parked delta's bulkIndex must come AFTER the scan.
    const auto ops = fixture.events->syncOps();
    std::size_t scanAt {ops.size()};
    std::size_t blockedAt {ops.size()};
    for (std::size_t i = 0; i < ops.size(); ++i)
    {
        if (std::get<0>(ops[i]) == "scan")
        {
            scanAt = i;
        }
        if (std::get<1>(ops[i]) == "test-cluster_001_doc-after-scan")
        {
            blockedAt = i;
        }
    }
    ASSERT_LT(scanAt, ops.size());
    ASSERT_LT(blockedAt, ops.size());
    EXPECT_LT(scanAt, blockedAt);

    pipeline->stop();
}

TEST(VdScanLaneTest, AnAgentMidScanCannotBeQuiescedInstantlyButPauseSucceedsOnceItFinishes)
{
    LaneUnderTest fixture;
    fixture.events->closeScanGate();

    invsync::vd::ServerScanCoordinator coordinator {fixture.registry, std::chrono::seconds {0}};

    auto vdFirst = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1"), vdFirst)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    EXPECT_FALSE(coordinator.pauseAgent("001", "test")) << "an agent mid-scan cannot be quiesced instantly";

    fixture.events->openScanGate();
    EXPECT_EQ(200, vdFirst->get().status);

    EXPECT_TRUE(coordinator.pauseAgent("001", "test"));
    EXPECT_FALSE(fixture.registry->isFree("001")) << "a paused agent must not dispatch";
    coordinator.resumeAgent("001");
    EXPECT_TRUE(fixture.registry->isFree("001"));
}

/**
 * The scan succeeded, the INDEXING did not. That is not a scan failure and must not be reported as
 * one: the outcome depends on whether the connector still considers itself usable, because the two
 * answers mean different things to the agent. A reachable indexer failing one bulk is OUR problem
 * (500); an unreachable one is a transient outage the agent should back off from (503).
 *
 * Either way the lane must flush whatever it had staged before answering -- the re-POST re-stages
 * the whole session, so leftover partial staging would be indexed twice.
 */
TEST(VdScanLaneTest, IndexingFailingAfterAGoodScanAnswers500WhileTheIndexerLooksHealthy)
{
    LaneUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "bulkIndex";
    }
    fixture.events->m_syncAvailable.store(true);
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted, fixture.lane->tryEnqueue(makeItem(vdDeltaBody(), responder)));

    const auto response = responder->get();
    EXPECT_EQ(500, response.status);
    EXPECT_NE(std::string::npos, response.body.find("Internal error"));

    const auto ops = fixture.events->syncOps();
    ASSERT_FALSE(ops.empty());
    EXPECT_EQ("scan", std::get<0>(ops[0])) << "the scan ran and passed; only the indexing broke";
    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "partial staging is drained before answering";

    EXPECT_TRUE(waitFor([&] { return fixture.registry->isFree("001"); }))
        << "a failed session must still release the agent, or it is fenced forever";
}

TEST(VdScanLaneTest, IndexingFailingWithAnUnavailableIndexerAnswers503)
{
    LaneUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "bulkIndex";
    }
    fixture.events->m_syncAvailable.store(false);
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted, fixture.lane->tryEnqueue(makeItem(vdDeltaBody(), responder)));

    const auto response = responder->get();
    EXPECT_EQ(503, response.status);
    EXPECT_NE(std::string::npos, response.body.find("Service unavailable"));
}

TEST(VdScanLaneTest, StopAnswers503ToQueuedSessions)
{
    LaneUnderTest fixture;
    fixture.events->closeScanGate();

    auto inFlight = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1"), inFlight)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    auto queued = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-2", invsync::test::fb::Option_VDFirst, "2"), queued, "2")));

    std::thread opener {[&fixture]
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds {50});
                            fixture.events->openScanGate();
                        }};
    fixture.lane->stop();
    opener.join();

    EXPECT_EQ(200, inFlight->get().status) << "the in-flight scan completes (no cancellation point)";
    EXPECT_EQ(503, queued->get().status);

    auto late = std::make_shared<FutureResponder>();
    EXPECT_EQ(
        VdScanLane::Admission::Stopping,
        fixture.lane->tryEnqueue(makeItem(vdDeltaBody("doc-3", invsync::test::fb::Option_VDFirst, "3"), late, "3")));
}

/**
 * The offset gate (mirrors /scan/vd's REST version check, see vdScanLane.cpp's comment right
 * above the check): a VDFirst/VDSync session built against a feed offset this node doesn't
 * currently have must be rejected with 409 before ever reaching the scanner, so the agent retries
 * once offsets align instead of scanning against a node whose feed doesn't match what the agent
 * synced its session against.
 */
TEST(VdScanLaneTest, VdSessionWithMatchingFeedOffsetProceedsToScan)
{
    LaneUnderTest fixture;
    fixture.events->m_vdCurrentOffset.store(100);
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(
                  vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1", /*feedOffset=*/100), responder)));

    EXPECT_EQ(200, responder->get().status);
    const auto ops = fixture.events->syncOps();
    ASSERT_FALSE(ops.empty());
    EXPECT_EQ("scan", std::get<0>(ops[0])) << "a matching offset must let the session reach the scanner";
}

TEST(VdScanLaneTest, VdSessionWithMismatchedFeedOffsetIsRejectedWith409BeforeScanning)
{
    LaneUnderTest fixture;
    fixture.events->m_vdCurrentOffset.store(100);
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(
                  vdDeltaBody("doc-1", invsync::test::fb::Option_VDFirst, "1", /*feedOffset=*/50), responder)));

    const auto response = responder->get();
    EXPECT_EQ(409, response.status);
    const auto body = nlohmann::json::parse(response.body);
    EXPECT_EQ("version_mismatch", body.at("error").get<std::string>());
    EXPECT_EQ(100u, body.at("current_version").get<std::uint64_t>());

    EXPECT_TRUE(fixture.events->syncOps().empty())
        << "a stale-offset VD session must never reach the scanner or the indexer";
    EXPECT_EQ(0, fixture.events->m_syncFlushes.load());

    EXPECT_TRUE(waitFor([&] { return fixture.registry->isFree("001"); }))
        << "a rejected session must still release the agent, or it is fenced forever";
}

TEST(VdScanLaneTest, NonVdSessionIgnoresFeedOffsetMismatch)
{
    LaneUnderTest fixture;
    fixture.events->m_vdCurrentOffset.store(100);
    auto responder = std::make_shared<FutureResponder>();

    // option=Sync -> isVD is false (fullSessionValidator.cpp), so feedOffset (here, deliberately
    // way off from currentFeedOffset) must be irrelevant: this is a plain syscollector delta, not
    // a VD session, and must proceed exactly as any other non-VD item would.
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(
                  vdDeltaBody("doc-1", invsync::test::fb::Option_Sync, "1", /*feedOffset=*/999999), responder)));

    EXPECT_EQ(200, responder->get().status);
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("scan", std::get<0>(ops[0]));
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
}
