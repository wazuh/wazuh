/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/syncEndpoint.hpp"

#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"
#include "vd/agentInFlightRegistry.hpp"
#include "vd/vdScanLane.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::Method;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::SessionSpec;

namespace
{
    constexpr auto CLUSTER {"test-cluster"};

    /// Captures whatever the handler sends; also resolves a future so a DEFERRED response (sent by
    /// a pipeline worker) can be awaited.
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            ++sendCount;
            captured = response;
            if (!m_resolved)
            {
                m_resolved = true;
                m_promise.set_value(std::move(response));
            }
        }

        HttpResponse await()
        {
            auto future = m_promise.get_future();
            if (future.wait_for(std::chrono::seconds {10}) != std::future_status::ready)
            {
                ADD_FAILURE() << "no response arrived within the deadline";
                return HttpResponse {0, "", {}};
            }
            return future.get();
        }

        int sendCount {0};
        std::optional<HttpResponse> captured;

    private:
        std::promise<HttpResponse> m_promise;
        bool m_resolved {false};
    };

    std::shared_ptr<const HttpRequest> makeRequest(std::string body, const char* agentId = "1")
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = Method::Post;
        request->target = invsync::endpoints::sync::path();
        request->body = std::move(body);
        if (agentId != nullptr)
        {
            request->headers.emplace(invsync::endpoints::sync::agentIdHeader(), agentId);
        }
        return request;
    }

    /// Handler + a real (fake-backed) pipeline: what the facade wires, minus the socket.
    struct HandlerUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<FakeIndexerConnectorSync> admission {
            std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
        std::shared_ptr<invsync::vd::AgentInFlightRegistry> registry {
            std::make_shared<invsync::vd::AgentInFlightRegistry>()};
        std::shared_ptr<invsync::vd::IVdScanner> scanner {std::make_shared<invsync::test::FakeVdScanner>(events)};
        std::shared_ptr<invsync::sync::SyncPipeline> pipeline;
        std::shared_ptr<invsync::vd::VdScanLane> lane;
        invsync::http::RouteHandler handler;

        explicit HandlerUnderTest(invsync::sync::SyncPipelineConfig config = {},
                                  int retryAfter = 60,
                                  invsync::vd::VdScanLaneConfig laneConfig = {})
        {
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {admission};
            pipeline = std::make_shared<invsync::sync::SyncPipeline>(config, std::move(connectors), CLUSTER, registry);
            lane = std::make_shared<invsync::vd::VdScanLane>(
                laneConfig,
                scanner,
                std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
                    std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
                registry,
                CLUSTER);
            handler = invsync::endpoints::sync::makeHandler(invsync::endpoints::sync::Dependencies {
                pipeline, admission, invsync::common::ClusterIdentity {CLUSTER, false}, retryAfter, lane, scanner});
        }
    };

    std::string validDelta()
    {
        return invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    }
} // namespace

/**
 * The path and verb are a wire contract with remoted's downstream configuration (its statefulEndpoint
 * forwards here). Pinning them is what turns a silent drift into a failing test.
 */
TEST(SyncEndpointTest, PathAndMethodAreStable)
{
    EXPECT_EQ(Method::Post, invsync::endpoints::sync::method());
    EXPECT_STREQ("/stateful", invsync::endpoints::sync::path());
    EXPECT_STREQ("x-wazuh-agent-id", invsync::endpoints::sync::agentIdHeader());
}

TEST(SyncEndpointTest, AMissingAgentIdHeaderIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta(), nullptr), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

/**
 * The transport hands the handler whatever it parsed, and a null request means it parsed nothing.
 * The handler must answer rather than dereference it: this is the one input it cannot inspect at
 * all, so it is also the one where a missing guard is a crash instead of a wrong status.
 */
TEST(SyncEndpointTest, ANullRequestIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find("Empty request"));
}

TEST(SyncEndpointTest, AnEmptyBodyIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(""), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

TEST(SyncEndpointTest, GarbageIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest("not a flatbuffer"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find(R"("code":400)"));
}

TEST(SyncEndpointTest, AnIdentityMismatchIs403)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta(), "42"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(403, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find("identity mismatch"));
}

TEST(SyncEndpointTest, AVDSessionWhileTheFeedIsNotReadyGets503WithRetryAfter)
{
    HandlerUnderTest fixture {{}, 120};
    fixture.events->m_vdFeedReady.store(false);
    auto responder = std::make_shared<CapturingResponder>();

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}})), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find("vulnerability feed not ready"));

    bool hasRetryAfter {false};
    for (const auto& [name, value] : responder->captured->headers)
    {
        if (name == "Retry-After")
        {
            hasRetryAfter = true;
            EXPECT_EQ("120", value) << "the configured Retry-After must reach the wire";
        }
    }
    EXPECT_TRUE(hasRetryAfter);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "a rejected VD session must not touch the indexer";
}

TEST(SyncEndpointTest, AVDSessionWithTheFeedReadyRidesTheScanLane)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDSync;
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}})), responder);

    const auto response = responder->await();
    EXPECT_EQ(200, response.status);
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("scan", std::get<0>(ops[0])) << "D22: the scan must gate the indexing";
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
}

TEST(SyncEndpointTest, AVDSessionAgainstAFullLaneGets503ScanCapacity)
{
    invsync::vd::VdScanLaneConfig laneConfig;
    laneConfig.workers = 1;
    laneConfig.queueSlots = 1;
    HandlerUnderTest fixture {{}, 60, laneConfig};
    fixture.events->closeScanGate();

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;

    // One in the worker (parked at the scan gate), one filling the single slot, the third bounces.
    auto first = std::make_shared<CapturingResponder>();
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}})), first);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (fixture.events->m_scanEntered.load() < 1 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
    }
    ASSERT_EQ(1, fixture.events->m_scanEntered.load());

    SessionSpec second;
    second.option = invsync::test::fb::Option_VDFirst;
    second.agentId = "2";
    auto queued = std::make_shared<CapturingResponder>();
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(second, {invsync::test::ValueSpec {}}), "2"),
                    queued);

    SessionSpec third;
    third.option = invsync::test::fb::Option_VDFirst;
    third.agentId = "3";
    auto rejected = std::make_shared<CapturingResponder>();
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(third, {invsync::test::ValueSpec {}}), "3"),
                    rejected);

    ASSERT_TRUE(rejected->captured.has_value());
    EXPECT_EQ(503, rejected->captured->status);
    EXPECT_NE(std::string::npos, rejected->captured->body.find("scan capacity exhausted"));

    fixture.events->openScanGate();
    EXPECT_EQ(200, first->await().status);
    EXPECT_EQ(200, queued->await().status);
}

/**
 * Every dependency is held WEAKLY so the facade's stop() is genuinely destructive. Losing the
 * scanner or the lane means the module is going down, and the session must be shed with a 503 --
 * never processed against half-torn-down state, and never crashed on a null lock().
 */
TEST(SyncEndpointTest, AVDSessionAfterTheLaneAndScannerAreGoneIs503)
{
    HandlerUnderTest fixture;
    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDSync;
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});

    // The lane owns a strong reference to the scanner, so both have to go for the weak_ptrs to
    // expire -- which is exactly the order stop() tears them down in.
    fixture.lane->stop();
    fixture.lane.reset();
    fixture.scanner.reset();

    auto responder = std::make_shared<CapturingResponder>();
    fixture.handler(makeRequest(body), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
    EXPECT_TRUE(fixture.events->syncOps().empty());
}

/// A lane that is still alive but already stopping refuses admission; the handler owns that answer.
TEST(SyncEndpointTest, AVDSessionAgainstAStoppingLaneIs503)
{
    HandlerUnderTest fixture;
    fixture.lane->stop();

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;
    auto responder = std::make_shared<CapturingResponder>();
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}})), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
    EXPECT_EQ(1, responder->sendCount) << "a refused admission is answered exactly once, by the handler";
}

/**
 * The admission connector gone is stop() clearing it, which is a DIFFERENT condition from an
 * indexer outage even though both answer 503: this one is terminal, so nothing is queued behind it.
 */
TEST(SyncEndpointTest, ASessionAfterTheAdmissionConnectorIsGoneIs503)
{
    // A handler of its own: HandlerUnderTest's pipeline keeps a strong reference to the connector,
    // so the weak_ptr can only expire if this test owns the only other one.
    auto events = std::make_shared<ConnectorEvents>();
    auto registry = std::make_shared<invsync::vd::AgentInFlightRegistry>();
    auto scanner =
        std::static_pointer_cast<invsync::vd::IVdScanner>(std::make_shared<invsync::test::FakeVdScanner>(events));
    auto pipeline = std::make_shared<invsync::sync::SyncPipeline>(
        invsync::sync::SyncPipelineConfig {},
        std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
            std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
        CLUSTER,
        registry);
    auto lane = std::make_shared<invsync::vd::VdScanLane>(
        invsync::vd::VdScanLaneConfig {},
        scanner,
        std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
            std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
        registry,
        CLUSTER);

    std::shared_ptr<invsync::indexer::IIndexerConnectorSync> admission {
        std::make_shared<FakeIndexerConnectorSync>(events, "admission")};
    auto handler = invsync::endpoints::sync::makeHandler(invsync::endpoints::sync::Dependencies {
        pipeline, admission, invsync::common::ClusterIdentity {CLUSTER, false}, 60, lane, scanner});
    admission.reset(); // stop() clearing the connector

    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
    EXPECT_TRUE(events->syncOps().empty()) << "a terminal 503 queues nothing";
}

TEST(SyncEndpointTest, AnUnavailableIndexerShedsAtAdmission)
{
    HandlerUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AnExpiredPipelineIs503)
{
    // Simulates the facade's stop(): the weak_ptr no longer locks.
    invsync::endpoints::sync::Dependencies deps;
    auto events = std::make_shared<ConnectorEvents>();
    auto connector = std::make_shared<FakeIndexerConnectorSync>(events, "sync");
    deps.indexer = connector;
    deps.cluster = invsync::common::ClusterIdentity {CLUSTER, false};
    auto handler = invsync::endpoints::sync::makeHandler(deps); // pipeline weak_ptr left empty

    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AFullPipelineQueueIs503)
{
    invsync::sync::SyncPipelineConfig config;
    config.maxQueueBytes = 1;
    HandlerUnderTest fixture {config};
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AValidSessionIsDeferredAndAnsweredByTheWorkerExactlyOnce)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    // The strand's part ends WITHOUT a response; the worker delivers it.
    const auto response = responder->await();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);
    EXPECT_EQ(1, responder->sendCount);
    EXPECT_FALSE(fixture.events->syncOps().empty()) << "the session must have reached the connector";
}
