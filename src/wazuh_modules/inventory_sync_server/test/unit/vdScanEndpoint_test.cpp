/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the POST /_internal/vd/scan route policy: body validation, the admission outcomes the
// lane can report, and the deferred answer -- with a REAL VdScanLane over the fake scanner, so what
// runs here is what runs in production.
//
// The route answers AT COMPLETION: the 200 means the scan RAN, which is what lets the Task Manager
// record the task as `completed` and have that mean scanned rather than accepted.
#include "endpoints/vdScanEndpoint.hpp"

#include "testIndexerConnectorFakes.hpp"
#include "vd/agentInFlightRegistry.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::FakeVdScanner;
using invsync::vd::AgentInFlightRegistry;
using invsync::vd::VdScanLane;
using invsync::vd::VdScanLaneConfig;
using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
namespace vd_scan = invsync::endpoints::vd_scan;

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

        /// Only meaningful next to a fact that pins WHERE the work is; on its own it is a race.
        bool answered() const
        {
            return m_sent.load();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_sent {false};
    };

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

    /// A real lane over the fake scanner, plus the handler wired exactly like the facade wires it.
    struct EndpointUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<AgentInFlightRegistry> registry {std::make_shared<AgentInFlightRegistry>()};
        std::shared_ptr<VdScanLane> lane;
        wazuh::uds_http::RouteHandler handler;

        explicit EndpointUnderTest(VdScanLaneConfig config = {})
        {
            lane = std::make_shared<VdScanLane>(config,
                                                std::make_shared<FakeVdScanner>(events),
                                                std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
                                                    std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
                                                registry,
                                                CLUSTER);
            handler = vd_scan::makeHandler(vd_scan::Dependencies {lane});
        }

        ~EndpointUnderTest()
        {
            // A test that failed an ASSERT may leave a worker parked at a closed gate; the lane's
            // stop() would then join forever. Opening the gates first makes teardown unconditional.
            events->openScanGate();
            events->openFlushGate();
        }
    };

    /// What the dispatcher sends: a task row's PAYLOAD as the body, and no headers at all.
    std::shared_ptr<HttpRequest> scanRequest(const std::string& body)
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = body;
        return request;
    }
} // namespace

TEST(VdScanEndpoint, TheRouteIsPinned)
{
    // Its caller is the Task Manager's dispatcher, whose descriptor carries this method and path as
    // data. A silent rename here would dead-letter every scan.
    EXPECT_EQ(vd_scan::method(), wazuh::uds_http::Method::Post);
    EXPECT_STREQ(vd_scan::path(), "/_internal/vd/scan");

    // Above manager_task_vd_scan_timeout (300 s), which is also the transport's server-wide value.
    // Leaving them equal makes which one fires a coin flip, and half the time a scan that SUCCEEDED
    // comes back to the dispatcher as a synthesized 504.
    EXPECT_GT(vd_scan::responseTimeoutSeconds(), 300U);
}

TEST(VdScanEndpoint, TheScanRunsForTheAgentNamedInTheBody)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), responder);

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("scanAgent", std::get<0>(ops[0]));
    // Padded, like every registry key: the per-agent exclusion between this lane and the pipeline
    // only works if both spell the agent the same way.
    EXPECT_EQ("007", std::get<1>(ops[0]));
}

TEST(VdScanEndpoint, TheNumberSpellingOfAnAgentIdIsAccepted)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":7})"), responder);
    ASSERT_EQ(200, responder->get().status);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", std::get<1>(ops[0])) << "the same agent, written the other way";
}

TEST(VdScanEndpoint, ABodyThatNamesNoAgentIs400)
{
    EndpointUnderTest fixture;

    const std::vector<std::string> bodies {
        "",                        // the dispatcher sent an empty payload
        "not json",                // malformed: discarded, and a discarded value is not an object
        "[]",                      // valid JSON, wrong shape
        R"({})",                   // no member
        R"({"agent_id":null})",    // present and useless
        R"({"agent_id":"12x"})",   // not an id
        R"({"agent_id":"-1"})",    // nor is this
        R"({"agent_id":{"id":7}})" // nor this
    };

    for (const auto& body : bodies)
    {
        auto responder = std::make_shared<FutureResponder>();
        fixture.handler(scanRequest(body), responder);
        EXPECT_EQ(400, responder->get().status) << "body='" << body << "'";
    }

    EXPECT_TRUE(fixture.events->syncOps().empty()) << "nothing may reach the scanner on a 400";
}

/// The body is the ONLY channel. The dispatcher POSTs a row's payload and sets no headers, so
/// honouring one here would hide a producer that forgot to write the id into the payload.
TEST(VdScanEndpoint, TheAgentIdHeaderIsIgnored)
{
    EndpointUnderTest fixture;

    auto request = scanRequest(R"({})");
    request->headers.emplace("x-wazuh-agent-id", "7");

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(request, responder);
    EXPECT_EQ(400, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty());
}

/**
 * THE interlock (§7.2), from the endpoint's side. A client-side timeout does not cancel
 * server-side work: the dispatcher gives up at its own deadline and re-posts while the first scan
 * is still running.
 *
 * 409 and not 503, because the dispatcher tells them apart: a 409 defers WITHOUT consuming an
 * attempt, which is right -- being busy is not a failure, and a scan that kept burning attempts
 * against its own still-running predecessor would dead-letter for no reason.
 */
TEST(VdScanEndpoint, ASecondScanOfTheSameAgentIs409WhileTheFirstRuns)
{
    EndpointUnderTest fixture;
    fixture.events->closeScanGate();

    auto first = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), first);

    // Not a race: the worker is demonstrably parked inside the scan, so it holds agent 007.
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));
    EXPECT_FALSE(first->answered()) << "a 200 here would record a scan that has not happened";

    auto second = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), second);

    const auto refusal = second->get();
    EXPECT_EQ(409, refusal.status);
    EXPECT_NE(std::string::npos, refusal.body.find("scan_in_progress")) << refusal.body;

    fixture.events->openScanGate();
    EXPECT_EQ(200, first->get().status);

    // One scan, not two. The second would have been invisible to the pipeline's own per-agent
    // ordering and could have run while that agent's session was mid-apply.
    EXPECT_EQ(1U, fixture.events->syncOps().size());
}

/// A DIFFERENT agent is not blocked by the first: the interlock is per agent, not a global lock.
TEST(VdScanEndpoint, AnotherAgentIsAdmittedWhileOneIsScanning)
{
    VdScanLaneConfig config;
    config.queueSlots = 4;
    EndpointUnderTest fixture {config};
    fixture.events->closeScanGate();

    auto first = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), first);
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    auto other = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"8"})"), other);
    EXPECT_FALSE(other->answered()) << "admitted and queued, not refused";

    fixture.events->openScanGate();
    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(200, other->get().status);
}

TEST(VdScanEndpoint, AFullLaneQueueIs503)
{
    // One connector means one worker, whatever `workers` says -- the lane sizes its pool from the
    // connector vector. One queue slot on top of it is what makes the third request bounce.
    VdScanLaneConfig config;
    config.queueSlots = 1;
    EndpointUnderTest fixture {config};
    fixture.events->closeScanGate();

    // One agent occupies the worker; a second fills the single slot; the third has nowhere to go.
    auto occupying = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), occupying);
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    auto queued = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"8"})"), queued);
    EXPECT_FALSE(queued->answered());

    auto refused = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"9"})"), refused);
    EXPECT_EQ(503, refused->get().status) << "the lane's bounded queue IS this route's capacity control";

    fixture.events->openScanGate();
    EXPECT_EQ(200, occupying->get().status);
    EXPECT_EQ(200, queued->get().status);
}

TEST(VdScanEndpoint, AnExpiredLaneIs503)
{
    EndpointUnderTest fixture;
    auto handler = vd_scan::makeHandler(vd_scan::Dependencies {std::weak_ptr<VdScanLane> {}});

    auto responder = std::make_shared<FutureResponder>();
    handler(scanRequest(R"({"agent_id":"7"})"), responder);
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty());
}

TEST(VdScanEndpoint, AStoppedLaneIs503)
{
    EndpointUnderTest fixture;
    fixture.lane->stop();

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(scanRequest(R"({"agent_id":"7"})"), responder);
    EXPECT_EQ(503, responder->get().status);
}

/// The counting rule: this handler counts only what IT sends. The fixture's lane carries no metrics
/// manager (null-object), so a count landing in OUR family could only have come from the endpoint.
TEST(VdScanEndpoint, TheRouteCountsOnlyTheResponsesItSendsItself)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    const auto counters = invsync::metrics::RequestCounters::make(*metrics);

    EndpointUnderTest fixture;
    auto handler = vd_scan::makeHandler(vd_scan::Dependencies {fixture.lane, counters});

    {
        auto responder = std::make_shared<FutureResponder>();
        handler(scanRequest(R"({})"), responder);
        EXPECT_EQ(400, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c400->get());

    {
        auto responder = std::make_shared<FutureResponder>();
        handler(scanRequest(R"({"agent_id":"7"})"), responder);
        EXPECT_EQ(200, responder->get().status);
    }

    // Zero, not one: the 200 was sent by the lane, which counts it into ITS manager. A count here
    // would mean the same request counted twice.
    EXPECT_EQ(0U, counters.c200->get());
    EXPECT_EQ(1U, counters.c400->get());
}
