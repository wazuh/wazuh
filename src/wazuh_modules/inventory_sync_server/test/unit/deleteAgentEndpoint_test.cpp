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

// Unit-tests the DELETE /agents route policy (design doc 04): header validation, the admission
// availability gate, and the deferred execution on the target agent's pipeline shard -- with a
// REAL SyncPipeline over the fake connector, so what runs here is what runs in production.
//
// The route answers AT ADMISSION: "200" means the deletion was queued and WILL be purged, not that
// the delete-by-query already flushed. These tests pin both halves of that contract -- the caller
// is released immediately, and the purge still happens afterwards.
#include "endpoints/deleteAgentEndpoint.hpp"

#include "sync/syncPipeline.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using invsync::sync::SyncPipeline;
using invsync::sync::SyncPipelineConfig;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
namespace delete_agent = invsync::endpoints::delete_agent;

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

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_sent {false};
    };

    /// A real single-worker pipeline over the shared fake-connector event log, plus the handler
    /// wired exactly like the facade wires it.
    ///
    /// The ASYNC connector is here because the deletion has a half that belongs to it: the
    /// AGENT_DELETION_SCOPE_BY_ID documents (`wazuh-agent-config`, `wazuh-agent-stats`) are written
    /// by POST /config and POST /stats through that connector's accumulating queue, so their deletes
    /// are queued there -- the only way to order them after a report the queue has accepted but not
    /// yet pushed. Both fakes share one event log, so a test can read the two halves from one
    /// fixture.
    struct EndpointUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<FakeIndexerConnectorSync> admissionConnector;
        std::shared_ptr<invsync::test::FakeIndexerConnectorAsync> asyncConnector;
        std::shared_ptr<SyncPipeline> pipeline;
        wazuh::uds_http::RouteHandler handler;

        EndpointUnderTest()
        {
            admissionConnector = std::make_shared<FakeIndexerConnectorSync>(events, "sync");
            asyncConnector = std::make_shared<invsync::test::FakeIndexerConnectorAsync>(events, "async");
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
                std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
            pipeline = std::make_shared<SyncPipeline>(SyncPipelineConfig {}, std::move(connectors), CLUSTER);
            handler =
                delete_agent::makeHandler(delete_agent::Dependencies {pipeline, admissionConnector, asyncConnector});
        }
    };

    /// The response no longer waits for the purge, so the purge has to be waited for explicitly.
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

    std::shared_ptr<HttpRequest> deleteRequest(const std::string& agentId)
    {
        auto request = std::make_shared<HttpRequest>();
        if (!agentId.empty())
        {
            request->headers.emplace("x-wazuh-agent-id", agentId);
        }
        return request;
    }
} // namespace

TEST(DeleteAgentEndpoint, RoutesArePinned)
{
    // remoted never exposes these (D15); authd targets the POST alias because uhttp_* only POSTs.
    // Pinned so a silent rename cannot break that C caller.
    EXPECT_EQ(delete_agent::method(), wazuh::uds_http::Method::Delete);
    EXPECT_STREQ(delete_agent::path(), "/agents");
    EXPECT_EQ(delete_agent::altMethod(), wazuh::uds_http::Method::Post);
    EXPECT_STREQ(delete_agent::altPath(), "/agents/delete");
}

TEST(DeleteAgentEndpoint, MissingOrNonNumericAgentIdHeaderIs400)
{
    EndpointUnderTest fixture;

    for (const auto& agentId : std::vector<std::string> {"", "12x", "-1", "agent-one"})
    {
        auto responder = std::make_shared<FutureResponder>();
        fixture.handler(deleteRequest(agentId), responder);
        const auto response = responder->get();
        EXPECT_EQ(400, response.status) << "agentId='" << agentId << "'";
    }

    EXPECT_TRUE(fixture.events->syncOps().empty()) << "nothing may reach the connector on a 400";
    EXPECT_TRUE(fixture.events->asyncOps().empty()) << "and nothing may be queued on the async half either";
}

TEST(DeleteAgentEndpoint, UnavailableIndexerIs503AtAdmission)
{
    EndpointUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);

    EXPECT_EQ(503, responder->get().status) << "the caller must retry instead of losing the delete";
    EXPECT_TRUE(fixture.events->syncOps().empty());
    EXPECT_TRUE(fixture.events->asyncOps().empty()) << "a refused deletion must queue nothing anywhere";
}

TEST(DeleteAgentEndpoint, TheAdmissionConnectorGoneIs503)
{
    // A handler of its own: EndpointUnderTest's pipeline keeps a strong reference to a connector,
    // so this weak_ptr can only expire if this test owns the only other one -- distinct from
    // UnavailableIndexerIs503AtAdmission, where the indexer is present but reports unhealthy.
    EndpointUnderTest fixture;
    std::shared_ptr<invsync::indexer::IIndexerConnectorSync> admission {
        std::make_shared<FakeIndexerConnectorSync>(fixture.events, "admission")};
    auto handler = delete_agent::makeHandler(delete_agent::Dependencies {fixture.pipeline, admission});
    admission.reset(); // stop() clearing the connector

    auto responder = std::make_shared<FutureResponder>();
    handler(deleteRequest("7"), responder);

    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "a terminal 503 queues nothing";
}

TEST(DeleteAgentEndpoint, ExpiredPipelineIs503)
{
    EndpointUnderTest fixture;
    wazuh::uds_http::RouteHandler handler = delete_agent::makeHandler(delete_agent::Dependencies {
        std::weak_ptr<SyncPipeline> {}, fixture.admissionConnector, fixture.asyncConnector});

    auto responder = std::make_shared<FutureResponder>();
    handler(deleteRequest("7"), responder);
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->asyncOps().empty()) << "the gate runs before either half is queued";
}

/// The other weak capture: the facade's phase-2 teardown has already dropped the async connector, so
/// the by-id half could not be queued. That is a `503`, not a half-done purge.
TEST(DeleteAgentEndpoint, ExpiredAsyncConnectorIs503)
{
    EndpointUnderTest fixture;
    wazuh::uds_http::RouteHandler handler = delete_agent::makeHandler(delete_agent::Dependencies {
        fixture.pipeline, fixture.admissionConnector, std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> {}});

    auto responder = std::make_shared<FutureResponder>();
    handler(deleteRequest("7"), responder);
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "and the by-query half must not run on its own";
}

TEST(DeleteAgentEndpoint, StoppedPipelineRefusesTheEnqueueWith503)
{
    EndpointUnderTest fixture;
    fixture.pipeline->stop();

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);
    EXPECT_EQ(503, responder->get().status);
}

// The deletion plane shares the sync route's sync.requests.total.* family: the handler counts
// its own inline rejections (each at the site that sends it), and counts NOTHING for an
// accepted deletion -- the terminal response is the pipeline's to count, so a request is never
// counted twice. The fixture's pipeline carries no metrics manager (null-object), so any count
// landing in OUR family can only have come from the endpoint.
TEST(DeleteAgentEndpoint, EveryResponseCountsIntoTheSharedFamilyExactlyOnce)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    const auto counters = invsync::metrics::RequestCounters::make(*metrics);

    EndpointUnderTest fixture;
    auto handler = delete_agent::makeHandler(
        delete_agent::Dependencies {fixture.pipeline, fixture.admissionConnector, fixture.asyncConnector, counters});

    // 400: bad agent-id header, answered (and counted) inline by the handler.
    {
        auto responder = std::make_shared<FutureResponder>();
        handler(deleteRequest("12x"), responder);
        EXPECT_EQ(400, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c400->get());

    // 503: the admission availability gate, answered (and counted) inline.
    fixture.events->m_syncAvailable.store(false);
    {
        auto responder = std::make_shared<FutureResponder>();
        handler(deleteRequest("7"), responder);
        EXPECT_EQ(503, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c503->get());
    fixture.events->m_syncAvailable.store(true);

    // Accepted deletion: the route answers AT ADMISSION, so the 200 is sent -- and therefore
    // counted -- right here. The queued item carries no responder, so the pipeline has nothing to
    // count for it and the cell cannot be double-counted when the purge later completes.
    {
        auto responder = std::make_shared<FutureResponder>();
        handler(deleteRequest("7"), responder);
        EXPECT_EQ(200, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c200->get());
    EXPECT_EQ(1U, counters.c400->get());
    EXPECT_EQ(1U, counters.c503->get());

    // Still one after the purge has run: the pipeline answering a responder-less item must not add
    // a second count for the same request.
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() >= 1; }));
    EXPECT_EQ(1U, counters.c200->get());
}

TEST(DeleteAgentEndpoint, DeletionRunsOnThePipelineWithThePaddedAgentId)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"queued"})", response.body) << "the body must not read as a completion";

    // The 200 no longer implies the purge ran, so wait for it before inspecting the connector.
    ASSERT_TRUE(waitFor([&] { return !fixture.events->syncOps().empty(); }))
        << "the queued deletion must still reach the indexer";

    // The scope itself is pinned by the pipeline suite; what this one owns is the id the endpoint
    // hands over -- BOTH halves must carry the SAME padded form the documents were written with.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("007", std::get<1>(ops[0])) << "padded to the historical 3-character form";
    EXPECT_EQ(CLUSTER, std::get<3>(ops[0]));

    // Counted, not just inspected: with an empty log the loop body would never run and this would
    // pass while the by-id half had quietly stopped happening.
    const auto asyncOps = fixture.events->asyncOps();
    ASSERT_EQ(2U, asyncOps.size()) << "one by-id delete per AGENT_DELETION_SCOPE_BY_ID entry";
    for (const auto& op : asyncOps)
    {
        EXPECT_EQ("bulkDelete", std::get<0>(op));
        EXPECT_EQ("007", std::get<1>(op)) << "the by-id half must use that same padded form";
    }
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() >= 1; }))
        << "the purge is only durable once it is flushed";
}

// --- The by-id half: AGENT_DELETION_SCOPE_BY_ID ---------------------------------------------------

/**
 * The two `wazuh-agent-*` documents are deleted BY ID, on the connector that WROTE them.
 *
 * They are deliberately no longer in the by-query scope: those documents come from POST /config and
 * POST /stats through the async connector's accumulating queue, and a by-query pass on the sync
 * connector can neither drain that queue nor -- being a SEARCH -- see a document that has not been
 * refreshed yet.
 */
TEST(DeleteAgentEndpoint, TheConfigAndStatsDocumentsAreDeletedByIdOnTheAsyncQueue)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);
    ASSERT_EQ(200, responder->get().status);

    // Queued at admission, so no waiting: this happens on the caller's thread, not a worker's.
    const auto ops = fixture.events->asyncOps();
    ASSERT_EQ(2U, ops.size());

    EXPECT_EQ("bulkDelete", std::get<0>(ops[0]));
    EXPECT_EQ("007", std::get<1>(ops[0])) << "the agent id IS the document id in these two indices";
    EXPECT_EQ("wazuh-agent-config", std::get<2>(ops[0]));

    EXPECT_EQ("bulkDelete", std::get<0>(ops[1]));
    EXPECT_EQ("007", std::get<1>(ops[1]));
    EXPECT_EQ("wazuh-agent-stats", std::get<2>(ops[1]));
}

/**
 * THE reported bug: a `/config` report the async queue had accepted but not yet pushed used to land
 * AFTER the deletion and resurrect the document -- permanently, since with the agent gone from
 * client.keys nothing overwrites it and nothing re-runs a deletion.
 *
 * The fix is that the deletion joins that same queue, which is FIFO: the report is applied first and
 * the deletes behind it. Here the report is the `index` op already on the timeline when the deletion
 * arrives, and what this pins is that both deletes land after it.
 */
TEST(DeleteAgentEndpoint, ADeletionIsQueuedBehindAReportTheAsyncConnectorHasAlreadyAccepted)
{
    EndpointUnderTest fixture;

    // What POST /config does, verbatim: hand the document to the async connector, whose queue may
    // not push it for another flush interval.
    fixture.asyncConnector->index("007", "wazuh-agent-config", R"({"wazuh":{"agent":{"id":"007"}}})");

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);
    ASSERT_EQ(200, responder->get().status);

    const auto ops = fixture.events->asyncOps();
    ASSERT_EQ(3U, ops.size());
    EXPECT_EQ("index", std::get<0>(ops[0])) << "the report was accepted first...";
    EXPECT_EQ("bulkDelete", std::get<0>(ops[1])) << "...so the deletion has to be queued behind it";
    EXPECT_EQ("bulkDelete", std::get<0>(ops[2]));
}

// The regression this whole change exists for: authd relays deletions from the one thread that
// persists client.keys, so the answer must not wait for the indexer. With the fake parked inside
// flush(), a caller that is already released proves the wait is gone.
TEST(DeleteAgentEndpoint, AnswersWhileThePurgeIsStillRunning)
{
    EndpointUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_flushGateClosed = true;
    }

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);

    // Answered even though the worker cannot get past its flush.
    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"queued"})", response.body);
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }))
        << "the purge must be parked in flush() while the caller is already free";

    // And the promise the 200 made is kept once the indexer lets go.
    fixture.events->openFlushGate();
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() >= 1; }));
}
