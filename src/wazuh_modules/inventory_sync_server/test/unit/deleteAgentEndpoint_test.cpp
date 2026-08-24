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
    struct EndpointUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<FakeIndexerConnectorSync> admissionConnector;
        std::shared_ptr<SyncPipeline> pipeline;
        wazuh::uds_http::RouteHandler handler;

        EndpointUnderTest()
        {
            admissionConnector = std::make_shared<FakeIndexerConnectorSync>(events, "sync");
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
                std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
            pipeline = std::make_shared<SyncPipeline>(SyncPipelineConfig {}, std::move(connectors), CLUSTER);
            handler = delete_agent::makeHandler(delete_agent::Dependencies {pipeline, admissionConnector});
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
}

TEST(DeleteAgentEndpoint, UnavailableIndexerIs503AtAdmission)
{
    EndpointUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);

    EXPECT_EQ(503, responder->get().status) << "the caller must retry instead of losing the delete";
    EXPECT_TRUE(fixture.events->syncOps().empty());
}

TEST(DeleteAgentEndpoint, ExpiredPipelineIs503)
{
    EndpointUnderTest fixture;
    wazuh::uds_http::RouteHandler handler = delete_agent::makeHandler(
        delete_agent::Dependencies {std::weak_ptr<SyncPipeline> {}, fixture.admissionConnector});

    auto responder = std::make_shared<FutureResponder>();
    handler(deleteRequest("7"), responder);
    EXPECT_EQ(503, responder->get().status);
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
    auto handler =
        delete_agent::makeHandler(delete_agent::Dependencies {fixture.pipeline, fixture.admissionConnector, counters});

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
    ASSERT_TRUE(waitFor([&] { return fixture.events->syncOps().size() >= 3U; }))
        << "the queued deletion must still reach the indexer";

    // The full scope is pinned by the pipeline suite; what this one owns is the id the endpoint
    // hands over -- every deletion must carry the SAME padded form the documents were written with.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(3U, ops.size());
    std::size_t deletes = 0;
    for (const auto& op : ops)
    {
        if (std::get<0>(op) == "deleteByQuery")
        {
            ++deletes;
            EXPECT_EQ("007", std::get<1>(op)) << "padded to the historical 3-character form";
            EXPECT_EQ(CLUSTER, std::get<3>(op));
        }
    }
    // Counted, not just inspected: without this, three ops of any other kind would satisfy the size
    // assertion above while the per-delete expectations never ran at all.
    EXPECT_EQ(3U, deletes) << "one deleteByQuery per index of the deletion scope";
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() >= 1; }))
        << "the purge is only durable once it is flushed";
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
