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
// REAL SyncPipeline over the fake connector, so "200" here means the same thing it means in
// production: delete-by-query flushed.
#include "endpoints/deleteAgentEndpoint.hpp"

#include "sync/syncPipeline.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
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
TEST(DeleteAgentEndpoint, InlineRejectionsCountIntoTheSharedFamilyAcceptedDeletionsDoNot)
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

    // Accepted deletion: the endpoint hands over to the pipeline and counts nothing -- the 200
    // is the pipeline's to count (invisible here: the fixture pipeline has its own private,
    // unwired registry), so the family must not move.
    {
        auto responder = std::make_shared<FutureResponder>();
        handler(deleteRequest("7"), responder);
        EXPECT_EQ(200, responder->get().status);
    }
    EXPECT_EQ(0U, counters.c200->get());
    EXPECT_EQ(1U, counters.c400->get());
    EXPECT_EQ(1U, counters.c503->get());
}

TEST(DeleteAgentEndpoint, DeletionRunsOnThePipelineWithThePaddedAgentId)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(deleteRequest("7"), responder);

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);

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
    EXPECT_GE(fixture.events->m_syncFlushes.load(), 1);
}
