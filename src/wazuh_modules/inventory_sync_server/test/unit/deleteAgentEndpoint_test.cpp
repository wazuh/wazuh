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

// Unit-tests the POST /_internal/agents/delete route policy (design doc 04): body validation, the
// up-front availability gate, and the deferred execution on the target agent's pipeline shard --
// with a REAL SyncPipeline over the fake connector, so what runs here is what runs in production.
//
// The route answers AT COMPLETION: the 200 means the delete-by-query has run AND flushed, which is
// what lets the Task Manager record the deletion as `completed` and have that mean purged.
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

        /// Whether anything has been sent yet. Only meaningful next to a fact that pins WHERE the
        /// handler is (the worker parked inside flush(), say); on its own it would just be a race.
        bool answered() const
        {
            return m_sent.load();
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
        /// The one behind the up-front availability gate; the pipeline holds its own.
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

    /// For the halves the response does NOT wait on -- the by-id deletes ride a fire-and-forget
    /// queue -- and for pinning that a refused request queued nothing.
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

    /// What the dispatcher sends: a manager-task row's PAYLOAD as the body, and no headers at all.
    std::shared_ptr<HttpRequest> executionRequest(const std::string& body)
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = body;
        return request;
    }
} // namespace

TEST(DeleteAgentEndpoint, TheRouteIsPinned)
{
    // Its caller is the Task Manager's dispatcher, whose descriptor carries this method and path as
    // data. A silent rename here would dead-letter every deletion.
    EXPECT_EQ(delete_agent::method(), wazuh::uds_http::Method::Post);
    EXPECT_STREQ(delete_agent::path(), "/_internal/agents/delete");

    // The backstop must stay ABOVE the Task Manager's manager_task_delete_timeout (600 s), or the
    // transport synthesizes a 504 while the purge is still succeeding and the dispatcher retries a
    // deletion that has no attempt budget to exhaust. Pinned so lowering it is a decision, not a
    // side effect.
    EXPECT_GT(delete_agent::responseTimeoutSeconds(), 600U);
}

TEST(DeleteAgentEndpoint, TheAdmissionConnectorGoneIs503)
{
    // A handler of its own: EndpointUnderTest's pipeline keeps a strong reference to a connector,
    // so this weak_ptr can only expire if this test owns the only other one -- distinct from
    // UnavailableIndexerIs503AtAdmission, where the indexer is present but reports unhealthy.
    EndpointUnderTest fixture;
    std::shared_ptr<invsync::indexer::IIndexerConnectorSync> admission {
        std::make_shared<FakeIndexerConnectorSync>(fixture.events, "admission")};
    // The async connector stays live on purpose: with it left expired too, the handler would refuse
    // on THAT gate and this case would pass without the admission weak_ptr ever being consulted.
    auto handler =
        delete_agent::makeHandler(delete_agent::Dependencies {fixture.pipeline, admission, fixture.asyncConnector});
    admission.reset(); // stop() clearing the connector

    auto responder = std::make_shared<FutureResponder>();
    handler(executionRequest(R"({"agent_id":"7"})"), responder);

    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "a terminal 503 queues nothing";
    EXPECT_TRUE(fixture.events->asyncOps().empty()) << "including the by-id half";
}

TEST(DeleteAgentEndpoint, ExpiredPipelineIs503)
{
    EndpointUnderTest fixture;
    wazuh::uds_http::RouteHandler handler = delete_agent::makeHandler(delete_agent::Dependencies {
        std::weak_ptr<SyncPipeline> {}, fixture.admissionConnector, fixture.asyncConnector});

    auto responder = std::make_shared<FutureResponder>();
    handler(executionRequest(R"({"agent_id":"7"})"), responder);
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
    handler(executionRequest(R"({"agent_id":"7"})"), responder);
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "and the by-query half must not run on its own";
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
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);
    ASSERT_EQ(200, responder->get().status);

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
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);
    ASSERT_EQ(200, responder->get().status);

    const auto ops = fixture.events->asyncOps();
    ASSERT_EQ(3U, ops.size());
    EXPECT_EQ("index", std::get<0>(ops[0])) << "the report was accepted first...";
    EXPECT_EQ("bulkDelete", std::get<0>(ops[1])) << "...so the deletion has to be queued behind it";
    EXPECT_EQ("bulkDelete", std::get<0>(ops[2]));
}

// --- Answered AT COMPLETION -----------------------------------------------------------------------
//
// The Task Manager's dispatcher writes its row `completed` on the 200, so these tests pin what makes
// that record true: nothing is sent until the purge has flushed, and the agent id is read from the
// body because the dispatcher sends no headers.

/// THE property the whole route exists for: `completed` must mean purged. With the fake parked
/// inside flush(), a caller that is still waiting proves the answer is not sent at admission.
TEST(DeleteAgentEndpoint, TheRouteAnswersOnlyAfterThePurgeHasFlushed)
{
    EndpointUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_flushGateClosed = true;
    }

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);

    // Not a race: the worker is demonstrably parked inside the flush that executeDeleteAgent()
    // runs, so it cannot have answered. The admission route answers 200 at exactly this point.
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));
    EXPECT_FALSE(responder->answered()) << "a 200 here would record a purge that has not happened";

    fixture.events->openFlushGate();

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body) << "the pipeline's own answer, not the queued body";
    EXPECT_GE(fixture.events->m_syncFlushes.load(), 1);
}

TEST(DeleteAgentEndpoint, TheRouteReadsTheAgentIdFromTheBody)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);
    ASSERT_EQ(200, responder->get().status);

    // Padded exactly like the header route pads: the deletion must match what indexing wrote,
    // whichever route asked for it.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("007", std::get<1>(ops[0]));

    const auto asyncOps = fixture.events->asyncOps();
    ASSERT_EQ(2U, asyncOps.size()) << "the by-id half runs on this route too";
    for (const auto& op : asyncOps)
    {
        EXPECT_EQ("bulkDelete", std::get<0>(op));
        EXPECT_EQ("007", std::get<1>(op));
    }
}

/// Both JSON spellings of the same small integer. Tolerated rather than rejected because this type's
/// descriptor sets allow_terminal_failure = false, so a 400 comes back to the dispatcher as
/// retryable -- a producer that emitted 7 instead of "7" would re-queue forever instead of failing.
TEST(DeleteAgentEndpoint, TheRouteAcceptsTheNumberSpellingOfAnAgentId)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":7})"), responder);
    ASSERT_EQ(200, responder->get().status);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", std::get<1>(ops[0])) << "the same agent, written the other way";
}

TEST(DeleteAgentEndpoint, TheRouteRejectsABodyThatNamesNoAgent)
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
        fixture.handler(executionRequest(body), responder);
        EXPECT_EQ(400, responder->get().status) << "body='" << body << "'";
    }

    EXPECT_TRUE(fixture.events->syncOps().empty()) << "nothing may reach the connector on a 400";
    EXPECT_TRUE(fixture.events->asyncOps().empty()) << "and nothing may be queued on the async half either";
}

/// The body is the ONLY channel on this route. The dispatcher POSTs a row's payload and sets no
/// headers, so honouring one here would hide a producer that forgot to write the id into the payload
/// -- and would work in a test while failing in production.
TEST(DeleteAgentEndpoint, TheRouteIgnoresTheAgentIdHeader)
{
    EndpointUnderTest fixture;

    auto request = executionRequest(R"({})");
    request->headers.emplace("x-wazuh-agent-id", "7");

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(request, responder);
    EXPECT_EQ(400, responder->get().status);
    EXPECT_TRUE(fixture.events->asyncOps().empty());
}

TEST(DeleteAgentEndpoint, TheRouteRefusesAtAdmissionWhenTheIndexerIsUnavailable)
{
    EndpointUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);

    // 503, not 409: the dispatcher reads a 5xx as retryable and backs off. Refusing here rather
    // than letting the worker re-check keeps a lane slot and a shard slot free.
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty());
    EXPECT_TRUE(fixture.events->asyncOps().empty());
}

/// A refused enqueue does not consume the item, so the responder it was carrying is still the
/// handler's to answer with. Exactly one answer, from exactly one place.
TEST(DeleteAgentEndpoint, AStoppedPipelineAnswersOnceWith503)
{
    EndpointUnderTest fixture;
    fixture.pipeline->stop();

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":"7"})"), responder);
    EXPECT_EQ(503, responder->get().status);
}

/// The counting rule, from the other side: this handler counts only what it sends itself. The
/// fixture's pipeline carries no metrics manager, so a count landing in OUR family could only have
/// come from the endpoint -- and after an accepted deletion there must be none.
TEST(DeleteAgentEndpoint, TheRouteCountsOnlyTheResponsesItSendsItself)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    const auto counters = invsync::metrics::RequestCounters::make(*metrics);

    EndpointUnderTest fixture;
    auto handler = delete_agent::makeHandler(
        delete_agent::Dependencies {fixture.pipeline, fixture.admissionConnector, fixture.asyncConnector, counters});

    {
        auto responder = std::make_shared<FutureResponder>();
        handler(executionRequest(R"({})"), responder);
        EXPECT_EQ(400, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c400->get());

    fixture.events->m_syncAvailable.store(false);
    {
        auto responder = std::make_shared<FutureResponder>();
        handler(executionRequest(R"({"agent_id":"7"})"), responder);
        EXPECT_EQ(503, responder->get().status);
    }
    EXPECT_EQ(1U, counters.c503->get());
    fixture.events->m_syncAvailable.store(true);

    {
        auto responder = std::make_shared<FutureResponder>();
        handler(executionRequest(R"({"agent_id":"7"})"), responder);
        EXPECT_EQ(200, responder->get().status);
    }
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() >= 1; }));

    // Zero, not one: the 200 was sent by the pipeline, which counts it into ITS manager. A count
    // here would mean the same request counted twice.
    EXPECT_EQ(0U, counters.c200->get());
    EXPECT_EQ(1U, counters.c400->get());
    EXPECT_EQ(1U, counters.c503->get());
}
