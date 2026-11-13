/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
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
// The route only gates and enqueues: both halves of the deletion -- the by-id deletes on the `agent-state`
// bucket and the by-query -- run on the agent's shard worker, which answers AT COMPLETION. The 200 means the
// delete-by-query has run AND flushed and the by-id deletes resolved, which is what lets the Task Manager record
// the deletion as `completed` and have that mean purged. The by-id half itself is syncPipeline_test.cpp's
// (a real runtime: a Group's tickets cannot be faked).
#include "endpoints/deleteAgentEndpoint.hpp"

#include "sync/fullSessionValidator.hpp"
#include "sync/syncPipeline.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>
#include <json.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using invsync::sync::SyncPipeline;
using invsync::sync::SyncPipelineConfig;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::SessionSpec;
using invsync::test::ValueSpec;
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

    /// A real single-worker pipeline over the shared fake-connector event log, plus the handler wired exactly
    /// like the facade wires it.
    ///
    /// The deletion's by-id half runs on that worker through `AgentDeletionDeps`; by default it is off
    /// (by-query only), and a test that wants the by-id half hands the pipeline a scripted writer.
    struct EndpointUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        /// The one behind the up-front availability gate; the pipeline holds its own.
        std::shared_ptr<FakeIndexerConnectorSync> admissionConnector;
        std::shared_ptr<SyncPipeline> pipeline;
        wazuh::uds_http::RouteHandler handler;

        explicit EndpointUnderTest(SyncPipelineConfig config = {})
        {
            admissionConnector = std::make_shared<FakeIndexerConnectorSync>(events, "sync");
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
                std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
            pipeline = std::make_shared<SyncPipeline>(std::move(config), std::move(connectors), CLUSTER);
            handler = delete_agent::makeHandler(delete_agent::Dependencies {pipeline, admissionConnector});
        }
    };

    /// A session item for agent 001, to park the worker inside flush() while the test looks at the deletion's queue.
    invsync::sync::SyncPipeline::Item sessionItem(const std::shared_ptr<FutureResponder>& responder)
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = invsync::test::buildSyncDataSession(SessionSpec {}, {ValueSpec {}});
        auto result = invsync::sync::validateFullSession(request->body, "001", CLUSTER);
        auto* session = std::get_if<invsync::sync::ValidatedSession>(&result);
        if (session == nullptr)
        {
            throw std::runtime_error {"test session failed validation"};
        }
        return SyncPipeline::Item {request, responder, std::move(*session)};
    }

    /// For facts that hold only once the worker got somewhere (parked in flush(), flushed).
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
    auto handler = delete_agent::makeHandler(delete_agent::Dependencies {fixture.pipeline, admission});
    admission.reset(); // stop() clearing the connector

    auto responder = std::make_shared<FutureResponder>();
    handler(executionRequest(R"({"agent_id":"7"})"), responder);

    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "a terminal 503 queues nothing";
}

TEST(DeleteAgentEndpoint, ExpiredPipelineIs503)
{
    EndpointUnderTest fixture;
    wazuh::uds_http::RouteHandler handler = delete_agent::makeHandler(
        delete_agent::Dependencies {std::weak_ptr<SyncPipeline> {}, fixture.admissionConnector});

    auto responder = std::make_shared<FutureResponder>();
    handler(executionRequest(R"({"agent_id":"7"})"), responder);
    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "the gate runs before anything is queued";
}

/**
 * The route validates, gates and enqueues -- nothing else. The by-id half (cancel, the Group of two
 * deletes) is the WORKER's, so while the worker is parked behind an earlier session's flush the writer has seen
 * nothing and the caller has no answer; once the worker gets to the item it cancels, asks for its Group and --
 * the scripted writer's Group refuses every add -- cancels again and answers a failure.
 */
TEST(DeleteAgentEndpoint, OnlyGatesAndEnqueues)
{
    SyncPipelineConfig config;
    auto events = std::make_shared<ConnectorEvents>();
    config.agentDeletion.byId = true;
    config.agentDeletion.agentState = events->m_agentStateWriter;
    config.agentDeletion.budget = std::chrono::seconds {5};

    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    auto pipeline = std::make_shared<SyncPipeline>(config, std::move(connectors), CLUSTER);
    auto admission = std::make_shared<FakeIndexerConnectorSync>(events, "admission");
    auto handler = delete_agent::makeHandler(delete_agent::Dependencies {pipeline, admission});

    // Park the worker inside the flush of an earlier session of the same shard.
    events->closeFlushGate();
    auto session = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline->enqueue(sessionItem(session)));
    ASSERT_TRUE(waitFor([&] { return events->m_flushEntered.load() == 1; }));

    auto responder = std::make_shared<FutureResponder>();
    handler(executionRequest(R"({"agent_id":"7"})"), responder);

    // The handler returned: the deletion is queued, and neither half has run nor answered.
    EXPECT_FALSE(responder->answered());
    EXPECT_TRUE(events->m_agentStateWriter->calls().empty()) << "the route must not touch the agent-state writer";
    EXPECT_TRUE(events->m_query->dbqs().empty());

    events->openFlushGate();

    const auto response = responder->get();
    EXPECT_GE(response.status, 500) << "the scripted Group refuses every add: the by-id half fails the deletion";
    EXPECT_EQ((std::vector<std::string> {"cancel:007", "group", "cancel:007"}), events->m_agentStateWriter->calls())
        << "cancel(agent), the Group, and a second cancel(agent) on the refusal";
    EXPECT_EQ(200, session->get().status);
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

    // Canonical, exactly the spelling the header route requires: the deletion must match what
    // indexing wrote, whichever route asked for it.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("007", std::get<1>(ops[0]));
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

/// Leading zeros are a spelling, not another agent: the id is normalized to the canonical form every
/// document carries, so "0007" reaches agent 007 instead of an id no document has.
TEST(DeleteAgentEndpoint, ALeadingZeroSpellingIsNormalizedToTheCanonicalId)
{
    EndpointUnderTest fixture;

    auto responder = std::make_shared<FutureResponder>();
    fixture.handler(executionRequest(R"({"agent_id":"0007"})"), responder);
    ASSERT_EQ(200, responder->get().status);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", std::get<1>(ops[0]));
}

TEST(DeleteAgentEndpoint, TheRouteRejectsABodyThatNamesNoAgent)
{
    EndpointUnderTest fixture;

    const std::vector<std::string> bodies {"",         // the dispatcher sent an empty payload
                                           "not json", // malformed: discarded, and a discarded value is not an object
                                           "[]",       // valid JSON, wrong shape
                                           R"({})",    // no member
                                           R"({"agent_id":null})",     // present and useless
                                           R"({"agent_id":"12x"})",    // not an id
                                           R"({"agent_id":"-1"})",     // nor is this
                                           R"({"agent_id":{"id":7}})", // nor this
                                           // Out of the 32-bit range: no agent can have these ids, and they must never
                                           // wrap onto one that exists (atoi("4294967297") is 1 on glibc LP64).
                                           R"({"agent_id":"4294967297"})",
                                           R"({"agent_id":4294967297})",
                                           R"({"agent_id":"99999999999"})"};

    for (const auto& body : bodies)
    {
        auto responder = std::make_shared<FutureResponder>();
        fixture.handler(executionRequest(body), responder);
        const auto response = responder->get();
        EXPECT_EQ(400, response.status) << "body='" << body << "'";

        // The reasons quote the member name, so the reply must be built as JSON, not concatenated.
        const auto reply = nlohmann::json::parse(response.body, nullptr, /*allow_exceptions=*/false);
        ASSERT_TRUE(reply.is_object()) << "reply is not valid JSON: '" << response.body << "'";
        EXPECT_TRUE(reply.contains("error") && reply.at("error").is_string()) << response.body;
        EXPECT_EQ(400, reply.value("code", 0)) << response.body;
    }

    EXPECT_TRUE(fixture.events->syncOps().empty()) << "nothing may reach the connector on a 400";
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
    auto handler =
        delete_agent::makeHandler(delete_agent::Dependencies {fixture.pipeline, fixture.admissionConnector, counters});

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
