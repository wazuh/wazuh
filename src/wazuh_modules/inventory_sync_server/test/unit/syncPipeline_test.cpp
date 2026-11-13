/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/syncPipeline.hpp"

#include "common/metricNames.hpp"
#include "sync/fullSessionValidator.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testRealIndexer.hpp"
#include "testSessionBuilder.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
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

namespace
{
    constexpr auto CLUSTER {"test-cluster"};
    constexpr auto WAIT {std::chrono::seconds {10}};

    /// Resolves a future with the response; safe to fulfill from a worker thread.
    class FutureResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_sent.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
            else
            {
                ++m_extraSends;
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

        int extraSends() const
        {
            return m_extraSends.load();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_sent {false};
        std::atomic<int> m_extraSends {0};
    };

    /// Builds a queue item whose ValidatedSession aliases the request's own body, exactly like the
    /// endpoint does.
    SyncPipeline::Item makeItem(std::string body, std::shared_ptr<FutureResponder> responder)
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = std::move(body);

        auto result = invsync::sync::validateFullSession(request->body, "001", CLUSTER);
        auto* session = std::get_if<invsync::sync::ValidatedSession>(&result);
        if (session == nullptr)
        {
            throw std::runtime_error {"test session failed validation"};
        }
        return SyncPipeline::Item {request, std::move(responder), std::move(*session)};
    }

    std::string deltaBody(const std::string& docId)
    {
        ValueSpec value;
        value.id = docId;
        return invsync::test::buildSyncDataSession(SessionSpec {}, {value});
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

    /// The value of @p name in the response, or "" when absent.
    std::string headerValue(const HttpResponse& response, const std::string& name)
    {
        for (const auto& [key, value] : response.headers)
        {
            if (key == name)
            {
                return value;
            }
        }
        return "";
    }

    struct PipelineUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<wazuh::metrics::Manager> metrics {std::make_shared<wazuh::metrics::Manager>()};
        std::unique_ptr<SyncPipeline> pipeline;

        explicit PipelineUnderTest(std::size_t workers = 1, SyncPipelineConfig config = {})
        {
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors;
            connectors.reserve(workers);
            for (std::size_t i = 0; i < workers; ++i)
            {
                connectors.push_back(std::make_shared<FakeIndexerConnectorSync>(events, "sync"));
            }
            pipeline = std::make_unique<SyncPipeline>(config, std::move(connectors), CLUSTER, nullptr, metrics);
        }
    };
} // namespace

TEST(SyncPipelineTest, ABulkSessionIsStagedFlushedAndAnswered200)
{
    PipelineUnderTest fixture;
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);
    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "queue drained -> exactly one flush";
    EXPECT_EQ(0, responder->extraSends());
}

// The connector's real `_bulk` request counts are no longer drained by the pipeline: with indexer_client
// they are read by pull at GET /metrics from the bucket's own counters; metricsEndpoint_test.cpp's
// PublishesBucketMetrics pins that.

TEST(SyncPipelineTest, GroupCommitBatchesWhateverQueuedBehindABlockedFlush)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), first)));

    // The worker stages doc-1, sees its queue empty and enters flush -- where the gate holds it.
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    auto second = std::make_shared<FutureResponder>();
    auto third = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-2"), second)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-3"), third)));

    fixture.events->openFlushGate();

    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(200, second->get().status);
    EXPECT_EQ(200, third->get().status);

    // doc-1 flushed alone (it was already inside flush); doc-2 and doc-3 shared ONE flush.
    EXPECT_TRUE(waitFor([&] { return fixture.events->m_syncFlushes.load() == 2; }))
        << "expected exactly 2 flushes, got " << fixture.events->m_syncFlushes.load();
}

TEST(SyncPipelineTest, PerAgentOrderHoldsAcrossSessionKinds)
{
    PipelineUnderTest fixture;

    auto delta = std::make_shared<FutureResponder>();
    auto cleans = std::make_shared<FutureResponder>();
    auto rebuild = std::make_shared<FutureResponder>();

    // delete-then-reindex (a full resync) hinges on this order surviving the queue.
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-old"), delta)));
    ASSERT_TRUE(fixture.pipeline->enqueue(
        makeItem(invsync::test::buildCleansSession(SessionSpec {}, {"wazuh-states-inventory-packages"}), cleans)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-new"), rebuild)));

    EXPECT_EQ(200, delta->get().status);
    EXPECT_EQ(200, cleans->get().status);
    EXPECT_EQ(200, rebuild->get().status);

    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(3U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0]));
    EXPECT_EQ("test-cluster_001_doc-old", std::get<1>(ops[0]));
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[1])) << "the clean must not overtake the earlier delta";
    EXPECT_EQ("bulkIndex", std::get<0>(ops[2]));
    EXPECT_EQ("test-cluster_001_doc-new", std::get<1>(ops[2])) << "nor be overtaken by the later one";
}

TEST(SyncPipelineTest, TheByteCapRefusesWithoutConsumingTheItem)
{
    SyncPipelineConfig config;
    config.maxQueueBytes = 1;
    PipelineUnderTest fixture {1, config};

    auto responder = std::make_shared<FutureResponder>();
    EXPECT_FALSE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));
    EXPECT_FALSE(responder->answered()) << "the caller answers a refused enqueue, not the pipeline";
}

TEST(SyncPipelineTest, AFailedFlushFailsTheWholeBatch)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), first)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    auto second = std::make_shared<FutureResponder>();
    auto third = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-2"), second)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-3"), third)));

    // Every flush from here on throws, with the connector reporting HEALTHY: the failure is not
    // an availability problem, so the whole batch must map to 500.
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
    }
    fixture.events->openFlushGate();

    EXPECT_EQ(500, first->get().status);
    EXPECT_EQ(500, second->get().status) << "batch members share the flush verdict";
    EXPECT_EQ(500, third->get().status);
}

/**
 * R-07 observability: a failed group commit is counted by its cause, and the sessions it punished
 * are counted as blast radius -- the amplification that was previously visible only as a log line.
 */
TEST(SyncPipelineTest, FailedGroupCommitsAreCountedByCauseAndBlastRadius)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    auto events = std::make_shared<ConnectorEvents>();
    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    SyncPipeline pipeline {SyncPipelineConfig {}, std::move(connectors), CLUSTER, nullptr, metrics};

    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowOn = "flush";
        events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::RetryExhausted;
    }
    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-1"), first)));
    // The retry budget ran out on a retryable condition: the agent is told to come back.
    EXPECT_EQ(503, first->get().status);

    // An untyped connector failure lands in the "other" bucket.
    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowCause.reset();
    }
    auto second = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-2"), second)));
    EXPECT_EQ(500, second->get().status);

    // A flush whose delete-by-query ran out of its conflict allowance left documents behind, but
    // it is contention: the sessions get a retryable 503 with the delay, not a 500.
    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::ConflictsExhausted;
    }
    auto third = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-3"), third)));
    const auto contention = third->get();
    EXPECT_EQ(503, contention.status);
    EXPECT_EQ(R"({"error":"indexer contention","code":503,"reason":"version_conflicts"})", contention.body);
    EXPECT_EQ("15", headerValue(contention, "Retry-After"));

    const auto counter = [&metrics](const std::string& name)
    {
        return metrics->getOrCreateCounter(name, "", "count")->get();
    };
    EXPECT_EQ(1U, counter(std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "exhausted"));
    EXPECT_EQ(1U, counter(std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "other"));
    EXPECT_EQ(1U, counter(std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "documents"));
    EXPECT_EQ(1U, counter(invsync::metrics::INDEXER_CONFLICT_EXHAUSTED));
    EXPECT_EQ(3U, counter(invsync::metrics::BULK_SESSIONS_FAILED));
}

TEST(SyncPipelineTest, FlushFailureMapsTo503WhenTheCauseIsUnavailable)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::Unavailable;
    }
    fixture.events->openFlushGate();

    EXPECT_EQ(503, responder->get().status) << "an indexer outage is retriable, so 503, not 500";
    EXPECT_EQ(1U,
              fixture.metrics
                  ->getOrCreateCounter(
                      std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "unavailable", "", "count")
                  ->get());
}

/// isAvailable() no longer decides the code after a failure: the cause alone does. An untyped
/// failure answers 500 whatever the connector reports about itself.
TEST(SyncPipelineTest, FlushFailureIgnoresWhatTheConnectorReportsAboutItself)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
    }
    fixture.events->m_syncAvailable.store(false);
    fixture.events->openFlushGate();

    EXPECT_EQ(500, responder->get().status);
}

TEST(SyncPipelineTest, AnUnavailableConnectorAtDispatchAnswers503WithoutStaging)
{
    PipelineUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));

    EXPECT_EQ(503, responder->get().status);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "nothing may be staged into a connector that cannot flush";
}

TEST(SyncPipelineTest, AnImmediateSessionFailureMapsByCause)
{
    PipelineUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "executeUpdateByQuery";
    }

    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_MetadataDelta;

    auto healthy = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(invsync::test::buildBareSession(spec), healthy)));
    const auto failed = healthy->get();
    EXPECT_EQ(500, failed.status);
    EXPECT_EQ("", headerValue(failed, "Retry-After"));

    // The update-by-query ran out of its version-conflict allowance: a competing writer of this
    // agent's documents was still running, so the agent is told to come back after the delay the
    // config derives from the connector's own allowance (15 s by default), and it is counted apart.
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::ConflictsExhausted;
    }
    auto contended = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(invsync::test::buildBareSession(spec), contended)));
    const auto contention = contended->get();
    EXPECT_EQ(503, contention.status);
    EXPECT_EQ(R"({"error":"indexer contention","code":503,"reason":"version_conflicts"})", contention.body);
    EXPECT_EQ("15", headerValue(contention, "Retry-After"));
    EXPECT_EQ(1U,
              fixture.metrics->getOrCreateCounter(invsync::metrics::INDEXER_CONFLICT_EXHAUSTED, "", "count")->get());
    EXPECT_EQ(
        1U,
        fixture.metrics->getOrCreateCounter(std::string {invsync::metrics::REQUESTS_TOTAL_PREFIX} + "500", "", "count")
            ->get());
    EXPECT_EQ(
        1U,
        fixture.metrics->getOrCreateCounter(std::string {invsync::metrics::REQUESTS_TOTAL_PREFIX} + "503", "", "count")
            ->get());

    // A transient failure of the by-query itself: the generic 503, no delay attached.
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::Unavailable;
    }
    auto transient = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(invsync::test::buildBareSession(spec), transient)));
    const auto transientResponse = transient->get();
    EXPECT_EQ(503, transientResponse.status);
    EXPECT_EQ(R"({"error":"Service unavailable","code":503})", transientResponse.body);
    EXPECT_EQ("", headerValue(transientResponse, "Retry-After"));

    fixture.events->m_syncAvailable.store(false);
    // The dispatch gate now rejects before the processor runs; that is the generic 503 the agent
    // sees, with no delay attached: an unavailable indexer outranks the contention cause.
    auto unavailable = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(invsync::test::buildBareSession(spec), unavailable)));
    const auto generic = unavailable->get();
    EXPECT_EQ(503, generic.status);
    EXPECT_EQ(R"({"error":"Service unavailable","code":503})", generic.body);
    EXPECT_EQ("", headerValue(generic, "Retry-After"));
}

TEST(SyncPipelineTest, AProtocolErrorDoesNotPoisonTheOpenBatch)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), first)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    ValueSpec forged;
    forged.rawOperation = 7;
    auto bad = std::make_shared<FutureResponder>();
    ASSERT_TRUE(
        fixture.pipeline->enqueue(makeItem(invsync::test::buildSyncDataSession(SessionSpec {}, {forged}), bad)));

    auto after = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-2"), after)));

    fixture.events->openFlushGate();

    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(400, bad->get().status);
    EXPECT_EQ(200, after->get().status) << "the 400 answered inline; the batch around it survived";
}

TEST(SyncPipelineTest, StopAnswers503ToWhateverWasStillQueued)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto inFlight = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), inFlight)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    auto queuedA = std::make_shared<FutureResponder>();
    auto queuedB = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-2"), queuedA)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-3"), queuedB)));

    // stop() joins the workers, and the parked one only moves once the gate opens.
    std::thread opener {[&fixture]
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds {50});
                            fixture.events->openFlushGate();
                        }};
    fixture.pipeline->stop();
    opener.join();

    // The in-flight batch completed (its flush had already been entered when stop() was called);
    // everything still queued behind it was answered 503 -- either by the draining worker (which
    // saw m_stopping before processing) or by stop()'s own sweep. Nobody is left hanging.
    EXPECT_EQ(200, inFlight->get().status);
    EXPECT_EQ(503, queuedA->get().status);
    EXPECT_EQ(503, queuedB->get().status);

    auto late = std::make_shared<FutureResponder>();
    EXPECT_FALSE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-4"), late))) << "enqueue after stop must refuse";
}

TEST(SyncPipelineTest, SameAgentSessionsKeepTheirOrderWithManyWorkers)
{
    PipelineUnderTest fixture {4};

    std::vector<std::shared_ptr<FutureResponder>> responders;
    for (int i = 0; i < 8; ++i)
    {
        auto responder = std::make_shared<FutureResponder>();
        ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-" + std::to_string(i)), responder)));
        responders.push_back(std::move(responder));
    }
    for (auto& responder : responders)
    {
        EXPECT_EQ(200, responder->get().status);
    }

    // All eight belong to agent 001, so whatever the worker count, they must appear in enqueue
    // order in the shared op log: same agent -> same shard -> same FIFO.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(8U, ops.size());
    for (int i = 0; i < 8; ++i)
    {
        EXPECT_EQ("test-cluster_001_doc-" + std::to_string(i), std::get<1>(ops[i]));
    }
}

// --- DeleteAgent items (design doc 04) ---------------------------------------------------------

namespace
{
    /// A whole-agent deletion item, exactly as deleteAgentEndpoint builds it: no FlatBuffer, only
    /// the (already padded) agent id.
    SyncPipeline::Item makeDeleteItem(const std::string& paddedAgentId, std::shared_ptr<FutureResponder> responder)
    {
        SyncPipeline::Item item;
        item.request = std::make_shared<HttpRequest>();
        item.responder = std::move(responder);
        item.kind = SyncPipeline::Item::Kind::DeleteAgent;
        item.session.agentId = paddedAgentId;
        return item;
    }
} // namespace

TEST(SyncPipelineTest, ADeleteAgentItemWipesTheByQueryScopeAndFlushes)
{
    PipelineUnderTest fixture;
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("005", responder)));

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    /*
     * AGENT_DELETION_SCOPE_BY_QUERY, and NOTHING else from the connector. Exactly one op is the assertion that
     * matters here: `wazuh-agent-config` and `wazuh-agent-stats` are deliberately NOT deleted through the sync
     * connector -- a delete-by-query could not see an unrefreshed document, which is how a report in flight used
     * to outlive the agent. The worker deletes them by id on the `agent-state` bucket instead (the by-id cases
     * below; this pipeline has no by-id deps, so it runs the by-query half alone).
     *
     * The deletion also does NOT refresh first (that needs a privilege the manager's indexer role
     * lacks), which is why a STATE document written inside the index refresh interval can survive.
     */
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("005", std::get<1>(ops[0]));
    EXPECT_EQ("wazuh-states-*", std::get<2>(ops[0]));
    EXPECT_EQ(CLUSTER, std::get<3>(ops[0])) << "scoped to this cluster";

    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "the 200 means the delete was FLUSHED";
}

TEST(SyncPipelineTest, ADeletionOrdersAfterAnEarlierSessionOfTheSameAgent)
{
    PipelineUnderTest fixture;

    // Same agent (001) -> same shard FIFO: the delta's write must reach the op log before the
    // deletion, whatever the flush grouping -- otherwise a delete-then-reenroll could resurrect.
    auto delta = std::make_shared<FutureResponder>();
    auto deletion = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), delta)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("001", deletion)));

    EXPECT_EQ(200, delta->get().status);
    EXPECT_EQ(200, deletion->get().status);

    // Exact, not just non-empty: the assertions below index ops[1], so a regression that dropped
    // the deletion entirely would read out of bounds instead of failing. One bulkIndex for the
    // delta, then the by-query pass over AGENT_DELETION_SCOPE_BY_QUERY.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0])) << "the delta's write reaches the indexer first";
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[1])) << "and the deletion follows it, never the other way round";
}

TEST(SyncPipelineTest, ADeleteFailureIsVisibleToTheCaller)
{
    // The legacy path lost this silently (doc 04 §1's key improvement): a connector throw must
    // surface as a retriable status, mapped by availability like every other failure.
    PipelineUnderTest fixture;
    fixture.events->m_syncThrowOn = "deleteByQuery";

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("005", responder)));
    EXPECT_EQ(500, responder->get().status) << "connector available but failing -> 500";

    // The deletion's by-query ran out of its version-conflict allowance in the flush: the same
    // contention an immediate session answers 503 + Retry-After, counted apart.
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::ConflictsExhausted;
    }
    auto contended = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("007", contended)));
    const auto contention = contended->get();
    EXPECT_EQ(503, contention.status);
    EXPECT_EQ(R"({"error":"indexer contention","code":503,"reason":"version_conflicts"})", contention.body);
    EXPECT_EQ("15", headerValue(contention, "Retry-After"));
    EXPECT_EQ(1U,
              fixture.metrics->getOrCreateCounter(invsync::metrics::INDEXER_CONFLICT_EXHAUSTED, "", "count")->get());
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowCause.reset();
    }

    fixture.events->m_syncThrowOn.clear();
    fixture.events->m_syncAvailable.store(false);
    auto second = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("006", second)));
    EXPECT_EQ(503, second->get().status) << "indexer unavailable at dispatch -> 503, nothing executed";
}

// --- The by-id half of a whole-agent deletion -----------------
//
// A Group and its tickets cannot be faked, so these run a REAL pipeline worker over a real runtime on the
// library's fake indexer, with the module's Client and `agent-state` bucket (testRealIndexer.hpp). The fake keeps
// no documents: the oracles are the answers (status, timing) and the wire (which requests arrived, in which order,
// holding what).

namespace
{
    using indexer_client::testing::BulkItem;
    using indexer_client::testing::BulkScript;
    using indexer_client::testing::Rule;
    using invsync::test::dbqBody;
    using invsync::test::RealIndexer;

    constexpr auto STATES_DBQ_PATH {"/wazuh-states-.*/_delete_by_query"};

    /// A worker over the real Client: connector = the production adapter, `agent-state` writer and sweeper wired like
    /// the facade wires them. The sweeper's window is long (nothing is swept): what it was note()d is read from
    /// stop()'s `dropped`.
    class ByIdPipeline
    {
    public:
        ByIdPipeline() = default;

        ~ByIdPipeline()
        {
            stop();
        }

        /// Starts runtime, Client, sweeper and pipeline. @p budget is Budgets::deletion (by-query + by-id wait).
        void start(std::chrono::milliseconds budget = std::chrono::seconds {5},
                   const std::function<void(RealIndexer::Specs&)>& tune = {})
        {
            real.startRuntime();
            ASSERT_TRUE(real.runtimeStarted) << real.startError;
            auto specs = RealIndexer::specs();
            if (tune)
            {
                tune(specs);
            }
            ASSERT_TRUE(real.makeClient(specs)) << real.startError;

            sweeper = std::make_shared<invsync::indexer::AgentDeleteSweeper>(
                real.client->query(), std::chrono::hours {1}, std::chrono::seconds {5}, real.closing);

            // Held strongly here, as the facade holds it: the deps only keep it weakly.
            writer = real.agentStateWriter();
            ASSERT_NE(nullptr, writer);
            SyncPipelineConfig config;
            config.agentDeletion = invsync::sync::AgentDeletionDeps {
                true, writer, sweeper, real.closing, budget, std::chrono::milliseconds {250}};
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
                std::shared_ptr<invsync::indexer::IIndexerConnectorSync> {real.makeAdapter()}};
            pipeline = std::make_unique<SyncPipeline>(config, std::move(connectors), CLUSTER);
        }

        void stop()
        {
            if (pipeline)
            {
                pipeline->stop();
                pipeline.reset();
            }
            if (sweeper)
            {
                sweeper->stop();
            }
            writer.reset();
            real.shutdown();
        }

        /// Enqueues a deletion of @p agent and returns its responder.
        std::shared_ptr<FutureResponder> deleteAgent(const std::string& agent)
        {
            auto responder = std::make_shared<FutureResponder>();
            EXPECT_TRUE(pipeline->enqueue(makeDeleteItem(agent, responder)));
            return responder;
        }

        /// Delete-by-query requests received on the states pattern.
        std::size_t statesDbqs() const
        {
            return real.dbqRequests("wazuh-states-*").size();
        }

        /// What the sweeper dropped after stop(): the agents it was note()d and never swept.
        std::uint64_t notedAgents()
        {
            sweeper->stop();
            return sweeper->stats().dropped;
        }

        RealIndexer real;
        std::shared_ptr<indexer_client::IWriter> writer;
        std::shared_ptr<invsync::indexer::AgentDeleteSweeper> sweeper;
        std::unique_ptr<SyncPipeline> pipeline;
    };

    std::int64_t millisSince(std::chrono::steady_clock::time_point start)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    }

    /// Whether the ops of one `_bulk` are exactly the two by-id deletes of @p agent, in scope order.
    bool isByIdDeletePair(const std::vector<indexer_client::testing::BulkOp>& ops, const std::string& agent)
    {
        return ops.size() == 2 && ops[0].action == "delete" && ops[0].index == "wazuh-agent-config" &&
               ops[0].id == agent && ops[1].action == "delete" && ops[1].index == "wazuh-agent-stats" &&
               ops[1].id == agent;
    }
} // namespace

/// Admission refused by the library (here: the Client is closing) is a 503 -- the failure class of ClientClosed --
/// and nothing of the by-query half runs: the Group is refused before it.
TEST(SyncPipelineTest, SubmitRefusedIs503)
{
    ByIdPipeline fixture;
    fixture.start();
    fixture.real.client->requestClose();

    const auto response = fixture.deleteAgent("007")->get();

    EXPECT_EQ(503, response.status) << response.body;
    EXPECT_EQ(0U, fixture.statesDbqs()) << "a refused by-id half stops the deletion before the by-query";
    EXPECT_EQ(0U, fixture.real.bulk->answered());
    EXPECT_EQ(0U, fixture.notedAgents()) << "a failed deletion is not handed to the sweeper";
}

/**
 * The wait: the worker cancels, commits ONE `_bulk` holding both deletes (one Group), runs the by-query, and
 * answers 200 only once the by-id tickets resolved. The bulk is held, the by-query has run, and the caller still has
 * no answer.
 */
TEST(SyncPipelineTest, DeleteWaitsByIdTickets)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::items().held());
    fixture.start();

    auto responder = fixture.deleteAgent("007");

    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.real.bulk->answered() == 1; }));
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.statesDbqs() == 1; }));
    EXPECT_FALSE(responder->answered()) << "a 200 before the by-id tickets would record a purge that has not happened";

    // On the wire: the two deletes travelled together in the one `_bulk` (the Group); which of the bulk and
    // the by-query reaches the indexer first is up to the runtime threads, and is not the contract.
    const auto received = fixture.real.bulk->received();
    ASSERT_EQ(1U, received.size());
    EXPECT_TRUE(isByIdDeletePair(received.front(), "007"));

    fixture.real.fake->releaseHeld();

    EXPECT_EQ(200, responder->get().status);
    EXPECT_EQ(1U, fixture.notedAgents()) << "an accepted deletion is note()d to the sweeper";
}

/// A by-id failure the library resolves Unavailable-class (the bucket's retries ran out) answers 503, and the
/// agent is not handed to the sweeper.
TEST(SyncPipelineTest, ByIdFailureIs503)
{
    ByIdPipeline fixture;
    fixture.real.bulk->setDefault(BulkScript::serverError(503));
    fixture.start(std::chrono::seconds {10}, [](RealIndexer::Specs& specs) { specs.agentState.retry.maxAttempts = 2; });

    const auto response = fixture.deleteAgent("007")->get();

    EXPECT_EQ(503, response.status) << response.body;
    EXPECT_EQ(1U, fixture.statesDbqs()) << "the by-query half ran before the ticket was waited";
    EXPECT_EQ(0U, fixture.notedAgents());
}

/// The budget runs out with the by-id bulk still held: 503 at the deadline (not before, not later than one slice),
/// the by-query already done inside it.
TEST(SyncPipelineTest, ByIdDeadlineCancels)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::items().held());
    fixture.start(std::chrono::seconds {1});

    const auto start = std::chrono::steady_clock::now();
    const auto response = fixture.deleteAgent("007")->get();
    const auto elapsed = millisSince(start);

    EXPECT_EQ(503, response.status) << response.body;
    EXPECT_GE(elapsed, 900) << "answered before the deletion budget";
    EXPECT_LE(elapsed, 1500) << "budget + one wait slice is the most it may take";
    EXPECT_EQ(1U, fixture.statesDbqs());
    EXPECT_EQ(0U, fixture.notedAgents());
}

/// A by-id delete of a missing index (404 index_not_found_exception) is a success, like the by-query half's 404.
TEST(SyncPipelineTest, ByIdIndexMissingIsOk)
{
    ByIdPipeline fixture;
    fixture.real.bulk->setDefault(BulkScript::all(BulkItem::failed(404, "index_not_found_exception")));
    fixture.start();

    const auto response = fixture.deleteAgent("007")->get();

    EXPECT_EQ(200, response.status) << response.body;
    EXPECT_EQ(1U, fixture.notedAgents());
}

/// One deadline for both halves: a slow by-query leaves the by-id wait only what remains of the budget.
TEST(SyncPipelineTest, ByIdAndByQueryShareOneDeadline)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::items().held());
    Rule slowDbq;
    slowDbq.method = "POST";
    slowDbq.pathRegex = STATES_DBQ_PATH;
    slowDbq.body = dbqBody(0);
    slowDbq.latency = std::chrono::milliseconds {1500};
    fixture.real.fake->addRule(std::move(slowDbq));
    fixture.start(std::chrono::seconds {2});

    const auto start = std::chrono::steady_clock::now();
    const auto response = fixture.deleteAgent("007")->get();
    const auto elapsed = millisSince(start);

    EXPECT_EQ(503, response.status) << response.body;
    EXPECT_GE(elapsed, 1900);
    EXPECT_LE(elapsed, 2500) << "by-query + by-id wait must fit one budget, not add two";
}

/// stop() cannot hang for a whole budget behind a held ticket: `closing` is noticed within a slice.
TEST(SyncPipelineTest, ByIdWaitHonoursClosing)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::items().held());
    fixture.start(std::chrono::seconds {30});

    auto responder = fixture.deleteAgent("007");
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.real.bulk->answered() == 1; }));
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.statesDbqs() == 1; }));
    ASSERT_FALSE(responder->answered());

    const auto start = std::chrono::steady_clock::now();
    fixture.real.closing->store(true);
    const auto response = responder->get();

    EXPECT_EQ(503, response.status) << response.body;
    EXPECT_LE(millisSince(start), 500) << "the wait must notice closing within one slice";
}

/// With `closing` set while the by-id bulk is held, the deletion answers 503 AND cancels the agent: the held bulk,
/// answered 503 afterwards, is not retried by the library (without the cancel it would be resent).
TEST(SyncPipelineTest, ByIdClosingCancelsHeldDeletes)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::serverError(503).held());
    fixture.start(std::chrono::seconds {30});

    auto responder = fixture.deleteAgent("007");
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.real.bulk->answered() == 1; }));
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.statesDbqs() == 1; }));
    ASSERT_FALSE(responder->answered());

    fixture.real.closing->store(true);
    EXPECT_EQ(503, responder->get().status);

    fixture.real.fake->releaseHeld(); // The held bulk fails with a 503 the library would retry.
    std::this_thread::sleep_for(std::chrono::milliseconds {600});
    EXPECT_EQ(1U, fixture.real.bulk->received().size()) << "the cancelled deletes must not be resent";
}

/// The same when the budget runs out: 503 and the held deletes are cancelled, not retried after the answer.
TEST(SyncPipelineTest, ByIdDeadlineCancelsHeldDeletes)
{
    ByIdPipeline fixture;
    fixture.real.bulk->push(BulkScript::serverError(503).held());
    fixture.start(std::chrono::seconds {1});

    auto responder = fixture.deleteAgent("007");
    ASSERT_TRUE(invsync::test::waitUntil([&] { return fixture.real.bulk->answered() == 1; }));
    EXPECT_EQ(503, responder->get().status);

    fixture.real.fake->releaseHeld();
    std::this_thread::sleep_for(std::chrono::milliseconds {600});
    EXPECT_EQ(1U, fixture.real.bulk->received().size()) << "the cancelled deletes must not be resent";
}

/// A 404 that is NOT index_not_found_exception is a failure of the by-id half, never a success: a permanent item
/// failure (ItemPermanent -> DocumentRejected), so 500 by the cause-to-HTTP table.
TEST(SyncPipelineTest, ByIdOther404Is500)
{
    ByIdPipeline fixture;
    fixture.real.bulk->setDefault(BulkScript::all(BulkItem::failed(404, "document_missing_exception")));
    fixture.start();

    const auto response = fixture.deleteAgent("007")->get();

    EXPECT_EQ(500, response.status) << response.body;
    EXPECT_EQ(0U, fixture.notedAgents()) << "a failed deletion is not handed to the sweeper";
}

/// Two deletions of one agent, back to back: they run in order on the agent's worker, and the second's cancel(agent)
/// cannot take the first's by-id deletes with it.
TEST(SyncPipelineTest, OverlappingDeletesBothSucceed)
{
    ByIdPipeline fixture;
    fixture.start();

    auto first = fixture.deleteAgent("007");
    auto second = fixture.deleteAgent("007");

    EXPECT_EQ(200, first->get().status);
    EXPECT_EQ(200, second->get().status);
    EXPECT_EQ(2U, fixture.statesDbqs());
    std::size_t pairs {0};
    for (const auto& request : fixture.real.bulk->received())
    {
        pairs += isByIdDeletePair(request, "007") ? 1 : 0;
    }
    EXPECT_EQ(2U, pairs) << "each deletion sent its own pair of by-id deletes";
    EXPECT_EQ(2U, fixture.notedAgents());
}

/// The Group is committed at once, so a deletion does not sit for the bucket's `maxAge` (5 s) like two loose submits.
TEST(SyncPipelineTest, DeleteDoesNotWaitMaxAge)
{
    ByIdPipeline fixture;
    fixture.start(std::chrono::seconds {10},
                  [](RealIndexer::Specs& specs)
                  { ASSERT_EQ(std::chrono::seconds {5}, specs.agentState.bulk.maxAge) << "the production maxAge"; });

    const auto start = std::chrono::steady_clock::now();
    const auto response = fixture.deleteAgent("007")->get();

    EXPECT_EQ(200, response.status) << response.body;
    EXPECT_LT(millisSince(start), 1000);
}

// --- Per-session outcomes of a group commit ------------------------------------------

namespace
{
    /// A batch of exactly @p count sessions behind a parked first one: the first session enters flush()
    /// and waits at the gate, the others queue behind it and are staged as one batch once it opens.
    /// Returns the responders of the @p count batched sessions; the parked one is `parked`.
    std::vector<std::shared_ptr<FutureResponder>> queueABatchBehindAParkedFlush(
        PipelineUnderTest& fixture, std::shared_ptr<FutureResponder>& parked, std::size_t count)
    {
        fixture.events->closeFlushGate();
        parked = std::make_shared<FutureResponder>();
        EXPECT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-parked"), parked)));
        EXPECT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

        std::vector<std::shared_ptr<FutureResponder>> batched;
        for (std::size_t i = 0; i < count; ++i)
        {
            batched.push_back(std::make_shared<FutureResponder>());
            EXPECT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-" + std::to_string(i)), batched.back())));
        }
        return batched;
    }

    std::uint64_t counterOf(const PipelineUnderTest& fixture, const std::string& name)
    {
        return fixture.metrics->getOrCreateCounter(name, "", "count")->get();
    }
} // namespace

/**
 * One flush, three sessions, three different results: the healthy one is answered 200 although the
 * indexer failed its batch-mates, the transient failure 503 and the rejection 500.
 */
TEST(SyncPipelineTest, PerSessionOutcome)
{
    PipelineUnderTest fixture;
    std::shared_ptr<FutureResponder> parked;
    const auto batched = queueABatchBehindAParkedFlush(fixture, parked, 3);
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_scriptedOutcomes = std::vector<invsync::indexer::SessionOutcome> {
            {true, invsync::indexer::ConnectorError::Cause::Other, ""},
            {false, invsync::indexer::ConnectorError::Cause::Unavailable, "no usable node"},
            {false, invsync::indexer::ConnectorError::Cause::DocumentRejected, "mapper_parsing_exception"}};
    }
    fixture.events->openFlushGate();

    EXPECT_EQ(200, parked->get().status) << "the parked batch had one session: not the scripted size";
    EXPECT_EQ(200, batched[0]->get().status);
    const auto transient = batched[1]->get();
    EXPECT_EQ(503, transient.status);
    EXPECT_EQ(R"({"error":"Service unavailable","code":503})", transient.body);
    const auto rejected = batched[2]->get();
    EXPECT_EQ(500, rejected.status);
    EXPECT_EQ(R"({"error":"Internal error","code":500})", rejected.body);

    EXPECT_EQ(2U, counterOf(fixture, invsync::metrics::BULK_SESSIONS_FAILED));
    EXPECT_EQ(1U, counterOf(fixture, std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "unavailable"));
    EXPECT_EQ(1U, counterOf(fixture, std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "documents"));
    EXPECT_EQ(4, fixture.events->m_endSessions.load()) << "every staged session closes its range";
}

/**
 * A connector without per-session results keeps the all-or-nothing contract of flush(): the seam's
 * default flushSessions() answers every session with the flush's own outcome, and a connector that
 * throws fails them all with its cause.
 */
TEST(SyncPipelineTest, DefaultFlushSessionsAllOrNothing)
{
    // The default itself: nothing thrown -> every session succeeds; a typed throw -> every session
    // carries its cause; an untyped one -> Other.
    auto events = std::make_shared<ConnectorEvents>();
    FakeIndexerConnectorSync connector {events, "sync"};
    for (const auto& outcome : connector.flushSessions(3))
    {
        EXPECT_TRUE(outcome.ok);
    }
    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowOn = "flush";
        events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::Unavailable;
    }
    auto typed = connector.flushSessions(3);
    ASSERT_EQ(3U, typed.size());
    for (const auto& outcome : typed)
    {
        EXPECT_FALSE(outcome.ok);
        EXPECT_EQ(invsync::indexer::ConnectorError::Cause::Unavailable, outcome.cause);
    }
    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowCause.reset();
    }
    for (const auto& outcome : connector.flushSessions(2))
    {
        EXPECT_FALSE(outcome.ok);
        EXPECT_EQ(invsync::indexer::ConnectorError::Cause::Other, outcome.cause);
    }

    // Through the pipeline: a flush that throws fails the whole batch, each session with that cause.
    PipelineUnderTest fixture;
    std::shared_ptr<FutureResponder> parked;
    const auto batched = queueABatchBehindAParkedFlush(fixture, parked, 3);
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::Unavailable;
    }
    fixture.events->openFlushGate();

    EXPECT_EQ(503, parked->get().status);
    for (const auto& responder : batched)
    {
        EXPECT_EQ(503, responder->get().status);
    }
    EXPECT_EQ(4U, counterOf(fixture, invsync::metrics::BULK_SESSIONS_FAILED));
    EXPECT_EQ(4U, counterOf(fixture, std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "unavailable"));
}

/**
 * An exception foreign to the connector while staging leaves the open batch in an unknown state: every
 * session of it is answered 500 and the staged operations are DISCARDED, never sent.
 */
TEST(SyncPipelineTest, PoisonedBatchDiscards)
{
    PipelineUnderTest fixture;
    fixture.events->closeFlushGate();

    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-parked"), parked)));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_flushEntered.load() == 1; }));

    // Behind the parked flush: a healthy session that stages into the open batch, then one whose
    // staging throws a plain runtime_error.
    auto healthy = std::make_shared<FutureResponder>();
    auto poisoned = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-healthy"), healthy)));
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-poison"), poisoned)));
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "bulkIndex";
        fixture.events->m_syncThrowOnIdContaining = "doc-poison";
    }
    fixture.events->openFlushGate();

    EXPECT_EQ(200, parked->get().status);
    EXPECT_EQ(500, healthy->get().status) << "the batch around the poison is answered with it";
    EXPECT_EQ(500, poisoned->get().status);

    EXPECT_EQ(1, fixture.events->m_discards.load());
    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "only the parked batch flushed; the poisoned one was dropped";
    EXPECT_EQ(2U, counterOf(fixture, invsync::metrics::BULK_SESSIONS_FAILED));
}
