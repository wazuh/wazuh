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
// they are read by pull at GET /metrics from the bucket's own counters (I140); metricsEndpoint_test.cpp's
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
    // The retry budget ran out on a retryable condition: the agent is told to come back (I135).
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

/// isAvailable() no longer decides the code after a failure (I135): the cause alone does. An untyped
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
     * AGENT_DELETION_SCOPE_BY_QUERY, and NOTHING else. Exactly one op is the assertion that matters
     * here: `wazuh-agent-config` and `wazuh-agent-stats` are deliberately NOT deleted from this
     * connector -- they are written by the async one, and a delete-by-query issued here could
     * neither drain its queue nor see an unrefreshed document, which is how a report in flight used
     * to outlive the agent. The endpoint queues their deletes by id on that connector instead
     * (deleteAgentEndpoint_test.cpp pins it).
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

// --- Per-session outcomes of a group commit (I136, I135) ------------------------------------------

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
 * indexer failed its batch-mates, the transient failure 503 and the rejection 500 (I135, I136).
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
 * throws fails them all with its cause (I136).
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
 * session of it is answered 500 and the staged operations are DISCARDED, never sent (I142).
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
