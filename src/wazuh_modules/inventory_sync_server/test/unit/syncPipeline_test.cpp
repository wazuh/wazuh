/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/syncPipeline.hpp"

#include "sync/fullSessionValidator.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::sync::SyncPipeline;
using invsync::sync::SyncPipelineConfig;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::SessionSpec;
using invsync::test::ValueSpec;

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

        auto result = invsync::sync::validateFullSession(request->body, "1", CLUSTER);
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

    struct PipelineUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::unique_ptr<SyncPipeline> pipeline;

        explicit PipelineUnderTest(std::size_t workers = 1, SyncPipelineConfig config = {})
        {
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors;
            connectors.reserve(workers);
            for (std::size_t i = 0; i < workers; ++i)
            {
                connectors.push_back(std::make_shared<FakeIndexerConnectorSync>(events, "sync"));
            }
            pipeline = std::make_unique<SyncPipeline>(config, std::move(connectors), CLUSTER);
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

TEST(SyncPipelineTest, FlushFailureMapsTo503WhenTheConnectorIsUnavailable)
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

    EXPECT_EQ(503, responder->get().status) << "an indexer outage is retriable, so 503, not 500";
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

TEST(SyncPipelineTest, AnImmediateSessionFailureMapsByAvailability)
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
    EXPECT_EQ(500, healthy->get().status);

    fixture.events->m_syncAvailable.store(false);
    // The dispatch gate now rejects before the processor runs; that is the 503 the agent sees.
    auto unavailable = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(invsync::test::buildBareSession(spec), unavailable)));
    EXPECT_EQ(503, unavailable->get().status);
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

// --- DeleteAgent items (DELETE /agents, design doc 04) ------------------------------------------

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

TEST(SyncPipelineTest, ADeleteAgentItemWipesTheWholeScopeAndFlushes)
{
    PipelineUnderTest fixture;
    auto responder = std::make_shared<FutureResponder>();

    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("005", responder)));

    const auto response = responder->get();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);

    // One delete-by-query per index of the scope, and nothing else: the deletion does NOT refresh
    // first (that needs a privilege the manager's indexer role lacks), which is why a document
    // written inside the index refresh interval can survive it.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(3U, ops.size());

    const std::vector<std::string> scope {"wazuh-states-*", "wazuh-agent-config", "wazuh-agent-stats"};
    for (std::size_t i = 0; i < scope.size(); ++i)
    {
        const auto& deletion = ops[i];
        EXPECT_EQ("deleteByQuery", std::get<0>(deletion));
        EXPECT_EQ("005", std::get<1>(deletion));
        EXPECT_EQ(scope[i], std::get<2>(deletion)) << "the config and stats indices live outside wazuh-states-*";
        EXPECT_EQ(CLUSTER, std::get<3>(deletion)) << "scoped to this cluster";
    }

    EXPECT_EQ(1, fixture.events->m_syncFlushes.load()) << "the 200 means every delete was FLUSHED, in one go";
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

    // Exact, not just non-empty: the assertions below index ops[1], so a regression that collapsed
    // the deletion to a single op would read out of bounds instead of failing. One bulkIndex for the
    // delta, then one delete-by-query per index of the deletion scope.
    const auto ops = fixture.events->syncOps();
    ASSERT_EQ(4U, ops.size());
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0])) << "the delta's write reaches the indexer first";
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[1])) << "and the deletion follows it, never the other way round";
    EXPECT_EQ("deleteByQuery", std::get<0>(ops.back()));
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

    fixture.events->m_syncThrowOn.clear();
    fixture.events->m_syncAvailable.store(false);
    auto second = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeDeleteItem("006", second)));
    EXPECT_EQ(503, second->get().status) << "indexer unavailable at dispatch -> 503, nothing executed";
}
