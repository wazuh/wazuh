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
#include "common/responseBudget.hpp"
#include "sync/fullSessionValidator.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
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

/**
 * The duration histograms subtract Item::enqueuedAt from the pipeline's own clock. If that clock
 * stayed the real steady_clock while a test (or the endpoint) stamped enqueuedAt from an injected
 * one, every sample would be the time since the machine booted instead of the session's own, and
 * nothing in the suite would notice. Pin the exact sample.
 */
TEST(SyncPipelineTest, TheDurationHistogramUsesTheInjectedClock)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    auto events = std::make_shared<ConnectorEvents>();
    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};

    const auto base = std::chrono::steady_clock::now();
    SyncPipelineConfig config;
    config.now = [base]
    {
        return base;
    }; // frozen: the sample is a pure function of enqueuedAt
    SyncPipeline pipeline {config, std::move(connectors), CLUSTER, nullptr, metrics};

    auto responder = std::make_shared<FutureResponder>();
    auto item = makeItem(deltaBody("doc-1"), responder);
    item.enqueuedAt = base - std::chrono::seconds {30};
    ASSERT_TRUE(pipeline.enqueue(std::move(item)));
    EXPECT_EQ(200, responder->get().status);

    const auto duration =
        std::dynamic_pointer_cast<wazuh::metrics::IHistogram>(metrics->get(invsync::metrics::SESSION_DURATION_BULK));
    ASSERT_NE(nullptr, duration);
    const auto snapshot = duration->snapshot();
    ASSERT_EQ(1U, snapshot.count);
    EXPECT_EQ(30000000.0, snapshot.max) << "30 s of injected clock, in microseconds";
}

/// Shorthand for the three deadline metrics a refusal must move (or leave alone).
namespace
{
    uint64_t counterValue(const std::shared_ptr<wazuh::metrics::Manager>& metrics, const char* name)
    {
        return static_cast<uint64_t>(metrics->get(name)->value());
    }

    wazuh::metrics::IHistogram::Snapshot histogramOf(const std::shared_ptr<wazuh::metrics::Manager>& metrics,
                                                     const char* name)
    {
        const auto histogram = std::dynamic_pointer_cast<wazuh::metrics::IHistogram>(metrics->get(name));
        return histogram ? histogram->snapshot() : wazuh::metrics::IHistogram::Snapshot {};
    }
} // namespace

/**
 * RF-5: a copy that waited longer than remoted will listen must not START. It is withdrawn at
 * dispatch, before anything of it reaches the connector's buffer, and it is NOT timed: a session
 * that did no work would dilute the duration histogram the reference run reads.
 */
TEST(SyncPipelineTest, ABulkPastItsDeadlineIsRefusedAtDispatch)
{
    const auto base = std::chrono::steady_clock::now();
    std::atomic<int64_t> offsetUs {0};
    SyncPipelineConfig config;
    config.now = [&base, &offsetUs]
    {
        return base + std::chrono::microseconds {offsetUs.load()};
    };

    auto events = std::make_shared<ConnectorEvents>();
    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    SyncPipeline pipeline {config, std::move(connectors), CLUSTER, nullptr, metrics};

    // X parks the worker inside flush(); A is queued behind it with a deadline that the test then
    // lets expire, so A is judged on its way out of the queue.
    events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return events->m_flushEntered.load() == 1; }));

    auto responder = std::make_shared<FutureResponder>();
    auto item = makeItem(deltaBody("doc-1"), responder);
    item.enqueuedAt = base;
    item.budget = std::chrono::milliseconds {20000};
    item.deadline = base + item.budget;
    ASSERT_TRUE(pipeline.enqueue(std::move(item)));

    offsetUs.store(std::chrono::microseconds {std::chrono::seconds {40}}.count());
    const auto durationBefore = histogramOf(metrics, invsync::metrics::SESSION_DURATION_BULK).count;
    events->openFlushGate();

    const auto response = responder->get();
    EXPECT_EQ(503, response.status);
    EXPECT_EQ(invsync::common::DEADLINE_EXPIRED_BODY, response.body);
    EXPECT_TRUE(std::none_of(response.headers.begin(),
                             response.headers.end(),
                             [](const auto& header) { return header.first == "Retry-After"; }))
        << "no Retry-After: nothing was applied, so an immediate re-send is correct";
    EXPECT_EQ(1U, counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK));
    EXPECT_EQ(0U, counterValue(metrics, invsync::metrics::DEADLINE_OVERRUN_PIPELINE_BULK))
        << "withdrawn before reaching the indexer: expired, never overrun";
    EXPECT_EQ(1U, counterValue(metrics, "sync.requests.total.503"));
    EXPECT_EQ(durationBefore, histogramOf(metrics, invsync::metrics::SESSION_DURATION_BULK).count)
        << "a withdrawn session is not timed";
    EXPECT_EQ(1U, histogramOf(metrics, invsync::metrics::SESSION_QUEUE_WAIT).count) << "but its wait IS sampled";
    const auto ops = events->syncOps();
    EXPECT_TRUE(std::none_of(
        ops.begin(), ops.end(), [](const auto& op) { return std::get<3>(op).find("doc-1") != std::string::npos; }))
        << "nothing of the withdrawn session reached the connector";
}

/// G-crear r3 P2-1: the deadline check goes BEFORE the indexer re-check, so an expired copy is
/// reported as expired and not as unavailability -- otherwise a held indexer would hide the metric.
TEST(SyncPipelineTest, ARefusedCopyStillComesOutAsExpiredWhenTheIndexerIsDown)
{
    const auto base = std::chrono::steady_clock::now();
    std::atomic<int64_t> offsetUs {0};
    SyncPipelineConfig config;
    config.now = [&base, &offsetUs]
    {
        return base + std::chrono::microseconds {offsetUs.load()};
    };

    auto events = std::make_shared<ConnectorEvents>();
    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    SyncPipeline pipeline {config, std::move(connectors), CLUSTER, nullptr, metrics};

    events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return events->m_flushEntered.load() == 1; }));

    auto responder = std::make_shared<FutureResponder>();
    auto item = makeItem(deltaBody("doc-1"), responder);
    item.enqueuedAt = base;
    item.budget = std::chrono::milliseconds {20000};
    item.deadline = base + item.budget;
    ASSERT_TRUE(pipeline.enqueue(std::move(item)));

    offsetUs.store(std::chrono::microseconds {std::chrono::seconds {40}}.count());
    events->m_syncAvailable.store(false);
    events->openFlushGate();

    EXPECT_EQ(invsync::common::DEADLINE_EXPIRED_BODY, responder->get().body);
    EXPECT_EQ(1U, counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK));
}

/**
 * RF-5, second seam: an immediate session passes the dispatch check with time to spare, but the
 * batch cut's flush is itself unbounded -- by the time it returns, nobody may be listening. The
 * test clock reads the fake's own flush counter, so the 40 s jump lands exactly between the two
 * checks without re-closing any gate.
 */
TEST(SyncPipelineTest, AnImmediateIsRefusedAfterTheBatchCutFlush)
{
    const auto base = std::chrono::steady_clock::now();
    auto events = std::make_shared<ConnectorEvents>();
    SyncPipelineConfig config;
    config.now = [&base, events]
    {
        return base + (events->m_flushEntered.load() >= 2 ? std::chrono::seconds {40} : std::chrono::seconds {0});
    };

    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    SyncPipeline pipeline {config, std::move(connectors), CLUSTER, nullptr, metrics};

    // X drains the queue and parks inside the first flush (counter 1), so A and B are queued with
    // the worker stopped: no race.
    events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return events->m_flushEntered.load() == 1; }));

    auto bulkResponder = std::make_shared<FutureResponder>();
    auto bulk = makeItem(deltaBody("doc-a"), bulkResponder);
    bulk.enqueuedAt = base;
    ASSERT_TRUE(pipeline.enqueue(std::move(bulk)));

    auto immediateResponder = std::make_shared<FutureResponder>();
    // A Cleans session: classify() calls it immediate, so it takes the batch-cut path. buildBare
    // would not do -- its payload is NONE and the validator rejects it.
    auto immediate = makeItem(invsync::test::buildCleansSession(SessionSpec {}, {"wazuh-states-inventory-packages"}),
                              immediateResponder);
    immediate.enqueuedAt = base;
    immediate.budget = std::chrono::milliseconds {20000};
    immediate.deadline = base + immediate.budget;
    ASSERT_TRUE(pipeline.enqueue(std::move(immediate)));

    events->openFlushGate();

    EXPECT_EQ(200, parked->get().status);
    EXPECT_EQ(200, bulkResponder->get().status) << "the bulk was staged before the cut and is answered normally";
    const auto response = immediateResponder->get();
    EXPECT_EQ(503, response.status) << "refused AFTER the cut flush, not at dispatch";
    EXPECT_EQ(invsync::common::DEADLINE_EXPIRED_BODY, response.body);
    EXPECT_EQ(1U, counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_IMMEDIATE));
    EXPECT_EQ(0U, counterValue(metrics, invsync::metrics::DEADLINE_OVERRUN_PIPELINE_IMMEDIATE))
        << "its by-query never started: expired, never overrun";
    const auto ops = events->syncOps();
    // A Cleans session's indexer work is a deleteByQuery (sessionProcessor.cpp), and the fake
    // records it under that exact name: asserting on "updateByQuery" would pass with the
    // production broken, because nothing ever registers that string.
    EXPECT_TRUE(std::none_of(
        ops.begin(),
        ops.end(),
        [](const auto& op) { return std::get<0>(op) == "deleteByQuery" || std::get<0>(op) == "executeUpdateByQuery"; }))
        << "its by-query never started";
}

/**
 * The queue wait is what the deadline is spent on, so EVERY dispatched /stateful session samples
 * it -- withdrawn ones included. Nothing else does: a DeleteAgent carries no session, and an item
 * nobody stamped has no wait to report (in production the endpoint always stamps; the sample sits
 * after the shutdown re-check, so what the drain answers never reaches the histogram).
 */
TEST(SyncPipelineTest, QueueWaitSamplesEveryDispatchedSessionAndNothingElse)
{
    PipelineUnderTest fixture;
    const auto base = std::chrono::steady_clock::now();

    auto first = std::make_shared<FutureResponder>();
    auto stamped = makeItem(deltaBody("doc-1"), first);
    stamped.enqueuedAt = base - std::chrono::seconds {3};
    ASSERT_TRUE(fixture.pipeline->enqueue(std::move(stamped)));
    EXPECT_EQ(200, first->get().status);

    auto second = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-2"), second))); // unstamped
    EXPECT_EQ(200, second->get().status);

    auto third = std::make_shared<FutureResponder>();
    auto purge = makeItem(deltaBody("doc-3"), third);
    purge.kind = SyncPipeline::Item::Kind::DeleteAgent;
    purge.enqueuedAt = base - std::chrono::seconds {3};
    ASSERT_TRUE(fixture.pipeline->enqueue(std::move(purge)));
    third->get();

    EXPECT_EQ(1U, histogramOf(fixture.metrics, invsync::metrics::SESSION_QUEUE_WAIT).count)
        << "only the stamped session sampled";
    EXPECT_EQ(0U, counterValue(fixture.metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK));
    EXPECT_EQ(0U, counterValue(fixture.metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_IMMEDIATE));
}

/// An item dispatched after stop() has set m_stopping is answered "shutting down" BEFORE the
/// deadline check: it was never worked on, so whatever its deadline says it moves neither deadline
/// counter. (What this pins is the order of the dispatch checks, not stop()'s own queue sweep.)
TEST(SyncPipelineTest, AnItemDispatchedDuringShutdownMovesNoDeadlineCounter)
{
    auto events = std::make_shared<ConnectorEvents>();
    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    const auto base = std::chrono::steady_clock::now();
    SyncPipelineConfig config;
    config.now = [&base]
    {
        return base + std::chrono::seconds {40};
    }; // every deadline below is past

    auto pipeline = std::make_unique<SyncPipeline>(config, std::move(connectors), CLUSTER, nullptr, metrics);
    events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline->enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return events->m_flushEntered.load() == 1; }));

    auto queued = std::make_shared<FutureResponder>();
    auto item = makeItem(deltaBody("doc-1"), queued);
    item.enqueuedAt = base;
    item.budget = std::chrono::milliseconds {20000};
    item.deadline = base + item.budget; // already past, per the clock above
    ASSERT_TRUE(pipeline->enqueue(std::move(item)));

    // Deterministic: stop() runs on another thread (it joins the workers), and enqueue() refusing
    // is the observable sign that m_stopping is set -- only THEN is the worker let go. Opening the
    // gate first would race: a worker that wins dispatches the expired item and counts it.
    std::thread stopper([&pipeline] { pipeline->stop(); });
    std::vector<std::shared_ptr<FutureResponder>> probes;
    const bool stopping = waitFor(
        [&]
        {
            probes.push_back(std::make_shared<FutureResponder>());
            return !pipeline->enqueue(makeItem(deltaBody("probe"), probes.back()));
        });
    // Release and join BEFORE asserting: an ASSERT with `stopper` still joinable would call
    // std::terminate and take the whole binary down instead of failing this one test.
    events->openFlushGate();
    stopper.join();
    ASSERT_TRUE(stopping);

    const auto response = queued->get();
    EXPECT_EQ(503, response.status);
    EXPECT_EQ(R"({"error":"Service unavailable","code":503})", response.body);
    EXPECT_EQ(0U, counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK))
        << "a drained item was never dispatched: the deadline counters stay put";
    EXPECT_EQ(0U, counterValue(metrics, invsync::metrics::DEADLINE_OVERRUN_PIPELINE_BULK))
        << "nor did it reach the indexer";
}

namespace
{
    /**
     * A pipeline on an injectable clock with its own fakes and metrics. The destructor opens every
     * gate BEFORE the pipeline is destroyed: a test that aborts with a worker parked inside a
     * connector call would otherwise hang the pipeline's join forever (members are destroyed in
     * reverse order, so `pipeline` goes after this body runs).
     */
    struct DeadlineRig
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<wazuh::metrics::Manager> metrics {std::make_shared<wazuh::metrics::Manager>()};
        std::chrono::steady_clock::time_point base {std::chrono::steady_clock::now()};
        std::shared_ptr<std::atomic<int64_t>> offsetUs {std::make_shared<std::atomic<int64_t>>(0)};
        std::unique_ptr<SyncPipeline> pipeline;

        DeadlineRig()
        {
            SyncPipelineConfig config;
            const auto start = base;
            auto offset = offsetUs;
            config.now = [start, offset]
            {
                return start + std::chrono::microseconds {offset->load()};
            };
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
                std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
            pipeline = std::make_unique<SyncPipeline>(config, std::move(connectors), CLUSTER, nullptr, metrics);
        }

        ~DeadlineRig()
        {
            events->openAllGates();
        }

        void advance(std::chrono::seconds by)
        {
            offsetUs->fetch_add(std::chrono::microseconds {by}.count());
        }

        /// An item stamped at `base` with a 20 s budget: it passes any check made before advance().
        SyncPipeline::Item withDeadline(std::string body, std::shared_ptr<FutureResponder> responder)
        {
            auto item = makeItem(std::move(body), std::move(responder));
            item.enqueuedAt = base;
            item.budget = std::chrono::milliseconds {20000};
            item.deadline = base + item.budget;
            return item;
        }

        uint64_t overrunBulk() const
        {
            return counterValue(metrics, invsync::metrics::DEADLINE_OVERRUN_PIPELINE_BULK);
        }
        uint64_t overrunImmediate() const
        {
            return counterValue(metrics, invsync::metrics::DEADLINE_OVERRUN_PIPELINE_IMMEDIATE);
        }
        uint64_t expiredAll() const
        {
            return counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK) +
                   counterValue(metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_IMMEDIATE);
        }
    };

    void injectThrow(const std::shared_ptr<ConnectorEvents>& events, const char* seam)
    {
        std::lock_guard<std::mutex> lock(events->m_mutex);
        events->m_syncThrowOn = seam;
    }

    std::string cleansBody()
    {
        return invsync::test::buildCleansSession(SessionSpec {}, {"wazuh-states-inventory-packages"});
    }
} // namespace

/**
 * RF-7: a bulk that passed dispatch with time to spare is NOT interrupted when its group flush runs
 * past the deadline -- it is applied and answered normally, and counted as overrun: the duplicated
 * work the deadline could not prevent. A failed flush counts the same, through the connector-failure
 * answer, because the operations had already reached the buffer.
 */
TEST(SyncPipelineTest, ABulkWhoseFlushOutlivesItsDeadlineCountsAsOverrun)
{
    for (const bool flushFails : {false, true})
    {
        DeadlineRig rig;
        rig.events->closeFlushGate();
        auto responder = std::make_shared<FutureResponder>();
        ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(deltaBody("doc-1"), responder)));
        ASSERT_TRUE(waitFor([&] { return rig.events->m_flushEntered.load() == 1; }));

        if (flushFails)
        {
            injectThrow(rig.events, "flush");
        }
        rig.advance(std::chrono::seconds {40});
        rig.events->openFlushGate();

        EXPECT_EQ(flushFails ? 500 : 200, responder->get().status) << "flushFails=" << flushFails;
        EXPECT_EQ(1U, rig.overrunBulk()) << "flushFails=" << flushFails;
        EXPECT_EQ(0U, rig.expiredAll()) << "it started in time: never withdrawn";
    }
}

/// The immediate counterpart: a Cleans parks in its OWN flush (the batch cut with an empty batch
/// does not flush), which is after the post-cut re-check. A failure there is marked by the catch.
TEST(SyncPipelineTest, AnImmediateWhoseWorkOutlivesItsDeadlineCountsAsOverrun)
{
    for (const bool flushFails : {false, true})
    {
        DeadlineRig rig;
        rig.events->closeFlushGate();
        auto responder = std::make_shared<FutureResponder>();
        ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(cleansBody(), responder)));
        ASSERT_TRUE(waitFor([&] { return rig.events->m_flushEntered.load() == 1; }));

        if (flushFails)
        {
            injectThrow(rig.events, "flush");
        }
        rig.advance(std::chrono::seconds {40});
        rig.events->openFlushGate();

        EXPECT_EQ(flushFails ? 500 : 200, responder->get().status) << "flushFails=" << flushFails;
        EXPECT_EQ(1U, rig.overrunImmediate()) << "flushFails=" << flushFails;
        EXPECT_EQ(0U, rig.expiredAll());
    }
}

/// No deadline, no overrun -- however late the answer.
TEST(SyncPipelineTest, ASessionWithoutDeadlineNeverCountsOverrun)
{
    DeadlineRig rig;
    rig.events->closeFlushGate();
    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));
    ASSERT_TRUE(waitFor([&] { return rig.events->m_flushEntered.load() == 1; }));
    rig.advance(std::chrono::seconds {40});
    rig.events->openFlushGate();

    EXPECT_EQ(200, responder->get().status);
    EXPECT_EQ(0U, rig.overrunBulk());
}

/**
 * RF-8: the copy that waited in the queue past its deadline is withdrawn, and the agent's re-send
 * -- fresh deadline -- is applied once. Nothing of the first copy reached the indexer, so it is
 * expired, not overrun.
 */
TEST(SyncPipelineTest, AQueuedCopyIsRefusedAndItsResendApplies)
{
    DeadlineRig rig;
    rig.events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return rig.events->m_flushEntered.load() == 1; }));

    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(deltaBody("doc-1"), first)));
    rig.advance(std::chrono::seconds {40});
    rig.events->openFlushGate();
    EXPECT_EQ(503, first->get().status);

    auto resend = std::make_shared<FutureResponder>();
    auto again = makeItem(deltaBody("doc-1"), resend);
    const auto now = rig.base + std::chrono::seconds {40};
    again.enqueuedAt = now;
    again.budget = std::chrono::milliseconds {20000};
    again.deadline = now + again.budget;
    ASSERT_TRUE(rig.pipeline->enqueue(std::move(again)));
    EXPECT_EQ(200, resend->get().status);

    const auto ops = rig.events->syncOps();
    EXPECT_EQ(
        1,
        std::count_if(ops.begin(),
                      ops.end(),
                      [](const auto& op)
                      { return std::get<0>(op) == "bulkIndex" && std::get<1>(op).find("doc-1") != std::string::npos; }))
        << "doc-1 indexed exactly once: by the re-send";
    EXPECT_EQ(1U, counterValue(rig.metrics, invsync::metrics::DEADLINE_EXPIRED_PIPELINE_BULK));
    EXPECT_EQ(0U, rig.overrunBulk());
}

/**
 * RF-8b (D13): a copy whose by-query ITSELF outlives the deadline is not refused -- it had started
 * in time and nothing is cut mid-flight -- so both it and the re-send run, once each, and the first
 * is what overrun counts. Two instances, each with its own fakes, stand in for two nodes.
 */
TEST(SyncPipelineTest, ACopyWhoseByQueryItselfOutlivesTheDeadlineIsNotRefused)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_GroupDelta;
    spec.indices = {"wazuh-states-inventory-packages"};
    const auto body = invsync::test::buildBareSession(spec);

    DeadlineRig firstNode;
    firstNode.events->closeGate(firstNode.events->m_updateByQueryGate);
    auto first = std::make_shared<FutureResponder>();
    ASSERT_TRUE(firstNode.pipeline->enqueue(firstNode.withDeadline(body, first)));
    ASSERT_TRUE(waitFor([&] { return firstNode.events->m_updateByQueryGate.entered.load() == 1; }));
    firstNode.advance(std::chrono::seconds {40});

    DeadlineRig secondNode;
    auto resend = std::make_shared<FutureResponder>();
    ASSERT_TRUE(secondNode.pipeline->enqueue(secondNode.withDeadline(body, resend)));
    EXPECT_EQ(200, resend->get().status);

    firstNode.events->openGate(firstNode.events->m_updateByQueryGate);
    EXPECT_EQ(200, first->get().status);

    for (const auto* node : {&firstNode, &secondNode})
    {
        const auto ops = node->events->syncOps();
        EXPECT_EQ(1,
                  std::count_if(
                      ops.begin(), ops.end(), [](const auto& op) { return std::get<0>(op) == "executeUpdateByQuery"; }))
            << "the by-query ran once per instance";
        EXPECT_EQ(0U, node->expiredAll());
    }
    EXPECT_EQ(1U, firstNode.overrunImmediate()) << "the copy answered past its deadline";
    EXPECT_EQ(0U, secondNode.overrunImmediate());
}

/**
 * The staging-failure path answers the session that threw AND the open batch. The batch was marked
 * when staged; the one that threw must be marked there, because its bulkIndex may already have
 * auto-flushed a real request. A stages through bulkDelete (no gate, no injection) so the batch is
 * genuinely open when B throws.
 */
TEST(SyncPipelineTest, AStagingFailureCountsTheSessionThatThrew)
{
    DeadlineRig rig;
    rig.events->closeFlushGate();
    auto parked = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(makeItem(deltaBody("doc-x"), parked)));
    ASSERT_TRUE(waitFor([&] { return rig.events->m_flushEntered.load() == 1; }));
    rig.events->closeGate(rig.events->m_bulkIndexGate);
    // X's own bulkIndex already counted an entry (the gate was open then): wait for one MORE.
    const auto before = rig.events->m_bulkIndexGate.entered.load();

    ValueSpec deletion;
    deletion.id = "doc-a";
    deletion.operation = invsync::test::fb::Operation_Delete;
    auto stagedResponder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(
        rig.withDeadline(invsync::test::buildSyncDataSession(SessionSpec {}, {deletion}), stagedResponder)));
    auto throwingResponder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(deltaBody("doc-b"), throwingResponder)));

    injectThrow(rig.events, "bulkIndex");
    rig.events->openFlushGate();
    ASSERT_TRUE(waitFor([&] { return rig.events->m_bulkIndexGate.entered.load() > before; }));
    rig.advance(std::chrono::seconds {40});
    rig.events->openGate(rig.events->m_bulkIndexGate);

    EXPECT_EQ(200, parked->get().status);
    EXPECT_EQ(500, throwingResponder->get().status);
    EXPECT_EQ(500, stagedResponder->get().status);
    EXPECT_EQ(2U, rig.overrunBulk()) << "the open batch AND the session that threw";
}

/// A checksum only READS, so however late it answers it is not duplicated work -- on its success
/// path (here a 409: the canned empty search sums differently) and on its failure path alike.
TEST(SyncPipelineTest, AChecksumOnlyReadsSoItNeverCountsOverrun)
{
    for (const bool searchFails : {false, true})
    {
        DeadlineRig rig;
        SessionSpec spec;
        spec.mode = invsync::test::fb::Mode_ModuleCheck;
        rig.events->closeGate(rig.events->m_searchGate);
        auto responder = std::make_shared<FutureResponder>();
        ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(
            invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "claimed"), responder)));
        ASSERT_TRUE(waitFor([&] { return rig.events->m_searchGate.entered.load() == 1; }));

        if (searchFails)
        {
            injectThrow(rig.events, "executeSearchQuery");
        }
        rig.advance(std::chrono::seconds {40});
        rig.events->openGate(rig.events->m_searchGate);

        EXPECT_EQ(searchFails ? 500 : 409, responder->get().status)
            << "searchFails=" << searchFails << " -- 409 proves the success path ran";
        EXPECT_EQ(0U, rig.overrunImmediate()) << "searchFails=" << searchFails;
    }
}

/**
 * The shutdown abandon answers the staged batch 503 -- and those sessions DID reach the buffer, so
 * past their deadline they are overrun. stop() runs on another thread (it joins the workers), and
 * enqueue() refusing is the observable sign that m_stopping is set before the worker resumes.
 */
TEST(SyncPipelineTest, AStagedSessionAbandonedAtShutdownCountsOverrun)
{
    DeadlineRig rig;
    rig.events->closeGate(rig.events->m_bulkIndexGate);
    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(rig.pipeline->enqueue(rig.withDeadline(deltaBody("doc-1"), responder)));
    ASSERT_TRUE(waitFor([&] { return rig.events->m_bulkIndexGate.entered.load() == 1; }));
    rig.advance(std::chrono::seconds {40});

    std::thread stopper([&rig] { rig.pipeline->stop(); });
    std::vector<std::shared_ptr<FutureResponder>> probes;
    const bool stopping = waitFor(
        [&]
        {
            probes.push_back(std::make_shared<FutureResponder>());
            return !rig.pipeline->enqueue(makeItem(deltaBody("probe"), probes.back()));
        });
    rig.events->openGate(rig.events->m_bulkIndexGate); // release and join before asserting
    stopper.join();
    ASSERT_TRUE(stopping);

    const auto response = responder->get();
    EXPECT_EQ(503, response.status);
    EXPECT_EQ(R"({"error":"Service unavailable","code":503})", response.body)
        << "answered by the shutdown abandon, not withdrawn by the deadline";
    EXPECT_EQ(1U, rig.overrunBulk());
}

/**
 * R-08 observability: sync.bulk.flushes counts group commits, but one group commit can be several
 * real `_bulk` requests (splits, retries, auto-flushes). The pipeline drains the connector's own
 * request counts after every flush so the metrics carry the real traffic too.
 */
TEST(SyncPipelineTest, TheConnectorsRealBulkRequestsReachTheMetrics)
{
    auto metrics = std::make_shared<wazuh::metrics::Manager>();
    auto events = std::make_shared<ConnectorEvents>();
    events->m_bulkStatsRequests = 3;
    events->m_bulkStatsBytes = 4096;
    events->m_bulkStatsConflictRetries = 2;

    std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {
        std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
    SyncPipeline pipeline {SyncPipelineConfig {}, std::move(connectors), CLUSTER, nullptr, metrics};

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(pipeline.enqueue(makeItem(deltaBody("doc-1"), responder)));
    EXPECT_EQ(200, responder->get().status);

    const auto requests = metrics->getOrCreateCounter(invsync::metrics::INDEXER_BULK_REQUESTS, "", "count");
    const auto bytes = metrics->getOrCreateCounter(invsync::metrics::INDEXER_BULK_BYTES, "", "bytes");
    const auto conflictRetries = metrics->getOrCreateCounter(invsync::metrics::INDEXER_CONFLICT_RETRIES, "", "count");
    EXPECT_EQ(3U, requests->get());
    EXPECT_EQ(4096U, bytes->get());
    EXPECT_EQ(2U, conflictRetries->get());
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
    EXPECT_EQ(500, first->get().status);

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

namespace
{
    constexpr auto PACKAGES_INDEX {"wazuh-states-inventory-packages"};

    /// Queues a checksum session on @p fixture and returns its response.
    HttpResponse answerChecksumSession(PipelineUnderTest& fixture)
    {
        SessionSpec spec;
        spec.mode = invsync::test::fb::Mode_ModuleCheck;
        auto responder = std::make_shared<FutureResponder>();
        EXPECT_TRUE(fixture.pipeline->enqueue(
            makeItem(invsync::test::buildChecksumSession(spec, PACKAGES_INDEX, "deadbeef"), responder)));
        return responder->get();
    }

    /// Whether the response carries the header at all, whatever its value. Field names are
    /// case-insensitive in HTTP, so the comparison is too.
    bool hasHeader(const HttpResponse& response, const std::string& name)
    {
        const auto sameName = [&name](const std::string& key)
        {
            return key.size() == name.size() &&
                   std::equal(key.begin(),
                              key.end(),
                              name.begin(),
                              [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); });
        };
        for (const auto& [key, value] : response.headers)
        {
            if (sameName(key))
            {
                return true;
            }
        }
        return false;
    }

    std::uint64_t counterOf(PipelineUnderTest& fixture, const std::string& name)
    {
        return fixture.metrics->getOrCreateCounter(name, "", "count")->get();
    }

    constexpr auto UNAVAILABLE_BODY {R"({"error":"Service unavailable","code":503})"};
    constexpr auto INTERNAL_BODY {R"({"error":"Internal error","code":500})"};
} // namespace

TEST(SyncPipelineTest, AChecksumReadRefusedByTheIndexerAnswers503)
{
    PipelineUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "executeSearchQuery";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::IndexerUnavailable;
    }

    const auto response = answerChecksumSession(fixture);

    EXPECT_EQ(503, response.status);
    EXPECT_EQ(UNAVAILABLE_BODY, response.body);
    EXPECT_FALSE(hasHeader(response, "Retry-After"));
    EXPECT_TRUE(fixture.events->m_syncAvailable.load()) << "the connector stayed available throughout";

    const std::string requests {invsync::metrics::REQUESTS_TOTAL_PREFIX};
    const std::string failures {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX};
    EXPECT_EQ(1U, counterOf(fixture, requests + "503"));
    EXPECT_EQ(0U, counterOf(fixture, requests + "500"));
    EXPECT_EQ(0U, counterOf(fixture, requests + "409"));
    EXPECT_EQ(0U, counterOf(fixture, invsync::metrics::INDEXER_CONFLICT_EXHAUSTED));
    EXPECT_EQ(0U, counterOf(fixture, invsync::metrics::BULK_SESSIONS_FAILED));
    EXPECT_EQ(0U, counterOf(fixture, failures + "exhausted"));
    EXPECT_EQ(0U, counterOf(fixture, failures + "other"));
    EXPECT_EQ(0U, counterOf(fixture, failures + "documents"));
}

TEST(SyncPipelineTest, AChecksumReadRefusedAnswers503WhenAvailabilityChangesDuringTheSearch)
{
    PipelineUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "executeSearchQuery";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::IndexerUnavailable;
        fixture.events->m_syncAvailableOnThrow = false;
    }

    const auto response = answerChecksumSession(fixture);

    EXPECT_FALSE(fixture.events->m_syncAvailable.load()) << "the fake flipped availability at the failure";
    EXPECT_EQ(503, response.status);
    EXPECT_EQ(UNAVAILABLE_BODY, response.body);
    EXPECT_FALSE(hasHeader(response, "Retry-After"));
}

TEST(SyncPipelineTest, AChecksumReadFailureOfAnotherCauseKeepsTheAvailabilityMapping)
{
    using Cause = invsync::indexer::ConnectorError::Cause;
    struct Row
    {
        const char* name;
        std::optional<Cause> cause;
        std::optional<bool> availableOnThrow;
        int status;
        const char* body;
    };
    const Row rows[] {
        {"untyped runtime_error", std::nullopt, std::nullopt, 500, INTERNAL_BODY},
        {"Other, available", Cause::Other, std::nullopt, 500, INTERNAL_BODY},
        {"RetryExhausted, available", Cause::RetryExhausted, std::nullopt, 500, INTERNAL_BODY},
        {"Other, unavailable after the failure", Cause::Other, false, 503, UNAVAILABLE_BODY},
    };

    for (const auto& row : rows)
    {
        SCOPED_TRACE(row.name);
        PipelineUnderTest fixture;
        {
            std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
            fixture.events->m_syncThrowOn = "executeSearchQuery";
            fixture.events->m_syncThrowCause = row.cause;
            fixture.events->m_syncAvailableOnThrow = row.availableOnThrow;
        }

        const auto response = answerChecksumSession(fixture);

        EXPECT_EQ(row.status, response.status);
        EXPECT_EQ(row.body, response.body);
    }
}

TEST(SyncPipelineTest, AFlushFailureWithTheIndexerUnavailableCauseCountsAsOther)
{
    PipelineUnderTest fixture;
    {
        std::lock_guard<std::mutex> lock(fixture.events->m_mutex);
        fixture.events->m_syncThrowOn = "flush";
        fixture.events->m_syncThrowCause = invsync::indexer::ConnectorError::Cause::IndexerUnavailable;
    }

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_TRUE(fixture.pipeline->enqueue(makeItem(deltaBody("doc-1"), responder)));
    const auto response = responder->get();

    EXPECT_EQ(503, response.status);
    EXPECT_EQ(UNAVAILABLE_BODY, response.body);
    EXPECT_EQ(1U, counterOf(fixture, std::string {invsync::metrics::BULK_FLUSH_FAILURES_PREFIX} + "other"));
    EXPECT_EQ(1U, counterOf(fixture, invsync::metrics::BULK_SESSIONS_FAILED));
}
