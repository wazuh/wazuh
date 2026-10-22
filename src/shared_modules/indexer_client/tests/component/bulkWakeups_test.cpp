/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The bulk sender end to end (plan-E3b-2 §Tests, step 4b): failover, the per-node window, the submit refusal, the
// wake-ups of the scheduler (completion, notBefore timer, health transition), the close of a client and the shutdown
// with requests in flight. Every case runs the production sink over the real transport against one fake per node
// (bulkFixture.hpp). In the wake-up cases nothing else may rescue them: buckets batch by maxDocs with maxAge = 60 s,
// the probe interval is an hour (a transition only through probeNowAndWait()) and each wait is <= 3 s. Every case
// ends with the charge and the retained ops at 0 (TearDown) unless it shuts the runtime down itself.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>

#include "bulkFixture.hpp"
#include "transport/transport.hpp"
#include "write/sender.hpp"

using namespace write_component;

namespace
{
    const std::uint32_t kWindow = ic::RuntimeConfig {}.nodeWindowMax; // I96: the AIMD window starts at its cap.
} // namespace
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;
using ::testing::HasSubstr;

namespace
{
    using NodeState = ic::HealthView::NodeState;

    /// Fixed-width ids: the key is recoverable from the `_id` the fake received.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    /// A bucket of `maxDocs`-op batches (maxAge 60 s: no age-based batch) with a retry of `base` ms, capped at `cap`
    /// ms, no jitter, `maxAttempts` (nullopt: unlimited) and no maxDuration.
    ic::BucketSpec bucket(std::string name,
                          std::size_t maxDocs,
                          std::optional<std::uint32_t> maxAttempts = std::nullopt,
                          std::int64_t base = 5,
                          std::int64_t cap = 20)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = maxAttempts;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {base};
        spec.retry.cap = ic::Duration {cap};
        spec.retry.jitter = 0.0;
        return spec;
    }

    wr::SenderNodeStats senderNode(std::size_t index)
    {
        const auto stats = wr::senderStats();
        EXPECT_GT(stats.nodes.size(), index);
        return stats.nodes.size() > index ? stats.nodes[index] : wr::SenderNodeStats {};
    }

    /// The node's health rule answers `status` from now on (its `_bulk` rule is kept).
    void setHealth(const bulk_component::Node& node, const std::string& status)
    {
        node.fake->clearRules();
        node.fake->addRule(indexer_client::testing::healthRule(status));
        node.fake->addRule(indexer_client::testing::bulkRule(node.bulk));
    }

    std::uint64_t transportCompleted()
    {
        const auto transport = ic::detail::runtimeTransport();
        return transport ? transport->stats().completed : 0;
    }

    std::string describe(const std::optional<ic::OpResult>& result)
    {
        if (!result)
        {
            return "no result";
        }
        const char* status = result->status == ic::Status::Ok       ? "Ok"
                             : result->status == ic::Status::Failed ? "Failed"
                                                                    : "Dropped";
        return std::string(status) + "/" + ic::toString(result->cause) + " http " + std::to_string(result->httpStatus) +
               " reason '" + result->reason + "'";
    }

    /// Runs `task` on its own thread, joined at the latest by the destructor. shutdown() must run on the thread that
    /// started the runtime, so the cases keep it on the test thread and race it from here.
    class Concurrently final
    {
    public:
        explicit Concurrently(std::function<void()> task)
            : m_thread(std::move(task))
        {
        }

        ~Concurrently()
        {
            join();
        }

        Concurrently(const Concurrently&) = delete;
        Concurrently& operator=(const Concurrently&) = delete;

        void join()
        {
            if (m_thread.joinable())
            {
                m_thread.join();
            }
        }

    private:
        std::thread m_thread;
    };
} // namespace

// CA-14: A is Available by the probe, then its fake stops: the batch that goes to A fails over to B with no loss, A is
// reported Down (passive) and takes nothing more; everything after goes to B. Mutant: the Failover verdict requeues
// without reporting the node (the batch is retried on the same, still usable, node).
TEST_F(BulkTest, FailoverOnTransportError)
{
    const auto a = startNode();
    const auto b = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Available);
    a.fake->stop();
    auto c = client("c", {bucket("b", 1, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();

    // One batch at a time until one has met A (round robin: within two).
    std::uint64_t k = 0;
    for (; k < 4 && wr::senderStats().failovers == 0; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        ASSERT_TRUE(results->waitTotal(k + 1, 3s)) << "op " << k;
    }
    ASSERT_EQ(wr::senderStats().failovers, 1u) << "one batch met A";
    EXPECT_EQ(nodeState(0), NodeState::Down) << "the transport error reported A Down";
    EXPECT_TRUE(senderNode(0).down) << "the sender mirrored it";
    EXPECT_EQ(nodeState(1), NodeState::Available);

    const auto first = k;
    for (; k < first + 10; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(k, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), k) << "no loss";
    for (std::uint64_t i = 0; i < k; ++i)
    {
        EXPECT_EQ(results->count(i), 1) << i;
    }
    EXPECT_EQ(wr::senderStats().failovers, 1u) << "nothing more went to A";
    EXPECT_EQ(b.bulk->opCount(), k) << "B wrote every op";
    // G-diff E3b-2 obj. 9: the latency counters take HTTP responses only; the transport error is a failure.
    EXPECT_EQ(senderNode(0).requests, 0u);
    EXPECT_EQ(senderNode(0).totalMicros, 0u);
    EXPECT_EQ(senderNode(0).failures, 1u);
    EXPECT_EQ(senderNode(1).requests, b.bulk->answered());
    EXPECT_EQ(senderNode(1).failures, 0u);
    expectInvariants(stats("b"));
}

// I68: never more than node_window_max (4, the AIMD window starts at its cap, I96) requests in flight per node. Two
// nodes whose `_bulk` answers are held, 12 one-op batches: 4 reach each node and no more during T; after the release
// every op ends Ok and no sample of the sender ever shows more than 4 in flight on a node. Mutant: the window is
// ignored (capacity and the node filter).
TEST_F(BulkTest, WindowPerNode)
{
    constexpr std::uint64_t OPS = 12;
    const auto a = startNode(BulkScript::items().held());
    const auto b = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    auto c = client("c", {bucket("b", 1, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(kWindow, 3s));
    ASSERT_TRUE(b.fake->waitHeld(kWindow, 3s));
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() + b.bulk->answered() > 2 * kWindow; }, 300ms))
        << "a fifth request reached a node";
    EXPECT_EQ(a.bulk->answered(), kWindow);
    EXPECT_EQ(b.bulk->answered(), kWindow);
    EXPECT_EQ(senderNode(0).inFlight, kWindow);
    EXPECT_EQ(senderNode(1).inFlight, kWindow);
    EXPECT_EQ(stats("b").retained, OPS);

    a.fake->releaseHeld();
    b.fake->releaseHeld();
    std::uint32_t peak = 0;
    ASSERT_TRUE(eventually(
        [&]
        {
            for (const auto& node : wr::senderStats().nodes)
            {
                peak = std::max(peak, node.inFlight);
            }
            return results->total() >= OPS;
        },
        3s));
    EXPECT_LE(peak, kWindow);
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    EXPECT_EQ(a.bulk->opCount() + b.bulk->opCount(), OPS);
}

// I68: a submit the transport refuses (seam refuseSubmit) gives its slot back and requeues the batch with an attempt
// and the reason; four refusals on one node (its whole window) still end with every op Ok and the window free. With
// one attempt allowed the refusal is the op's last error. Mutant: the refusal keeps the slot.
TEST_F(BulkTest, SubmitRefusedRequeues)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto refusals = std::make_shared<std::atomic<int>>(0);
    auto refuseNext = std::make_shared<std::atomic<int>>(static_cast<int>(kWindow));
    ic::testing_hooks::setRefuseSubmit(
        [refusals, refuseNext]()
        {
            if (refuseNext->load() > 0)
            {
                refuseNext->fetch_sub(1);
                refusals->fetch_add(1);
                return true;
            }
            return false;
        });
    auto c = client("c", {bucket("b", 1), bucket("one", 1, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < kWindow; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(kWindow, 3s)) << "refusals " << refusals->load();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), kWindow);
    EXPECT_EQ(refusals->load(), static_cast<int>(kWindow));
    auto sender = wr::senderStats();
    EXPECT_EQ(sender.submitRefused, kWindow);
    EXPECT_EQ(sender.sent, kWindow) << "only the admitted submits count as sent";
    EXPECT_GE(sender.retries, kWindow) << "each refusal costs an attempt";
    EXPECT_EQ(a.bulk->opCount(), kWindow);
    ASSERT_TRUE(eventually([] { return senderNode(0).inFlight == 0; }, 3s)) << "the window was given back";

    refuseNext->store(1);
    ASSERT_TRUE(c->writer("one")->submit(indexOp(id(9)), results->callback(9)).accepted);
    ASSERT_TRUE(results->waitTotal(kWindow + 1, 3s));
    const auto exhausted = results->result(9);
    EXPECT_EQ(exhausted->status, ic::Status::Failed) << describe(exhausted);
    EXPECT_EQ(exhausted->cause, ic::Cause::RetryExhausted);
    EXPECT_THAT(exhausted->reason, HasSubstr(ic::toString(ic::Cause::InvalidState)));
    EXPECT_THAT(exhausted->reason, HasSubstr("refused"));
    EXPECT_EQ(wr::senderStats().submitRefused, kWindow + 1);
    ASSERT_TRUE(eventually([] { return senderNode(0).inFlight == 0; }, 3s));
}

// Objection 1: one node, 12 one-op batches whose answers are held: 4 reach the node and nothing more during T; once
// released, each completion frees its slot and wakes the scheduler, so the 12 end in < T. Nothing else wakes it
// (maxAge 60 s, probe 1 h, no submit after the first 12). Mutant: no sinkReady() after a completion.
TEST_F(BulkTest, CompletionFreesWindow)
{
    constexpr std::uint64_t OPS = 12;
    constexpr auto T = 1000ms;
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 1, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(kWindow, 3s));
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > kWindow; }, T)) << "sent past the window";
    EXPECT_EQ(a.bulk->answered(), kWindow);
    EXPECT_EQ(results->total(), 0u);

    const auto released = std::chrono::steady_clock::now();
    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(OPS, T)) << results->total() << " of " << OPS << " within T of the release";
    EXPECT_LT(std::chrono::steady_clock::now() - released, T);
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    EXPECT_EQ(a.bulk->answered(), OPS);
}

// Objection 1: one node answers a request-level 429 with `Retry-After: 1`; no other submit follows. The notBefore timer
// wakes the scheduler, so the batch leaves again ~1 s later and ends Ok. Mutant: the timer is never armed.
TEST_F(BulkTest, NotBeforeExpiryWakesScheduler)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::throttled("1"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 1, 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == 1; }, 3s));
    const auto notBefore = senderNode(0).notBefore;
    ASSERT_TRUE(notBefore.has_value());
    EXPECT_EQ(a.bulk->answered(), 1u);

    ASSERT_TRUE(results->waitTotal(1, 3s)) << "nothing woke the scheduler at the notBefore";
    // Measured against the node's notBefore itself (not a poll sample after the 429): a slow poll cannot break it.
    const auto resolvedAt = std::chrono::steady_clock::now();
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << describe(results->result(0));
    EXPECT_GE(resolvedAt + 50ms, *notBefore) << "left before Retry-After";
    EXPECT_LT(resolvedAt - *notBefore, 1500ms);
    EXPECT_EQ(a.bulk->answered(), 2u);
}

// Objection 7: every node Down (cluster red): nothing leaves and nothing is lost while they stay Down; a probe round
// that brings them back is the wake-up (the NodeSet hook), and the ops leave and end Ok. Mutant: the hook mirrors the
// state without sinkReady().
TEST_F(BulkTest, NoUsableNodeWaitsThenSends)
{
    constexpr std::uint64_t OPS = 6;
    const auto a = startNode(BulkScript::items(), "red");
    const auto b = startNode(BulkScript::items(), "red");
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    ASSERT_EQ(nodeState(0), NodeState::Down);
    ASSERT_EQ(nodeState(1), NodeState::Down);
    auto c = client("c", {bucket("b", 2, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() + b.bulk->answered() > 0 || results->total() > 0; }, 500ms))
        << "something left (or was resolved) with every node Down";
    EXPECT_EQ(stats("b").retained, OPS) << "nothing lost";
    EXPECT_EQ(wr::senderStats().sent, 0u);

    setHealth(a, "green");
    setHealth(b, "green");
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_TRUE(results->waitTotal(OPS, 3s)) << "the transition did not wake the scheduler";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    EXPECT_EQ(a.bulk->opCount() + b.bulk->opCount(), OPS);
}

// I66, I99: requestClose() while a batch is in flight closes only the admission (D43): its answer (503) sends it back
// to retry and the drain writes it (Ok, exactly once, sent twice). Once the bucket is SWEPT (a Client destroyed on a
// runtime thread, obj. 3) the same answer finds it closed, so the op ends Dropped(ClientClosed) exactly once and is
// never sent again. Mutant: the closed ops of a requeue are not resolved.
TEST_F(BulkTest, CloseClientWhileInFlightRetry)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::serverError(503).held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    {
        auto c = client("c", {bucket("b", 1)});
        auto results = Results::create();
        ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
        ASSERT_TRUE(a.fake->waitHeld(1, 3s));

        c->requestClose();
        EXPECT_FALSE(eventually([&] { return results->total() > 0; }, 200ms)) << "the op in flight was resolved early";
        a.fake->releaseHeld();
        ASSERT_TRUE(results->waitTotal(1, 3s)) << "the retried op of a draining bucket was never resolved";
        const auto result = results->result(0);
        EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
        EXPECT_FALSE(eventually([&] { return results->total() > 1; }, 200ms)) << "a second result";
        EXPECT_EQ(results->count(0), 1);
        EXPECT_EQ(a.bulk->answered(), 2u) << "retried once during the drain";
        const auto report = c->awaitClosed(now() + 1s);
        ASSERT_TRUE(report.ok());
        EXPECT_EQ(report.value.droppedClientClosed, 0u);
        EXPECT_EQ(report.value.droppedShutdown, 0u);
        EXPECT_EQ(report.value.drained, 1u);
        auto s = stats("b");
        EXPECT_EQ(s.resolvedOk, 1u);
        EXPECT_EQ(s.resolvedDropped, 0u);
        expectInvariants(s);
    }
    {
        a.fake->rearmHold();
        a.bulk->push(BulkScript::serverError(503).held());
        const auto errorsBefore = ic::detail::testing::usageErrors();
        auto owned = std::make_shared<std::shared_ptr<ic::Client>>(client("swept", {bucket("b", 1)}));
        auto writer = (*owned)->writer("b"); // Keeps the bucket (and its counters) alive after the Client.
        auto results = Results::create();
        ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
        ASSERT_TRUE(a.fake->waitHeld(1, 3s));

        auto destroyed = std::make_shared<std::promise<void>>();
        auto destroyedFuture = destroyed->get_future();
        ASSERT_TRUE(m_path->postToPool(
            [owned, destroyed]
            {
                owned->reset(); // ~Client on a pool thread: requestClose() plus the immediate sweep.
                destroyed->set_value();
            }));
        ASSERT_EQ(destroyedFuture.wait_for(3s), std::future_status::ready);
        EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + 1);
        EXPECT_FALSE(eventually([&] { return results->total() > 0; }, 200ms)) << "the op in flight was resolved early";
        a.fake->releaseHeld();
        ASSERT_TRUE(results->waitTotal(1, 3s)) << "the retried op of a closed bucket was never resolved";
        const auto result = results->result(1);
        EXPECT_EQ(result->status, ic::Status::Dropped) << describe(result);
        EXPECT_EQ(result->cause, ic::Cause::ClientClosed);
        EXPECT_FALSE(eventually([&] { return results->total() > 1; }, 200ms)) << "a second result";
        EXPECT_EQ(results->count(1), 1);
        EXPECT_EQ(a.bulk->answered(), 3u) << "never sent again";
        auto s = stats("b", "swept");
        EXPECT_EQ(s.resolvedDropped, 1u);
        expectInvariants(s);
    }
}

// I66: a retried op that comes due goes out before the pending ops: the batch after the retry takes the retry lane
// first and then the pending queue (one batch mixing both).
TEST_F(BulkTest, RetryLaneBeforePendingE2E)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items({{1, BulkItem::rejected()}}).held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 4)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(1, 3s));
    for (std::uint64_t k = 4; k < 7; ++k) // Three pending ops: under maxDocs, not eligible on their own.
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 200ms));
    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(7, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 7u);

    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 2u);
    ASSERT_EQ(received[1].size(), 4u);
    EXPECT_EQ(received[1][0].id, id(1)) << "the retry first";
    for (std::size_t i = 1; i < 4; ++i)
    {
        EXPECT_EQ(received[1][i].id, id(3 + i)) << "then the pending ops in order";
    }
}

// I66: a bucket whose op waits a 1.5 s backoff in its retry lane does not hold back another bucket: the other's ops
// are written at once while the first one's retry waits; then the retry goes out and ends Ok.
TEST_F(BulkTest, BackoffIsPerBucket)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::all(BulkItem::rejected()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("slow", 1, std::nullopt, 1500, 1500), bucket("fast", 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("slow")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().retries == 1; }, 3s));
    const auto backoffFrom = std::chrono::steady_clock::now();

    auto fast = c->writer("fast");
    for (std::uint64_t k = 1; k <= 8; ++k)
    {
        ASSERT_TRUE(fast->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(8, 1000ms)) << "the other bucket was held back";
    EXPECT_LT(std::chrono::steady_clock::now() - backoffFrom, 1000ms);
    EXPECT_EQ(results->count(0), 0) << "the slow op is still in its backoff";
    EXPECT_EQ(a.bulk->answered(), 9u);
    EXPECT_EQ(stats("fast").resolvedOk, 8u);

    ASSERT_TRUE(results->waitTotal(9, 3s));
    EXPECT_GE(std::chrono::steady_clock::now() - backoffFrom, 1400ms);
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << describe(results->result(0));
    EXPECT_EQ(a.bulk->answered(), 10u);
}

// I68: a batch held by the node and shutdown(): the transfer is cancelled, the op ends Dropped(Shutdown) exactly once
// (callback and ticket), in < 2 s.
TEST_F(BulkTest, ShutdownCancelsInFlight)
{
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 2)});
    auto writer = c->writer("b");
    auto results = Results::create();
    auto withCallback = writer->submit(indexOp(id(0)), results->callback(0));
    auto withoutCallback = writer->submit(indexOp(id(1)));
    ASSERT_TRUE(withCallback.accepted);
    ASSERT_TRUE(withoutCallback.accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s));
    EXPECT_EQ(stats("b").retained, 2u);

    const auto t0 = now();
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    EXPECT_LT(now() - t0, 2s);
    ASSERT_TRUE(results->waitTotal(1, 2s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Dropped) << describe(results->result(0));
    EXPECT_EQ(results->result(0)->cause, ic::Cause::Shutdown);
    ASSERT_TRUE(withoutCallback.ticket.ready());
    const auto ticketResult = withoutCallback.ticket.wait(now() + 1s);
    EXPECT_EQ(ticketResult.value.status, ic::Status::Dropped);
    EXPECT_EQ(ticketResult.value.cause, ic::Cause::Shutdown);
    EXPECT_FALSE(eventually([&] { return results->total() > 1; }, 200ms)) << "a second result";
    const auto report = c->awaitClosed(now() + 100ms);
    EXPECT_EQ(report.value.droppedShutdown, 2u);
    auto s = stats("b");
    EXPECT_EQ(s.resolvedDropped, 2u) << describe(s);
    EXPECT_EQ(s.resolvedOk, 0u) << describe(s);
    expectInvariants(s);
}

// I68 (TSAN): completions that resolve and requeue race the shutdown sweep. (1) Deterministic: 8 batches of two ops
// are answered (item 0 Ok, item 1 a retryable 429) while the CPU pool is blocked; the shutdown sweep resolves the 16
// ops Dropped(Shutdown) first, then the late completions run: their Ok resolution and their requeue must both lose
// (one result per op, the bucket counts 16 dropped and nothing else). Mutant: WritePath::resolve without the CAS.
// (2) Three rounds where the held answers are released while shutdown() runs: one result per op, invariants kept.
TEST_F(BulkTest, ShutdownRacesRequeue)
{
    constexpr std::uint64_t OPS = 16;
    const auto script = BulkScript::items({{1, BulkItem::rejected()}}).held();
    const auto a = startNode(script);
    const auto b = startNode(script);

    {
        ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
        auto c = client("c", {bucket("b", 2)});
        auto writer = c->writer("b");
        auto results = Results::create();
        for (std::uint64_t k = 0; k < OPS; ++k)
        {
            ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        }
        ASSERT_TRUE(a.fake->waitHeld(kWindow, 3s));
        ASSERT_TRUE(b.fake->waitHeld(kWindow, 3s));

        auto blocker = component::Blocker::create();
        component::ReleaseOnExit releaseOnExit(blocker);
        ASSERT_TRUE(ic::detail::testing::postToPool(blocker->task()));
        ASSERT_TRUE(ic::detail::testing::postToPool(blocker->task()));
        ASSERT_TRUE(blocker->waitStarted(2, 3s)) << "both CPU threads blocked";
        const auto completedBefore = transportCompleted();
        a.fake->releaseHeld();
        b.fake->releaseHeld();
        ASSERT_TRUE(eventually([&] { return transportCompleted() >= completedBefore + 2 * kWindow; }, 3s))
            << "the eight answers reached the transport";

        // The sweep runs inside shutdown() (test thread); the pool stays blocked until it has resolved the 16 ops.
        std::atomic<bool> sweptFirst {false};
        std::atomic<std::size_t> callbacksAtSweep {0};
        Concurrently releaser(
            [&]()
            {
                sweptFirst = eventually([&] { return stats("b").resolvedDropped == OPS; }, 3s);
                callbacksAtSweep = results->total();
                blocker->release();
            });
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        releaser.join();
        ASSERT_TRUE(sweptFirst.load()) << "the sweep did not resolve the delivered ops: " << describe(stats("b"));
        EXPECT_EQ(callbacksAtSweep.load(), 0u) << "the pool was still blocked";

        ASSERT_TRUE(results->waitTotal(OPS, 2s));
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), OPS);
        for (std::uint64_t k = 0; k < OPS; ++k)
        {
            EXPECT_EQ(results->count(k), 1) << k;
        }
        auto s = stats("b");
        EXPECT_EQ(s.resolvedDropped, OPS) << describe(s);
        EXPECT_EQ(s.resolvedOk, 0u) << "a late completion resolved an op the sweep had resolved: " << describe(s);
        EXPECT_EQ(s.resolvedFailed, 0u) << describe(s);
        expectInvariants(s);
        EXPECT_TRUE(eventually([this] { return drainedNow(); }, 2s)) << describe(m_path->stats());
        EXPECT_FALSE(blocker->expired());
    }

    for (int round = 0; round < 3; ++round)
    {
        SCOPED_TRACE(round);
        a.fake->rearmHold();
        b.fake->rearmHold();
        ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
        auto c = client("c", {bucket("b", 2)});
        auto writer = c->writer("b");
        auto results = Results::create();
        for (std::uint64_t k = 0; k < OPS; ++k)
        {
            ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        }
        ASSERT_TRUE(a.fake->waitHeld(kWindow, 3s));
        ASSERT_TRUE(b.fake->waitHeld(kWindow, 3s));
        {
            Concurrently release(
                [&]()
                {
                    std::this_thread::sleep_for(std::chrono::microseconds(200 * round));
                    a.fake->releaseHeld();
                    b.fake->releaseHeld();
                });
            EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        }
        ASSERT_TRUE(results->waitTotal(OPS, 2s));
        EXPECT_FALSE(eventually([&] { return results->total() > OPS; }, 100ms)) << "a second result";
        for (std::uint64_t k = 0; k < OPS; ++k)
        {
            EXPECT_EQ(results->count(k), 1) << k;
            const auto result = results->result(k);
            const bool ok = result->status == ic::Status::Ok && result->cause == ic::Cause::None;
            const bool dropped = result->status == ic::Status::Dropped && result->cause == ic::Cause::Shutdown;
            EXPECT_TRUE(ok || dropped) << k << ": " << describe(result);
        }
        auto s = stats("b");
        EXPECT_EQ(s.resolvedOk + s.resolvedDropped, OPS) << describe(s);
        expectInvariants(s);
        EXPECT_TRUE(eventually([this] { return drainedNow(); }, 2s)) << describe(m_path->stats());
    }
}

// G-diff E3b-2 obj. 4: the NodeSet hook that mirrors Down is held (seam), so the node is Down in the NodeSet but the
// sender's mirror still says usable. A batch dispatched in that window finds no node: dispatch refreshes the mirror
// itself, capacity() drops to 0 and the scheduler stops instead of re-slicing the batch until the hook lands. The two
// ops end Dropped(ClientClosed) when the client closes. Mutant: the no-node branch does not refresh the mirror.
TEST_F(BulkTest, StaleDownMirrorDoesNotSpin)
{
    struct Gate final
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool open {false};
        std::atomic<int> entered {0};

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                open = true;
            }
            cv.notify_all();
        }
    };
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_FALSE(senderNode(0).down);
    auto gate = std::make_shared<Gate>();
    ic::testing_hooks::setBeforeSenderMirror(
        [gate]()
        {
            gate->entered.fetch_add(1);
            std::unique_lock<std::mutex> lock(gate->mutex);
            gate->cv.wait_for(lock, 5s, [&] { return gate->open; });
        });
    struct OpenOnExit final
    {
        std::shared_ptr<Gate> gate;
        ~OpenOnExit()
        {
            gate->release();
        }
    } openOnExit {gate};

    a.fake->stop();
    auto c = client("c", {bucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([&] { return gate->entered.load() >= 1; }, 3s)) << "the transport error reported no Down";
    ASSERT_EQ(nodeState(0), NodeState::Down);
    ASSERT_FALSE(senderNode(0).down) << "precondition: the mirror lags (its hook is held)";

    const auto scheduler = m_path->scheduler();
    ASSERT_NE(scheduler, nullptr);
    const auto before = scheduler->stats().batches;
    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    EXPECT_TRUE(eventually([] { return senderNode(0).down; }, 3s)) << "dispatch did not refresh the mirror";
    EXPECT_FALSE(eventually([&] { return scheduler->stats().batches > before + 3; }, 300ms))
        << "the scheduler kept re-slicing: " << scheduler->stats().batches - before << " batches";
    EXPECT_EQ(results->total(), 0u);

    gate->release();
    c->requestClose();
    // I99: the node is still Down, so the drain cannot write them; awaitClosed's sweep (drainEnd = 600 ms) drops them.
    EXPECT_FALSE(eventually([&] { return results->total() > 0; }, 200ms)) << "requestClose() swept (D43)";
    ASSERT_TRUE(c->awaitClosed(now() + 1s).ok());
    ASSERT_TRUE(results->waitTotal(2, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 2u);
}

// G-diff E3b-2 obj. 5: WritePath::setSink stops the bulk sender while a request is in flight; its cancelled
// completion sends the batch back to the lane with no attempt, so the new sink gets it (outside a runtime stop no
// sweep would resolve it). Mutant: a Cancelled completion stays Ignore.
TEST_F(BulkTest, SetSinkRequeuesCancelledInFlight)
{
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 1, 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s));

    auto sink = installSink(); // Stops the bulk sender: Transport::cancel on the request held by the node.
    ASSERT_TRUE(sink->waitDispatched(1, 3s)) << "the cancelled batch never reached the new sink";
    EXPECT_EQ(sink->log().at(0).ops, 1u);
    EXPECT_EQ(results->total(), 0u) << "not resolved by the cancellation";
    EXPECT_EQ(sink->resolveHeld(), 1u) << "with maxAttempts = 1 the requeue cost no attempt";
    ASSERT_TRUE(results->waitTotal(1, 3s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << describe(results->result(0));
    EXPECT_EQ(results->count(0), 1);
    a.fake->releaseHeld();
}

// G-diff E3b-2 obj. 6: a completion that throws after its slot was released (seam beforeCompletion) does not strand
// the batch: it is requeued with an attempt and the reason, the window is free again and the op ends Ok; with one
// attempt allowed the failure is the op's last error. Mutant: complete() without its exception guard.
TEST_F(BulkTest, CompletionExceptionRequeues)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto throwNext = std::make_shared<std::atomic<int>>(1);
    ic::testing_hooks::setBeforeCompletion(
        [throwNext]()
        {
            if (throwNext->load() > 0)
            {
                throwNext->fetch_sub(1);
                throw std::runtime_error("injected");
            }
        });
    auto c = client("c", {bucket("b", 1), bucket("one", 1, 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, 3s)) << "the batch of the throwing completion was stranded";
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << describe(results->result(0));
    EXPECT_EQ(a.bulk->answered(), 2u) << "sent again after the failed completion";
    EXPECT_GE(wr::senderStats().retries, 1u);
    ASSERT_TRUE(eventually([] { return senderNode(0).inFlight == 0; }, 3s));

    throwNext->store(1);
    ASSERT_TRUE(c->writer("one")->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2, 3s));
    const auto exhausted = results->result(1);
    EXPECT_EQ(exhausted->status, ic::Status::Failed) << describe(exhausted);
    EXPECT_EQ(exhausted->cause, ic::Cause::RetryExhausted);
    EXPECT_THAT(exhausted->reason, HasSubstr("bulk completion failed: injected"));
}
