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

// Ordered buckets and the ambiguous state end to end: one bulk in
// flight, a key at most once per bulk, a key in retry blocking only its successors, the ambiguous pin (same node for
// ambiguous_retry_window, then a counted failover), the failure before sending that fails over at once, no idle spin of
// loop 0, and the unordered bucket unchanged. Every case runs the production sink over the real transport against one
// fake per node (bulkFixture.hpp). The ambiguous cases use a 1.5 s window and a 300 ms request timeout (a held `_bulk`
// answer times out after the fake recorded, i.e. applied, it), the probe interval is an hour (a transition only
// through probeNowAndWait()), and the ordered buckets batch by maxDocs with maxAge = 200 ms (a skipped op leaves on its
// own by age). Every case ends with the charge and the retained ops at 0 (TearDown).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"
#include "write/scheduler.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;

namespace
{
    using NodeState = ic::HealthView::NodeState;
    using Clock = std::chrono::steady_clock;

    constexpr auto WINDOW = 1500ms;
    constexpr auto REQUEST_TIMEOUT = 300ms;

    /// The runtime values of the ambiguous cases.
    std::map<std::string, std::string> ambiguousConfig(std::chrono::milliseconds window = WINDOW,
                                                       std::chrono::milliseconds timeout = REQUEST_TIMEOUT)
    {
        return {{"ambiguous_retry_window_ms", std::to_string(window.count())},
                {"request_timeout_ms", std::to_string(timeout.count())}};
    }

    /// Fixed-width ids: the key is recoverable from the `_id` the fake received.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    ic::Op deleteOp(std::string docId)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::Delete;
        op.index = "wazuh-states-test";
        op.id = std::move(docId);
        return op;
    }

    /// A bucket of `maxDocs`-op batches with maxAge = 200 ms (60 s when not ordered), `ordered`, and a retry of
    /// `backoff` ms (base = cap, no jitter), unlimited attempts and no maxDuration.
    ic::BucketSpec bucket(std::string name, std::size_t maxDocs, bool ordered = true, std::int64_t backoff = 5)
    {
        auto spec = bucketSpec(std::move(name),
                               4u << 20,
                               ic::Overflow::Kind::Reject,
                               0,
                               maxDocs,
                               ordered ? ic::Duration {200} : ic::Duration {60000});
        spec.ordered = ordered;
        spec.retry.maxAttempts.reset();
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {backoff};
        spec.retry.cap = ic::Duration {backoff};
        spec.retry.jitter = 0.0;
        return spec;
    }

    /// The node's health answers a transient 429 from now on (Throttled: choose() prefers every Available node, but
    /// the sender still sends to it when none is); its `_bulk` rule is kept.
    void throttleHealth(const bulk_component::Node& node)
    {
        node.fake->clearRules();
        node.fake->addRule(indexer_client::testing::throttledRule(indexer_client::testing::Durability::Transient));
        node.fake->addRule(indexer_client::testing::bulkRule(node.bulk));
    }

    /// When each `_bulk` request reached the fake (recorded on arrival, before any hold or latency).
    std::vector<Clock::time_point> bulkArrivals(const bulk_component::Node& node)
    {
        std::vector<Clock::time_point> arrivals;
        for (const auto& request : node.fake->requests())
        {
            if (request.method == "POST" && request.path.find("_bulk") != std::string::npos)
            {
                arrivals.push_back(request.receivedAt);
            }
        }
        return arrivals;
    }

    /// The ids of one received `_bulk` request, in order.
    std::vector<std::string> ids(const std::vector<indexer_client::testing::BulkOp>& ops)
    {
        std::vector<std::string> out;
        for (const auto& op : ops)
        {
            out.push_back(op.id.value_or("<none>"));
        }
        return out;
    }

    std::string describe(const std::vector<std::vector<indexer_client::testing::BulkOp>>& received)
    {
        std::string out;
        for (const auto& ops : received)
        {
            out += "[";
            for (const auto& op : ops)
            {
                out += " " + op.action + ":" + op.id.value_or("<none>");
            }
            out += " ]";
        }
        return out;
    }

    /// The moment each key's callback ran (the first time).
    class Stamps final
    {
    public:
        ic::Callback wrap(std::uint64_t key, ic::Callback inner)
        {
            return [this, key, inner = std::move(inner)](const ic::OpResult& result)
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_at.emplace(key, Clock::now());
                }
                inner(result);
            };
        }

        std::optional<Clock::time_point> at(std::uint64_t key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_at.find(key);
            return it == m_at.end() ? std::nullopt : std::optional<Clock::time_point> {it->second};
        }

    private:
        mutable std::mutex m_mutex;
        std::map<std::uint64_t, Clock::time_point> m_at;
    };

    wr::SenderNodeStats senderNode(std::size_t index)
    {
        const auto stats = wr::senderStats();
        return stats.nodes.size() > index ? stats.nodes[index] : wr::SenderNodeStats {};
    }

    std::uint32_t inFlightTotal()
    {
        std::uint32_t total = 0;
        for (const auto& node : wr::senderStats().nodes)
        {
            total += node.inFlight;
        }
        return total;
    }
} // namespace

// 20 ops of an ordered bucket (one op per batch) against two nodes that answer after 30 ms: never two bulks of
// the bucket in flight (sampled from the sender, and each request reaches a fake only after the previous one was
// answered); all end Ok in submit order. Mutant: the delivered set ignored (eligible/slice/headBytes/nextDue).
TEST_F(BulkTest, OrderedOneBulkInFlight)
{
    constexpr std::uint64_t OPS = 20;
    constexpr auto LATENCY = 30ms;
    auto slow = BulkScript::items();
    slow.latency = LATENCY;
    const auto a = startNode(slow);
    const auto b = startNode(slow);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    auto c = client("c", {bucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();

    std::atomic<bool> sampling {true};
    std::atomic<std::uint32_t> maxInFlight {0};
    std::thread sampler(
        [&]
        {
            while (sampling.load())
            {
                const auto n = inFlightTotal();
                if (n > maxInFlight.load())
                {
                    maxInFlight.store(n);
                }
                std::this_thread::sleep_for(1ms);
            }
        });
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    const bool all = results->waitTotal(OPS, 5s);
    sampling.store(false);
    sampler.join();
    ASSERT_TRUE(all) << results->total() << " of " << OPS;
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    EXPECT_LE(maxInFlight.load(), 1u) << "two bulks of the ordered bucket in flight at once";

    auto arrivals = bulkArrivals(a);
    const auto fromB = bulkArrivals(b);
    arrivals.insert(arrivals.end(), fromB.begin(), fromB.end());
    std::sort(arrivals.begin(), arrivals.end());
    ASSERT_EQ(arrivals.size(), OPS);
    for (std::size_t i = 1; i < arrivals.size(); ++i)
    {
        EXPECT_GE(arrivals[i] - arrivals[i - 1], LATENCY - 5ms)
            << "request " << i << " left before " << i - 1 << " was answered";
    }
    expectInvariants(stats("b"));
}

// X, Y, X, Z queued in an ordered bucket of 4-op batches: the first bulk carries X, Y, Z (the second X is
// skipped and keeps its place); the second X leaves alone afterwards (by age). Mutant: the repeated key not skipped.
TEST_F(BulkTest, OrderedKeyOncePerBulk)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 4)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(indexOp(id(1), 16), results->callback(0)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(2), 16), results->callback(1)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(1), 32), results->callback(2)).accepted); // X again, a distinct body.
    ASSERT_TRUE(writer->submit(indexOp(id(3), 16), results->callback(3)).accepted);
    ASSERT_TRUE(results->waitTotal(4, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 4u);

    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 2u) << describe(received);
    EXPECT_EQ(ids(received[0]), (std::vector<std::string> {id(1), id(2), id(3)})) << describe(received);
    ASSERT_EQ(received[0].size(), 3u);
    EXPECT_EQ(received[0][0].source, body(16)) << "the first X first";
    ASSERT_EQ(received[1].size(), 1u);
    EXPECT_EQ(received[1][0].id, id(1));
    EXPECT_EQ(received[1][0].source, body(32)) << "then the second X";
    expectInvariants(stats("b"));
}

// index(X) gets a 429 item and waits a 600 ms backoff in the retry lane; delete(X) and W are queued
// behind it. W leaves at once (its key is free), delete(X) never travels with index(X) and leaves only after index(X)
// ended Ok. Mutants: a lane key blocks every pending op / blocks none.
TEST_F(BulkTest, OrderedItemRetryBlocksOnlyItsKey)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::all(BulkItem::rejected()).held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 3, true, 600)});
    auto writer = c->writer("b");
    auto results = Results::create();
    Stamps stamps;
    constexpr std::uint64_t X = 0, DELETE_X = 1, W = 2;
    ASSERT_TRUE(writer->submit(indexOp(id(1)), stamps.wrap(X, results->callback(X))).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s)) << "index(X) left by age";
    ASSERT_TRUE(writer->submit(deleteOp(id(1)), stamps.wrap(DELETE_X, results->callback(DELETE_X))).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(2)), stamps.wrap(W, results->callback(W))).accepted);
    a.fake->releaseHeld();

    ASSERT_TRUE(results->waitTotal(3, 3s)) << results->total();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 4u) << describe(received);
    EXPECT_EQ(ids(received[0]), (std::vector<std::string> {id(1)})) << describe(received);
    EXPECT_EQ(ids(received[1]), (std::vector<std::string> {id(2)})) << "W first, while X waits: " << describe(received);
    ASSERT_EQ(received[2].size(), 1u) << "the retry of index(X) alone: " << describe(received);
    EXPECT_EQ(received[2][0].action, "index");
    ASSERT_EQ(received[3].size(), 1u) << describe(received);
    EXPECT_EQ(received[3][0].action, "delete");
    for (const auto& ops : received)
    {
        const auto indexX = std::count_if(
            ops.begin(), ops.end(), [](const auto& op) { return op.action == "index" && op.id == id(1); });
        const auto deleteX = std::count_if(
            ops.begin(), ops.end(), [](const auto& op) { return op.action == "delete" && op.id == id(1); });
        EXPECT_FALSE(indexX > 0 && deleteX > 0) << "delete(X) in the bulk of index(X): " << describe(received);
    }
    const auto arrivals = bulkArrivals(a);
    ASSERT_EQ(arrivals.size(), 4u);
    const auto xOk = stamps.at(X);
    ASSERT_TRUE(xOk.has_value());
    EXPECT_LE(*xOk, arrivals[3]) << "delete(X) left before index(X) ended";
    EXPECT_EQ(results->result(X)->status, ic::Status::Ok);
    expectInvariants(stats("b"));
}

// More blocked operations than bulk.maxDocs ahead of another key must not stall it: index(X) gets a 429 item and waits
// a 1.5 s backoff in the retry lane, five more operations of X (maxDocs = 3) and then W are queued behind it. W leaves
// at once, alone, long before the retry of X; the successors of X still leave one per bulk after it, in order.
// Mutant: the scan bounded by the entries visited (bulk.maxDocs) instead of by the operations taken.
TEST_F(BulkTest, OrderedBlockedPrefixBeyondMaxDocsDoesNotStallOtherKeys)
{
    constexpr auto BACKOFF = 1500ms;
    constexpr std::uint64_t MAX_DOCS = 3;
    constexpr std::uint64_t BLOCKED = 5; // > MAX_DOCS successors of X behind it.
    const auto a = startNode();
    a.bulk->push(BulkScript::all(BulkItem::rejected()).held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", MAX_DOCS, true, BACKOFF.count())});
    auto writer = c->writer("b");
    auto results = Results::create();
    Stamps stamps;
    constexpr std::uint64_t X = 0, W = 1 + BLOCKED;
    ASSERT_TRUE(writer->submit(indexOp(id(1)), stamps.wrap(X, results->callback(X))).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s)) << "index(X) left by age";
    for (std::uint64_t i = 1; i <= BLOCKED; ++i)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(1)), stamps.wrap(i, results->callback(i))).accepted) << i;
    }
    ASSERT_TRUE(writer->submit(indexOp(id(2)), stamps.wrap(W, results->callback(W))).accepted);
    const auto released = Clock::now();
    a.fake->releaseHeld();

    ASSERT_TRUE(results->waitTotal(W + 1, 10s)) << results->total();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), W + 1);
    const auto received = a.bulk->received();
    const auto arrivals = bulkArrivals(a);
    ASSERT_GE(received.size(), 3u) << describe(received);
    ASSERT_EQ(arrivals.size(), received.size());
    EXPECT_EQ(ids(received[1]), (std::vector<std::string> {id(2)})) << "W first, while X waits: " << describe(received);
    EXPECT_LT(arrivals[1] - released, BACKOFF / 2) << "W waited for the retry of X";
    EXPECT_GE(arrivals[2] - released, BACKOFF - 100ms) << "the retry of X left before its backoff";
    ASSERT_EQ(received.size(), 2 + BLOCKED + 1) << describe(received);
    for (std::size_t i = 2; i < received.size(); ++i)
    {
        EXPECT_EQ(ids(received[i]), (std::vector<std::string> {id(1)})) << "one X per bulk: " << describe(received);
    }
    for (std::uint64_t i = 1; i <= BLOCKED; ++i)
    {
        const auto previous = stamps.at(i - 1);
        const auto current = stamps.at(i);
        ASSERT_TRUE(previous.has_value() && current.has_value()) << i;
        EXPECT_LE(*previous, *current) << "X's successors out of order at " << i;
    }
    expectInvariants(stats("b"));
}

// Two nodes; A records (applies) the bulk of X, Y, Z and never answers (timeout after sending), so the batch
// is pinned to A and A is reported Down; delete(X) waits behind it. A probe brings A back: the retry reaches A well
// before window/2 from the probe, B never sees the ambiguous batch (no `_bulk` before the probe, no index op ever),
// delete(X) arrives after it; orderedAmbiguous = 3, orderedAmbiguousFailover = 0. Mutants: immediate failover (no
// Pin::Set); only the window's end wakes the pinned batch (no pinnedNodeUsable from the sender).
TEST_F(BulkTest, OrderedTimeoutAfterApplyKeepsOrder)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items().held());
    const auto b = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, 3600000ms, ambiguousConfig()));
    auto c = client("c", {bucket("b", 3)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(1, 3s)) << "the batch did not reach A";
    ASSERT_TRUE(writer->submit(deleteOp(id(0)), results->callback(3)).accepted);

    ASSERT_TRUE(eventually([this] { return stats("b").orderedAmbiguous >= 3; }, 3s)) << describe(stats("b"));
    EXPECT_EQ(stats("b").orderedAmbiguous, 3u);
    ASSERT_TRUE(eventually([] { return nodeState(0) == NodeState::Down; }, 1s));
    EXPECT_FALSE(eventually([&] { return b.bulk->answered() > 0; }, 200ms)) << "the pinned batch went to B";
    EXPECT_EQ(results->total(), 0u);

    const auto probe = Clock::now();
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_TRUE(eventually([&] { return a.bulk->answered() >= 2; }, 3s)) << "the retry never reached A";
    const auto arrivalsA = bulkArrivals(a);
    ASSERT_GE(arrivalsA.size(), 2u);
    EXPECT_LT(arrivalsA[1] - probe, WINDOW / 2) << "the retry waited for the window's end";

    ASSERT_TRUE(results->waitTotal(4, 3s)) << results->total();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 4u);
    const auto receivedA = a.bulk->received();
    ASSERT_GE(receivedA.size(), 2u);
    EXPECT_EQ(ids(receivedA[1]), (std::vector<std::string> {id(0), id(1), id(2)})) << describe(receivedA);
    // delete(X) went wherever choose() sent it (B by round robin), always after the retry; B never saw an index op.
    std::optional<Clock::time_point> deleteAt;
    for (const auto* node : {&a, &b})
    {
        const auto received = node->bulk->received();
        const auto arrivals = bulkArrivals(*node);
        for (std::size_t i = 0; i < received.size() && i < arrivals.size(); ++i)
        {
            for (const auto& op : received[i])
            {
                if (op.action == "delete")
                {
                    deleteAt = arrivals[i];
                }
                EXPECT_FALSE(node == &b && op.action == "index") << "B got " << op.id.value_or("?");
            }
        }
    }
    ASSERT_TRUE(deleteAt.has_value());
    EXPECT_GT(*deleteAt, arrivalsA[1]) << "delete(X) before the retry of index(X)";
    const auto s = stats("b");
    EXPECT_EQ(s.orderedAmbiguous, 3u);
    EXPECT_EQ(s.orderedAmbiguousFailover, 0u);
    expectInvariants(s);
}

// One-op batches; W goes to A and Ok, Y to B and gets a 429 item (200 ms backoff), X to A, which records it
// and never answers: X is pinned to A (Down after the timeout) and A dies. Y, due during the window, stays behind the
// pin: nothing reaches B until the window ends; then both go to B and the pinned op counts orderedAmbiguousFailover.
// Mutants: no window (the filter admits any node); a pin that does not stop the bucket (no pin gate).
TEST_F(BulkTest, OrderedAmbiguousFailoverAfterWindow)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items());
    a.bulk->push(BulkScript::items().held());
    const auto b = startNode();
    b.bulk->push(BulkScript::all(BulkItem::rejected()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, 3600000ms, ambiguousConfig()));
    auto c = client("c", {bucket("b", 1, true, 200)});
    auto writer = c->writer("b");
    auto results = Results::create();
    constexpr std::uint64_t W = 0, Y = 1, X = 2;
    ASSERT_TRUE(writer->submit(indexOp(id(W)), results->callback(W)).accepted);
    ASSERT_TRUE(results->waitTotal(1, 3s));
    ASSERT_EQ(a.bulk->answered(), 1u) << "precondition: round robin starts at A";
    ASSERT_TRUE(writer->submit(indexOp(id(Y)), results->callback(Y)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(X)), results->callback(X)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s)) << "X did not reach A";
    ASSERT_EQ(b.bulk->answered(), 1u) << "precondition: Y met B";
    ASSERT_EQ(ids(a.bulk->received().at(1)), (std::vector<std::string> {id(X)}));

    ASSERT_TRUE(eventually([this] { return stats("b").orderedAmbiguous >= 1; }, 3s)) << describe(stats("b"));
    const auto pinnedAt = Clock::now();
    a.fake->stop();
    EXPECT_FALSE(eventually([&] { return b.bulk->answered() > 1; }, WINDOW - 300ms))
        << "something reached B during the window: " << describe(b.bulk->received());
    EXPECT_EQ(stats("b").orderedAmbiguousFailover, 0u);

    ASSERT_TRUE(results->waitTotal(3, 3s)) << results->total();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    const auto received = b.bulk->received();
    const auto arrivals = bulkArrivals(b);
    ASSERT_EQ(received.size(), 3u) << describe(received);
    ASSERT_EQ(arrivals.size(), 3u);
    EXPECT_GE(arrivals[1] - pinnedAt, WINDOW - 200ms) << "B was used before the window ended";
    bool xOnB = false;
    for (std::size_t i = 1; i < received.size(); ++i)
    {
        for (const auto& op : received[i])
        {
            xOnB = xOnB || op.id == id(X);
        }
    }
    EXPECT_TRUE(xOnB) << describe(received);
    EXPECT_GT(stats("b").orderedAmbiguousFailover, 0u);
    expectInvariants(stats("b"));
}

// A refuses the connection (its fake stopped after the probe saw it Available): nothing was sent
// (!mayHaveSent), so the batch fails over to B at once, unpinned.
TEST_F(BulkTest, OrderedFailureBeforeSendFailsOverAtOnce)
{
    const auto a = startNode();
    const auto b = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, 3600000ms, ambiguousConfig()));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    a.fake->stop();
    auto c = client("c", {bucket("b", 1)});
    auto results = Results::create();
    const auto submitted = Clock::now();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, WINDOW / 2)) << "the batch waited (pinned?)";
    EXPECT_LT(Clock::now() - submitted, WINDOW / 2);
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    EXPECT_EQ(wr::senderStats().failovers, 1u) << "the batch met A first";
    EXPECT_EQ(b.bulk->opCount(), 1u);
    const auto s = stats("b");
    EXPECT_EQ(s.orderedAmbiguous, 0u);
    EXPECT_EQ(s.orderedAmbiguousFailover, 0u);
    expectInvariants(s);
}

// No idle spin of loop 0 in an ordered bucket. B's health is Throttled, so A is always chosen while it is
// Available and B keeps the sender's capacity above 0. The window and the request timeout are 8 s here, so that (2)
// holds its bulk well beyond the quiet period even when the hold is observed late. (1) A batch pinned to A (timeout
// after sending, A Down): the scheduler stays quiet for 2 s; a probe brings A back and the batch ends Ok. (2) A holds a
// bulk of X while Y (429 item, 300 ms backoff) comes due in the lane: quiet for 2 s, X still in flight; the release
// ends both Ok. Mutants: nextDue = the lane head while a bulk is delivered (case 2); the pinned batch requeued Now
// instead of At(pinUntil) (case 1).
TEST_F(BulkTest, OrderedNoIdleSpin)
{
    constexpr auto QUIET = 2s;
    constexpr std::uint64_t MAX_RUNS = 20;
    const auto a = startNode();
    a.bulk->push(BulkScript::items().held());
    const auto b = startNode();
    throttleHealth(b);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, 3600000ms, ambiguousConfig(8000ms, 8000ms)));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Throttled);
    const auto scheduler = m_path->scheduler();
    ASSERT_NE(scheduler, nullptr);
    auto c = client("c", {bucket("pinned", 1), bucket("busy", 1, true, 300)});
    auto results = Results::create();

    // (1) The pinned lane with its node Down.
    ASSERT_TRUE(c->writer("pinned")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([this] { return stats("pinned").orderedAmbiguous == 1; }, 10s));
    ASSERT_TRUE(eventually([] { return nodeState(0) == NodeState::Down; }, 1s));
    std::this_thread::sleep_for(100ms); // The pinned batch meets the Down node and goes back to wait.
    auto before = scheduler->stats().runs;
    std::this_thread::sleep_for(QUIET);
    EXPECT_LE(scheduler->stats().runs - before, MAX_RUNS) << "loop 0 spun on the pinned lane";
    EXPECT_EQ(b.bulk->answered(), 0u);
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_TRUE(results->waitTotal(1, 3s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    EXPECT_EQ(a.bulk->answered(), 2u);

    // (2) A bulk in flight while the lane head comes due.
    a.bulk->push(BulkScript::all(BulkItem::rejected()));
    a.bulk->push(BulkScript::items().held());
    auto busy = c->writer("busy");
    ASSERT_TRUE(busy->submit(indexOp(id(1)), results->callback(1)).accepted); // Y
    ASSERT_TRUE(busy->submit(indexOp(id(2)), results->callback(2)).accepted); // X
    // The held answer of (1) is still there: X makes it two.
    ASSERT_TRUE(a.fake->waitHeld(2, 3s)) << "X was not held";
    ASSERT_EQ(ids(a.bulk->received().back()), (std::vector<std::string> {id(2)}));
    std::this_thread::sleep_for(400ms); // Y is due now.
    before = scheduler->stats().runs;
    std::this_thread::sleep_for(QUIET);
    EXPECT_LE(scheduler->stats().runs - before, MAX_RUNS) << "loop 0 spun while a bulk was in flight";
    EXPECT_EQ(stats("busy").orderedAmbiguous, 0u) << "precondition: X was still in flight (no timeout)";
    EXPECT_EQ(senderNode(0).inFlight, 1u) << "precondition: X was still in flight";
    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(3, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    expectInvariants(stats("pinned"));
    expectInvariants(stats("busy"));
}

// An unordered bucket is unconstrained: several bulks in flight on one node and a key repeated inside a bulk.
TEST_F(BulkTest, UnorderedUnchanged)
{
    constexpr std::uint64_t PAIRS = 4;
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucket("b", 2, false)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 2 * PAIRS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k / 2)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(PAIRS, 3s)) << "fewer than " << PAIRS << " bulks in flight at once";
    EXPECT_EQ(a.fake->heldNow(), PAIRS);
    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(2 * PAIRS, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2 * PAIRS);
    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), PAIRS) << describe(received);
    for (const auto& ops : received)
    {
        ASSERT_EQ(ops.size(), 2u) << describe(received);
        EXPECT_EQ(ops[0].id, ops[1].id) << "the key repeated in one bulk: " << describe(received);
    }
    const auto s = stats("b");
    EXPECT_EQ(s.orderedAmbiguous, 0u);
    expectInvariants(s);
}
