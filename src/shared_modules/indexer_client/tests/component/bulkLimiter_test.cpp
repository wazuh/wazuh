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

// The per-node limiter end to end (plan-E5a §Tests, step 6; the normative rules are in src/write/sender.hpp, I98): the
// AIMD window and the bulk target, the pace and its relaxation, the batch limit the scheduler passes to
// Bucket::slice, the pinned batch against the real window (D47), queries outside the window (I95) and the default DRR
// quantum with its cap of batches per turn (I97b). Every BulkLimiterTest case runs the production sink over the real
// transport against one fake per node (bulkFixture.hpp); the probe interval is an hour, so health moves only with
// probeNowAndWait(). The fake «limiter X» is a token bucket of depth B refilled continuously at X requests/s: a `_bulk`
// request without a token gets a 429 without Retry-After. Time bounds of the plan are scaled() (x3 under TSAN); the
// `*Long` case runs in the normal build only (verificar.sh excludes it under the sanitizers). The BulkLimiterSliceTest
// cases drive Bucket::slice directly with a chosen `cap` (the test sink holds every batch and has no capacity, so the
// scheduler never slices). Every wait is bounded; every case ends with the charge and the retained ops at 0 (TearDown).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "bulkFixture.hpp"
#include "queryFixture.hpp"
#include "write/scheduler.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;
using query_component::scaled;

namespace
{
    using NodeState = ic::HealthView::NodeState;
    using Clock = std::chrono::steady_clock;
    using indexer_client::testing::RecordedRequest;
    using indexer_client::testing::Rule;

    const std::uint32_t kWindowMax = ic::RuntimeConfig {}.nodeWindowMax;

    /// Fixed-width ids: every op with the same body has the same wire size.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    /// An unordered bucket of `maxDocs`-op batches (and `maxBytes`, 0 = the quota's), `maxAge`, unlimited attempts with
    /// a 5 ms .. 20 ms retry without jitter, no maxDuration.
    ic::BucketSpec loadBucket(std::string name,
                              std::size_t maxDocs,
                              ic::Duration maxAge = ic::Duration {60000},
                              std::size_t maxBytes = 0,
                              bool ordered = false)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, maxBytes, maxDocs, maxAge);
        spec.ordered = ordered;
        spec.retry.maxAttempts.reset();
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        return spec;
    }

    wr::SenderNodeStats senderNode(std::size_t index)
    {
        const auto stats = wr::senderStats();
        return stats.nodes.size() > index ? stats.nodes[index] : wr::SenderNodeStats {};
    }

    std::string describe(const wr::SenderNodeStats& n)
    {
        char buffer[512];
        std::snprintf(buffer,
                      sizeof(buffer),
                      "window %.3f bulkTarget %llu pace %lld ms inFlight %u requests %llu decreases429 %llu "
                      "decreasesThrottled %llu decreasesLatency %llu increases %llu paceRelaxed %llu",
                      n.window,
                      static_cast<unsigned long long>(n.bulkTarget),
                      static_cast<long long>(n.pace.count()),
                      n.inFlight,
                      static_cast<unsigned long long>(n.requests),
                      static_cast<unsigned long long>(n.decreases429),
                      static_cast<unsigned long long>(n.decreasesThrottled),
                      static_cast<unsigned long long>(n.decreasesLatency),
                      static_cast<unsigned long long>(n.increases),
                      static_cast<unsigned long long>(n.paceRelaxed));
        return buffer;
    }

    /// The `_bulk` requests the fake received, in arrival order.
    std::vector<RecordedRequest> bulkRequests(const bulk_component::Node& node)
    {
        std::vector<RecordedRequest> out;
        for (auto& request : node.fake->requests())
        {
            if (request.method == "POST" && request.path.find("_bulk") != std::string::npos)
            {
                out.push_back(std::move(request));
            }
        }
        return out;
    }

    /// Ops of a recorded `_bulk` body (index ops: an action line and a source line each; needs recordBodies).
    std::size_t opsIn(const RecordedRequest& request)
    {
        return static_cast<std::size_t>(std::count(request.body.begin(), request.body.end(), '\n')) / 2;
    }

    /// The fake «limiter X»: a token bucket of depth B refilled continuously at X tokens/s. Every `_bulk` request is
    /// logged with its arrival and whether it got a token; disabled, every request gets one.
    class TokenLimiter final
    {
    public:
        TokenLimiter(double rate, double depth)
            : m_rate(rate)
            , m_depth(depth)
            , m_tokens(depth)
            , m_last(Clock::now())
        {
        }

        bool admit()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto t = Clock::now();
            refillLocked(t);
            bool admitted = true;
            if (m_enabled)
            {
                admitted = m_tokens >= 1.0;
                if (admitted)
                {
                    m_tokens -= 1.0;
                }
            }
            m_log.emplace_back(t, admitted);
            return admitted;
        }

        /// Enabling starts from a full bucket.
        void setEnabled(bool enabled)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_enabled = enabled;
            m_tokens = m_depth;
            m_last = Clock::now();
        }

        struct Window final
        {
            std::uint64_t requests {0};
            std::uint64_t rejected {0};
        };

        Window between(Clock::time_point from, Clock::time_point to) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            Window window;
            for (const auto& [at, admitted] : m_log)
            {
                if (at >= from && at < to)
                {
                    ++window.requests;
                    window.rejected += admitted ? 0 : 1;
                }
            }
            return window;
        }

    private:
        void refillLocked(Clock::time_point t)
        {
            const std::chrono::duration<double> elapsed = t - m_last;
            m_tokens = std::min(m_depth, m_tokens + elapsed.count() * m_rate);
            m_last = t;
        }

        const double m_rate;
        const double m_depth;
        mutable std::mutex m_mutex;
        bool m_enabled {true};
        double m_tokens;
        Clock::time_point m_last;
        std::vector<std::pair<Clock::time_point, bool>> m_log;
    };

    /// Sustained load: a thread keeps `cap` ops submitted and unresolved in `writer` until stop(); results counted. Its
    /// bucket batches by maxDocs with a short maxAge, so the ops left after stop() still leave.
    class Producer final
    {
    public:
        Producer(std::shared_ptr<ic::IWriter> writer, std::uint64_t cap, std::size_t bodyBytes)
            : m_writer(std::move(writer))
            , m_cap(cap)
            , m_bodyBytes(bodyBytes)
            , m_counts(std::make_shared<Counts>())
        {
            m_thread = std::thread([this] { run(); });
        }

        ~Producer()
        {
            stop();
        }

        Producer(const Producer&) = delete;
        Producer& operator=(const Producer&) = delete;

        void stop()
        {
            m_stop = true;
            if (m_thread.joinable())
            {
                m_thread.join();
            }
        }

        /// After stop(): every submitted op resolved within `timeout`.
        bool waitResolved(std::chrono::milliseconds timeout) const
        {
            return eventually([this] { return m_counts->resolved.load() == m_submitted.load(); }, timeout);
        }

        std::uint64_t submitted() const
        {
            return m_submitted.load();
        }
        std::uint64_t ok() const
        {
            return m_counts->ok.load();
        }
        std::uint64_t failed() const
        {
            return m_counts->failed.load();
        }
        std::uint64_t dropped() const
        {
            return m_counts->dropped.load();
        }

    private:
        struct Counts final
        {
            std::atomic<std::uint64_t> ok {0};
            std::atomic<std::uint64_t> failed {0};
            std::atomic<std::uint64_t> dropped {0};
            std::atomic<std::uint64_t> resolved {0};
        };

        void run()
        {
            std::uint64_t key = 0;
            while (!m_stop.load())
            {
                if (m_submitted.load() - m_counts->resolved.load() >= m_cap)
                {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                auto counts = m_counts;
                const auto submit = m_writer->submit(indexOp(id(key), m_bodyBytes),
                                                     [counts](const ic::OpResult& result)
                                                     {
                                                         switch (result.status)
                                                         {
                                                             case ic::Status::Ok: ++counts->ok; break;
                                                             case ic::Status::Failed: ++counts->failed; break;
                                                             default: ++counts->dropped; break;
                                                         }
                                                         ++counts->resolved;
                                                     });
                if (submit.accepted)
                {
                    ++m_submitted;
                    ++key;
                }
                else
                {
                    std::this_thread::sleep_for(1ms);
                }
            }
        }

        std::shared_ptr<ic::IWriter> m_writer;
        const std::uint64_t m_cap;
        const std::size_t m_bodyBytes;
        std::shared_ptr<Counts> m_counts;
        std::atomic<bool> m_stop {false};
        std::atomic<std::uint64_t> m_submitted {0};
        std::thread m_thread;
    };
} // namespace

class BulkLimiterTest : public BulkTest
{
protected:
    /// A node whose `_bulk` answers go through `limiter` (a 429 without Retry-After when it has no token).
    bulk_component::Node startLimitedNode(const std::shared_ptr<TokenLimiter>& limiter)
    {
        return startNode(BulkScript::items(),
                         "green",
                         {},
                         [limiter](const httplib::Request& /*request*/, Rule& reply)
                         {
                             if (!limiter->admit())
                             {
                                 const auto throttled = BulkScript::throttled();
                                 reply.status = throttled.status;
                                 reply.body = throttled.body;
                                 reply.retryAfter.reset();
                             }
                         });
    }

    /// The node's health answers `health` from now on; its `_bulk` rule (no rewrite) is kept.
    static void setHealth(const bulk_component::Node& node, Rule health)
    {
        node.fake->clearRules();
        node.fake->addRule(std::move(health));
        node.fake->addRule(indexer_client::testing::bulkRule(node.bulk));
    }

    std::uint64_t schedulerBatches() const
    {
        const auto scheduler = m_path ? m_path->scheduler() : nullptr;
        return scheduler ? scheduler->stats().batches : 0;
    }

    /// Prints one line of numbers for the plan's ledger (estado.md, «Números CA-24»).
    static void report(const char* label,
                       std::size_t window,
                       const TokenLimiter::Window& w,
                       const wr::SenderNodeStats* final = nullptr)
    {
        std::printf("[  CA-24   ] %s window %zu: requests %llu, 429 %llu%s%s\n",
                    label,
                    window,
                    static_cast<unsigned long long>(w.requests),
                    static_cast<unsigned long long>(w.rejected),
                    final ? "; final " : "",
                    final ? describe(*final).c_str() : "");
    }
};

// CA-24, T9: one node behind «limiter X» = 4 req/s with B = 4, sustained load, defaults but pace_initial_ms = 50. After
// 60 s, each 10 s window carries <= X * 1.1 * 10 = 44 requests, fewer than 5 % of the measured requests are 429 and no
// op fails. Mutant: the pace only after a 429 (no nextSendAt in the choose filter).
TEST_F(BulkLimiterTest, RateConvergesBelowOneTransferLong)
{
    constexpr auto WARMUP = 60s;
    constexpr auto WINDOW = 10s;
    constexpr std::size_t WINDOWS = 3;
    auto limiter = std::make_shared<TokenLimiter>(4.0, 4.0);
    const auto a = startLimitedNode(limiter);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"pace_initial_ms", "50"}}));
    auto c = client("c", {loadBucket("b", 10, ic::Duration {500})});
    Producer producer(c->writer("b"), 200, 100);

    std::this_thread::sleep_for(WARMUP);
    const auto t0 = Clock::now();
    std::this_thread::sleep_for(WINDOW * WINDOWS);
    const auto final = senderNode(0);
    producer.stop();

    TokenLimiter::Window total;
    for (std::size_t i = 0; i < WINDOWS; ++i)
    {
        const auto w = limiter->between(t0 + WINDOW * i, t0 + WINDOW * (i + 1));
        report("RateConvergesBelowOneTransferLong", i, w, i + 1 == WINDOWS ? &final : nullptr);
        EXPECT_LE(w.requests, 44u) << "window " << i << ": " << w.rejected << " of them 429";
        total.requests += w.requests;
        total.rejected += w.rejected;
    }
    EXPECT_GT(total.requests, 0u);
    EXPECT_LT(total.rejected * 100, total.requests * 5) << total.rejected << " 429 of " << total.requests;

    limiter->setEnabled(false);
    ASSERT_TRUE(producer.waitResolved(60s)) << producer.submitted() << " submitted, " << producer.ok() << " ok";
    EXPECT_EQ(producer.failed(), 0u);
    EXPECT_EQ(producer.dropped(), 0u);
}

// T9: limiter X = 4, B = 2, pace_relax_after = 5: after 15 s of warm-up, two 10 s windows of <= X * 1.1 * 10 = 44
// requests each (10 s windows: the 429s of one burst do not crowd a short one, G-diff E5a obj. 5); then the limit is
// lifted and the rate passes 3X (> 12 requests in one second) within 20 s. Mutant: no relaxation (the pace only grows).
TEST_F(BulkLimiterTest, RateConvergesBelowOneTransfer)
{
    constexpr auto WARMUP = 15s;
    constexpr auto WINDOW = 10s;
    constexpr std::size_t WINDOWS = 2;
    auto limiter = std::make_shared<TokenLimiter>(4.0, 2.0);
    const auto a = startLimitedNode(limiter);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"pace_relax_after", "5"}}));
    auto c = client("c", {loadBucket("b", 10, ic::Duration {500})});
    Producer producer(c->writer("b"), 400, 100);

    std::this_thread::sleep_for(WARMUP);
    const auto t0 = Clock::now();
    std::this_thread::sleep_for(WINDOW * WINDOWS);
    const auto limited = senderNode(0);
    for (std::size_t i = 0; i < WINDOWS; ++i)
    {
        const auto w = limiter->between(t0 + WINDOW * i, t0 + WINDOW * (i + 1));
        report("RateConvergesBelowOneTransfer", i, w, i + 1 == WINDOWS ? &limited : nullptr);
        EXPECT_LE(w.requests, 44u) << "window " << i << ": " << w.rejected << " of them 429";
    }

    limiter->setEnabled(false);
    const auto lifted = Clock::now();
    std::chrono::milliseconds reached {0};
    const bool fast = eventually(
        [&]
        {
            const auto t = Clock::now();
            if (t - lifted < 1s || limiter->between(t - 1s, t).requests <= 12)
            {
                return false;
            }
            reached = std::chrono::duration_cast<std::chrono::milliseconds>(t - lifted);
            return true;
        },
        scaled(20000ms));
    std::printf("[  CA-24   ] RateConvergesBelowOneTransfer recovery: > 3X after %lld ms; %s\n",
                static_cast<long long>(reached.count()),
                describe(senderNode(0)).c_str());
    EXPECT_TRUE(fast) << "the rate never passed 3X once the limit was lifted: " << describe(senderNode(0));
    producer.stop();
    ASSERT_TRUE(producer.waitResolved(30s)) << producer.submitted() << " submitted, " << producer.ok() << " ok";
    EXPECT_EQ(producer.failed(), 0u);
}

// T9: limiter X = 4, B = 2, defaults: the 429s take the window to 1; the next success makes it 2 without a rebound:
// the 5 s window that follows carries <= X * 1.1 * 5 = 22 requests. Mutant: a 2xx sets the pace to 0 (E3b's rule).
TEST_F(BulkLimiterTest, NoReboundFromOneToTwo)
{
    auto limiter = std::make_shared<TokenLimiter>(4.0, 2.0);
    const auto a = startLimitedNode(limiter);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", 10, ic::Duration {500})});
    Producer producer(c->writer("b"), 200, 100);

    ASSERT_TRUE(eventually([] { return senderNode(0).window <= 1.0; }, scaled(10000ms)))
        << "the window never reached 1: " << describe(senderNode(0));
    ASSERT_TRUE(eventually([] { return senderNode(0).window >= 2.0; }, scaled(10000ms)))
        << "no success after the window reached 1: " << describe(senderNode(0));
    const auto t0 = Clock::now();
    std::this_thread::sleep_for(5s);
    const auto w = limiter->between(t0, t0 + 5s);
    const auto node = senderNode(0);
    report("NoReboundFromOneToTwo", 0, w, &node);
    EXPECT_LE(w.requests, 22u) << w.rejected << " of them 429";

    limiter->setEnabled(false);
    producer.stop();
    ASSERT_TRUE(producer.waitResolved(30s));
    EXPECT_EQ(producer.failed(), 0u);
}

// T9: a node without pressure answers one 429 without Retry-After: the pace becomes paceInitial (300 ms); the throttled
// batch leaves again >= paceInitial later and the next batch, already queued, waits the nextSendAt of that send: it
// arrives >= paceInitial and < paceInitial + 200 ms after it. Nothing else wakes the scheduler (maxAge 60 s, probe 1
// h). Mutant: dispatch() does not arm the timer for nextSendAt.
TEST_F(BulkLimiterTest, FirstBare429StartsPace)
{
    constexpr auto PACE = 300ms;
    const auto a = startNode();
    a.bulk->push(BulkScript::throttled());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"pace_initial_ms", "300"}}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();

    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == 1; }, scaled(3000ms)));
    EXPECT_EQ(senderNode(0).pace, ic::Duration {PACE}) << "paceInitial";
    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2, scaled(3000ms))) << "the queued batch never left: " << describe(senderNode(0));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);

    const auto requests = bulkRequests(a);
    ASSERT_EQ(requests.size(), 3u);
    const auto retry = requests[1].receivedAt - requests[0].receivedAt;
    const auto next = requests[2].receivedAt - requests[1].receivedAt;
    EXPECT_GE(retry, PACE) << "the throttled batch left inside its notBefore";
    EXPECT_LT(retry, PACE + scaled(200ms));
    EXPECT_GE(next, PACE - 20ms) << "the next send ignored nextSendAt";
    EXPECT_LT(next, PACE + scaled(200ms)) << "nothing woke the scheduler at nextSendAt";
}

// CA-24: for 3 s every `_bulk` answers 200 with every item 429 (a full write queue): the items are retried, and the
// window stays at its maximum, the pace at 0 and the bulk target uncapped (item rejections never decrease). Mutant: an
// item 429 treated as a request 429.
TEST_F(BulkLimiterTest, ItemRejectsDoNotMoveWindow)
{
    const auto a = startNode(BulkScript::all(BulkItem::rejected()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    std::this_thread::sleep_for(3s);
    const auto during = senderNode(0);
    EXPECT_GE(a.bulk->answered(), 20u) << "the items were not retried";
    EXPECT_EQ(during.window, static_cast<double>(kWindowMax)) << describe(during);
    EXPECT_EQ(during.pace, ic::Duration {0}) << describe(during);
    EXPECT_EQ(during.bulkTarget, 0u) << describe(during);
    EXPECT_EQ(during.decreases429 + during.decreasesThrottled + during.decreasesLatency, 0u) << describe(during);
    EXPECT_EQ(wr::senderStats().throttled, 0u);

    a.bulk->setDefault(BulkScript::items());
    ASSERT_TRUE(results->waitTotal(4, scaled(3000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 4u);
}

// CA-24: latency_target_ms = 50 and a fake that answers after 200 ms: the window falls to 1 and the bulk target to its
// floor (bulk_min_bytes 4096), and the batches stay under the target; once the latency is gone the window is back at
// its maximum and the target uncapped within 10 s.
TEST_F(BulkLimiterTest, LatencyHalvesWindowAndBulk)
{
    constexpr std::uint64_t FLOOR = 4096;
    auto slow = BulkScript::items();
    slow.latency = 200ms;
    const auto a = startNode(std::move(slow));
    ASSERT_NO_FATAL_FAILURE(startOn(
        {a.url()}, std::chrono::hours(1), {{"latency_target_ms", "50"}, {"bulk_min_bytes", std::to_string(FLOOR)}}));
    auto c = client("c", {loadBucket("b", 1000, ic::Duration {100}, 32768)});
    Producer producer(c->writer("b"), 200, 1000);

    ASSERT_TRUE(
        eventually([] { return senderNode(0).window <= 1.0 && senderNode(0).bulkTarget == FLOOR; }, scaled(20000ms)))
        << describe(senderNode(0));
    const auto slowNode = senderNode(0);
    EXPECT_GE(slowNode.decreasesLatency, 2u) << describe(slowNode);
    EXPECT_EQ(slowNode.decreases429, 0u);
    const auto capped = Clock::now();
    std::this_thread::sleep_for(1500ms);
    const auto requests = bulkRequests(a);
    ASSERT_FALSE(requests.empty());
    EXPECT_GT(requests.front().bodySize, FLOOR) << "the first batch was not larger than the floor";
    std::size_t checked = 0;
    for (const auto& request : requests)
    {
        if (request.receivedAt > capped + 300ms)
        {
            ++checked;
            EXPECT_LE(request.bodySize, FLOOR) << "a batch over the bulk target";
        }
    }
    EXPECT_GE(checked, 3u);

    a.bulk->setDefault(BulkScript::items());
    EXPECT_TRUE(
        eventually([] { return senderNode(0).window >= kWindowMax && senderNode(0).bulkTarget == 0; }, scaled(10000ms)))
        << "not recovered without latency: " << describe(senderNode(0));
    producer.stop();
    ASSERT_TRUE(producer.waitResolved(30s));
    EXPECT_EQ(producer.failed(), 0u);
}

// CA-24: latency_target_ms = 50; eight answers at 200 ms (the ring's minimum), then fast ones: one latency decrease,
// the window at max / 2 before it recovers, and no second decrease from the same slow samples. Mutant: the ring is not
// emptied by the decrease.
TEST_F(BulkLimiterTest, LatencySpikeHalvesOnce)
{
    const auto a = startNode();
    for (int i = 0; i < 8; ++i)
    {
        auto slow = BulkScript::items();
        slow.latency = 200ms;
        a.bulk->push(std::move(slow));
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"latency_target_ms", "50"}}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 8; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(8, scaled(5000ms)));
    const auto spiked = senderNode(0);
    EXPECT_EQ(spiked.decreasesLatency, 1u) << describe(spiked);
    EXPECT_EQ(spiked.window, kWindowMax / 2.0) << describe(spiked);
    EXPECT_EQ(spiked.increases, 0u) << describe(spiked);

    for (std::uint64_t k = 8; k < 28; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        ASSERT_TRUE(results->waitTotal(k + 1, scaled(3000ms)));
    }
    const auto recovered = senderNode(0);
    EXPECT_EQ(recovered.decreasesLatency, 1u) << "the slow samples decreased twice: " << describe(recovered);
    EXPECT_EQ(recovered.window, static_cast<double>(kWindowMax)) << describe(recovered);
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 28u);
}

// CA-24 (G-diff E5a obj. 1): sixteen one-op batches queued at once, latency_target_ms = 50 and slow answers staged so
// that the window is full of slow requests when the ring reaches 8 samples: requests 1-4 answer after 200 ms, 5-7
// after 300 ms, 8 after 600 ms (the 8th sample, the decrease) and 9-11, sent at ~500 ms by the completions of 5-7,
// after 800 ms: they come back after the decrease. Then 12-16 answer at once. One latency decrease, the window at
// max / 2 until the in-flight requests return, and never below it afterwards: the samples of requests sent before the
// decrease do not enter the ring. Mutant: every response enters the ring (no sentAt filter).
TEST_F(BulkLimiterTest, LatencySpikeHalvesOnceUnderLoad)
{
    constexpr std::uint64_t OPS = 16;
    const auto a = startNode();
    const auto pushSlow = [&a](std::chrono::milliseconds latency, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            auto slow = BulkScript::items();
            slow.latency = latency;
            a.bulk->push(std::move(slow));
        }
    };
    pushSlow(200ms, 4);
    pushSlow(300ms, 3);
    pushSlow(600ms, 1);
    pushSlow(800ms, 3);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"latency_target_ms", "50"}}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(eventually([] { return senderNode(0).decreasesLatency >= 1; }, scaled(5000ms)))
        << describe(senderNode(0));
    const auto spiked = senderNode(0);
    EXPECT_EQ(spiked.decreasesLatency, 1u) << describe(spiked);
    EXPECT_EQ(spiked.window, kWindowMax / 2.0) << describe(spiked);
    EXPECT_EQ(spiked.inFlight, 3u) << "the window was not full of slow requests at the decrease: " << describe(spiked);

    double lowest = spiked.window;
    ASSERT_TRUE(eventually(
        [&]
        {
            lowest = std::min(lowest, senderNode(0).window);
            return results->total() == OPS;
        },
        scaled(10000ms)));
    const auto after = senderNode(0);
    EXPECT_EQ(after.decreasesLatency, 1u) << "the in-flight slow samples decreased again: " << describe(after);
    EXPECT_GE(lowest, kWindowMax / 2.0) << describe(after);
    EXPECT_GE(after.window, kWindowMax / 2.0) << describe(after);
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
}

// CA-24: four requests in flight (the whole window) come back 429 together from Available: one decrease (429), none
// from the Throttled hook, the window at max / 2. Mutant: a decrease on every 429 (or in the hook).
TEST_F(BulkLimiterTest, OneDecreasePerBurst)
{
    const auto a = startNode();
    for (std::uint32_t i = 0; i < kWindowMax; ++i)
    {
        a.bulk->push(BulkScript::throttled().held());
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"pace_initial_ms", "1000"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < kWindowMax; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(kWindowMax, scaled(3000ms)));
    a.fake->releaseHeld();
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == kWindowMax; }, scaled(3000ms)));
    const auto burst = senderNode(0);
    EXPECT_EQ(burst.decreases429, 1u) << describe(burst);
    EXPECT_EQ(burst.decreasesThrottled, 0u) << describe(burst);
    EXPECT_EQ(burst.window, kWindowMax / 2.0) << describe(burst);
    EXPECT_EQ(nodeState(0), NodeState::Throttled);

    ASSERT_TRUE(results->waitTotal(kWindowMax, scaled(10000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), kWindowMax);
    EXPECT_EQ(senderNode(0).decreasesThrottled, 0u);
    EXPECT_EQ(senderNode(0).decreases429, 1u);
}

// CA-24: the probe gets a 429 after a bulk left (sent after the last decrease): the Throttled hook decreases once; a
// second Throttled probe (no transition) and a new transition with no bulk sent since do not decrease again; a bulk
// sent afterwards makes the next transition decrease.
TEST_F(BulkLimiterTest, ProbeThrottledHalvesOnce)
{
    using indexer_client::testing::Durability;
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, scaled(3000ms)));

    setHealth(a, indexer_client::testing::throttledRule(Durability::Transient));
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Throttled);
    auto node = senderNode(0);
    EXPECT_EQ(node.decreasesThrottled, 1u) << describe(node);
    EXPECT_EQ(node.window, kWindowMax / 2.0) << describe(node);
    ASSERT_TRUE(probeNowAndWait());
    EXPECT_EQ(senderNode(0).decreasesThrottled, 1u) << "a second Throttled probe decreased again";

    setHealth(a, indexer_client::testing::healthRule("green"));
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available);
    setHealth(a, indexer_client::testing::throttledRule(Durability::Transient));
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Throttled);
    EXPECT_EQ(senderNode(0).decreasesThrottled, 1u) << "a transition with no bulk since the decrease decreased";

    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2, scaled(3000ms)));
    setHealth(a, indexer_client::testing::healthRule("green"));
    ASSERT_TRUE(probeNowAndWait());
    setHealth(a, indexer_client::testing::throttledRule(Durability::Transient));
    ASSERT_TRUE(probeNowAndWait());
    EXPECT_EQ(senderNode(0).decreasesThrottled, 2u) << describe(senderNode(0));
    EXPECT_EQ(senderNode(0).decreases429, 0u);
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
}

// CA-24: limiter X = 4 (B = 4) for 20 s, then no limit. With the defaults the window is back at its maximum and the
// bulk target uncapped within 15 s, and the pace relaxed one step within 9 s; with pace_relax_after = 5 the pace is 0
// within 20 s. Two runtimes, one after the other, against the same fake.
TEST_F(BulkLimiterTest, RecoversToMaxWhen429Stop)
{
    auto limiter = std::make_shared<TokenLimiter>(4.0, 4.0);
    const auto a = startLimitedNode(limiter);

    {
        SCOPED_TRACE("defaults");
        ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
        auto c = client("c", {loadBucket("b", 10, ic::Duration {500})});
        Producer producer(c->writer("b"), 200, 100);
        std::this_thread::sleep_for(20s);
        const auto limited = senderNode(0);
        ASSERT_GT(limited.pace, ic::Duration {0}) << describe(limited);
        limiter->setEnabled(false);
        const auto lifted = Clock::now();
        std::optional<Clock::duration> relaxedAfter;
        std::optional<Clock::duration> maxAfter;
        eventually(
            [&]
            {
                const auto node = senderNode(0);
                const auto t = Clock::now() - lifted;
                if (!relaxedAfter && node.paceRelaxed > limited.paceRelaxed)
                {
                    relaxedAfter = t;
                }
                if (!maxAfter && node.window >= kWindowMax && node.bulkTarget == 0)
                {
                    maxAfter = t;
                }
                return relaxedAfter && maxAfter;
            },
            scaled(15000ms));
        std::printf(
            "[  CA-24   ] RecoversToMaxWhen429Stop defaults: limited {%s}; relaxed after %lld ms, max after "
            "%lld ms\n",
            describe(limited).c_str(),
            relaxedAfter
                ? static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(*relaxedAfter).count())
                : -1LL,
            maxAfter ? static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(*maxAfter).count())
                     : -1LL);
        ASSERT_TRUE(relaxedAfter.has_value()) << "the pace never relaxed: " << describe(senderNode(0));
        EXPECT_LE(*relaxedAfter, scaled(9000ms));
        EXPECT_TRUE(maxAfter.has_value()) << "window/target not recovered: " << describe(senderNode(0));
        producer.stop();
        ASSERT_TRUE(producer.waitResolved(30s));
        EXPECT_EQ(producer.failed(), 0u);
        ASSERT_TRUE(eventually([this] { return drainedNow(); }, 5s));
    }
    m_ref = ic::RuntimeRef {};
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    m_path.reset();

    {
        SCOPED_TRACE("pace_relax_after = 5");
        limiter->setEnabled(true);
        ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"pace_relax_after", "5"}}));
        auto c = client("c", {loadBucket("b", 10, ic::Duration {500})});
        Producer producer(c->writer("b"), 200, 100);
        std::this_thread::sleep_for(20s);
        const auto limited = senderNode(0);
        limiter->setEnabled(false);
        const auto lifted = Clock::now();
        const bool zero = eventually([] { return senderNode(0).pace.count() == 0; }, scaled(20000ms));
        std::printf("[  CA-24   ] RecoversToMaxWhen429Stop pace_relax_after=5: limited {%s}; pace 0 after %lld ms\n",
                    describe(limited).c_str(),
                    static_cast<long long>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - lifted).count()));
        EXPECT_TRUE(zero) << describe(senderNode(0));
        producer.stop();
        ASSERT_TRUE(producer.waitResolved(30s));
        EXPECT_EQ(producer.failed(), 0u);
    }
}

// I98: a 429 to a batch of N bytes caps the bulk target at N / 2 (bulk_min_bytes 1024); while every later answer is
// held (no completion moves the target) every batch is <= the target, the throttled batch's ops come back from the
// retry lane in batches under it, and one op larger than the target leaves alone, the next op in a batch of its own.
// Mutant: the cap applied to the first op too (the large op never leaves).
TEST_F(BulkLimiterTest, BatchLimitCapsSlices)
{
    bulk_component::FakeIndexerOptions options;
    options.recordBodies = true;
    const auto a = startNode(BulkScript::items().held(), "green", options);
    a.bulk->push(BulkScript::throttled());
    ASSERT_NO_FATAL_FAILURE(
        startOn({a.url()}, std::chrono::hours(1), {{"node_window_max", "16"}, {"bulk_min_bytes", "1024"}}));
    auto c = client("c", {loadBucket("b", 1000, ic::Duration {200}, 16384)});
    auto writer = c->writer("b");
    auto results = Results::create();
    const auto small = wireSize(indexOp(id(0), 1000));
    const auto first = 16384 / small + 1; // The op that crosses maxBytes.
    for (std::uint64_t k = 0; k < first; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == 1; }, scaled(3000ms)));
    const auto n = bulkRequests(a).front().bodySize;
    const auto cap = senderNode(0).bulkTarget;
    EXPECT_EQ(cap, std::max<std::uint64_t>(1024, n / 2)) << "n " << n;
    ASSERT_LT(cap + small, n) << "the target must leave room for the case";

    const auto opsSent = [&a]()
    {
        std::size_t total = 0;
        const auto requests = bulkRequests(a);
        for (std::size_t i = 1; i < requests.size(); ++i)
        {
            total += opsIn(requests[i]);
        }
        return total;
    };
    ASSERT_TRUE(eventually([&] { return opsSent() == first; }, scaled(3000ms))) << opsSent() << " of " << first;
    const auto big = wireSize(indexOp(id(first), 12000));
    ASSERT_GT(big, cap);
    ASSERT_TRUE(writer->submit(indexOp(id(first), 12000), results->callback(first)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(first + 1), 1000), results->callback(first + 1)).accepted);
    ASSERT_TRUE(eventually([&] { return opsSent() == first + 2; }, scaled(3000ms)))
        << "the op larger than the target never left: " << opsSent() << " of " << first + 2;

    const auto requests = bulkRequests(a);
    std::size_t alone = 0;
    std::size_t multi = 0;
    for (std::size_t i = 1; i < requests.size(); ++i)
    {
        const auto ops = opsIn(requests[i]);
        if (requests[i].bodySize > cap)
        {
            ++alone;
            EXPECT_EQ(ops, 1u) << "a batch over the target with more than one op";
            EXPECT_EQ(requests[i].bodySize, big);
        }
        multi += ops > 1 ? 1 : 0;
    }
    EXPECT_EQ(alone, 1u);
    EXPECT_GE(multi, 2u) << "the retry lane's ops were not batched under the target";
    EXPECT_EQ(senderNode(0).bulkTarget, cap) << "no completion may have moved it";

    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(first + 2, scaled(5000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), first + 2);
}

// I98: a 413 to a 15-op batch of N bytes splits it and caps the bulk target at N / 2 without touching the window or the
// decrease counters; while the answers are held, the halves and the next batch are <= N / 2.
TEST_F(BulkLimiterTest, Payload413CapsTarget)
{
    constexpr std::uint64_t OPS = 15;
    bulk_component::FakeIndexerOptions options;
    options.recordBodies = true;
    const auto a = startNode(BulkScript::items().held(), "green", options);
    a.bulk->push(BulkScript::tooLarge());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", OPS, ic::Duration {200})});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    ASSERT_TRUE(eventually([] { return wr::senderStats().splits == 1; }, scaled(3000ms)));
    const auto n = bulkRequests(a).front().bodySize;
    EXPECT_EQ(opsIn(bulkRequests(a).front()), OPS);
    auto node = senderNode(0);
    EXPECT_LE(node.bulkTarget, n / 2) << describe(node);
    EXPECT_GT(node.bulkTarget, 0u) << describe(node);
    EXPECT_EQ(node.window, static_cast<double>(kWindowMax)) << describe(node);
    EXPECT_EQ(node.decreases429 + node.decreasesThrottled + node.decreasesLatency, 0u) << describe(node);

    for (std::uint64_t k = OPS; k < 2 * OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(kWindowMax, scaled(3000ms)));
    const auto requests = bulkRequests(a);
    ASSERT_EQ(requests.size(), 1u + kWindowMax);
    std::size_t fresh = 0;
    for (std::size_t i = 1; i < requests.size(); ++i)
    {
        EXPECT_LE(requests[i].bodySize, n / 2) << "request " << i;
        const auto body = requests[i].body;
        fresh += body.find(id(OPS)) != std::string::npos ? 1 : 0;
    }
    EXPECT_EQ(fresh, 1u) << "the first batch of the new ops was not among the held ones";
    node = senderNode(0);
    EXPECT_EQ(node.window, static_cast<double>(kWindowMax)) << describe(node);

    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(2 * OPS, scaled(5000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2 * OPS);
}

// D47: node_window_max = 4 and two 429 bursts bring A's window to 1 (no success moves it back: the answer that follows
// is slower than latency_target_ms); an ordered batch takes A's only slot, an unordered batch queues behind it, and the
// ordered batch's answer is cut after A applied it (pinned to A, A Down). The probe brings A back: the unordered batch
// takes A's only slot (held) and the pinned one waits. B then becomes usable, so the scheduler has capacity: the pinned
// batch is sent 0 times to A while A's inFlight is 1, at most 2 "no usable node" requeues happen, and it leaves < 500
// ms after the release. Mutant: wakePinned tests the slot against nodeWindowMax.
TEST_F(BulkLimiterTest, PinnedWaitsForTheRealWindow)
{
    constexpr std::uint64_t PINNED = 100;
    const auto cut = std::make_shared<std::atomic<bool>>(false);
    const auto a = startNode(BulkScript::items(),
                             "green",
                             {},
                             [cut](const httplib::Request& request, Rule& reply)
                             {
                                 if (request.body.find(id(PINNED)) != std::string::npos && cut->exchange(false))
                                 {
                                     // A applied the bulk; the answer, held until the case releases it, is cut.
                                     reply.hold = true;
                                     reply.cutAfter = 5;
                                 }
                             });
    a.bulk->push(BulkScript::throttled());
    a.bulk->push(BulkScript::throttled());
    auto slowOk = BulkScript::items();
    slowOk.latency = 400ms;
    a.bulk->push(std::move(slowOk));
    const auto b = startNode();
    setHealth(b, indexer_client::testing::healthStatusRule(503));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()},
                                    std::chrono::hours(1),
                                    {{"latency_target_ms", "300"}, {"ambiguous_retry_window_ms", "20000"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Down);
    auto c = client("c", {loadBucket("u", 1), loadBucket("o", 1, ic::Duration {200}, 0, true)});
    auto results = Results::create();

    // Two 429 bursts, then a slow success: A's window is 1.
    ASSERT_TRUE(c->writer("u")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, scaled(5000ms)));
    ASSERT_EQ(a.bulk->answered(), 3u);
    auto node = senderNode(0);
    ASSERT_EQ(node.window, 1.0) << describe(node);
    ASSERT_EQ(node.decreases429, 2u) << describe(node);
    ASSERT_TRUE(eventually(
        []
        {
            const auto n = senderNode(0);
            return !n.notBefore && !n.nextSendAt;
        },
        scaled(3000ms)));

    // The ordered batch reaches A and its answer is cut: pinned to A, A Down.
    cut->store(true);
    ASSERT_TRUE(c->writer("o")->submit(indexOp(id(PINNED)), results->callback(PINNED)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(3000ms)));

    // An unordered batch queued while A's only slot is taken: its bucket's turn is cut with the scheduler's cursor on
    // it. Then the pinned batch's answer is cut: pinned to A, A Down, its bucket queued behind the unordered one.
    a.bulk->push(BulkScript::items().held());
    ASSERT_TRUE(c->writer("u")->submit(indexOp(id(1)), results->callback(1)).accepted);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 4; }, 200ms));
    a.fake->releaseHeld();
    ASSERT_TRUE(eventually([this] { return stats("o").orderedAmbiguous == 1; }, scaled(3000ms)));
    ASSERT_TRUE(eventually([] { return nodeState(0) == NodeState::Down; }, scaled(1000ms)));
    a.fake->rearmHold();
    EXPECT_EQ(senderNode(0).window, 1.0) << "the failure moved the window";
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 4; }, 200ms)) << "a bulk reached A while Down";

    // The probe brings A back: the unordered batch takes A's only slot.
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(3000ms)));
    const auto pinnedSends = [&a]()
    {
        std::size_t n = 0;
        for (const auto& ops : a.bulk->received())
        {
            for (const auto& op : ops)
            {
                n += op.id == id(PINNED) ? 1 : 0;
            }
        }
        return n;
    };
    ASSERT_EQ(pinnedSends(), 1u) << "the pinned batch took A's slot before the unordered one";
    node = senderNode(0);
    EXPECT_EQ(node.window, 1.0) << "Down -> Available must keep the window: " << describe(node);
    EXPECT_EQ(node.inFlight, 1u);

    // B usable: the scheduler has capacity while A's window is full.
    const auto batches = schedulerBatches();
    setHealth(b, indexer_client::testing::healthRule("green"));
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(1), NodeState::Available);
    EXPECT_FALSE(eventually([&] { return pinnedSends() > 1; }, scaled(500ms))) << "the pinned batch went to A";
    EXPECT_EQ(senderNode(0).inFlight, 1u);
    EXPECT_LE(schedulerBatches() - batches, 2u) << "the pinned batch spun through \"no usable node\" requeues";
    EXPECT_EQ(b.bulk->answered(), 0u) << "the pinned batch went to B";

    const auto released = Clock::now();
    a.fake->releaseHeld();
    ASSERT_TRUE(eventually([&] { return pinnedSends() == 2; }, scaled(500ms)))
        << "the pinned batch did not leave after the release: " << describe(senderNode(0));
    EXPECT_LT(Clock::now() - released, scaled(500ms));
    ASSERT_TRUE(results->waitTotal(3, scaled(3000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    EXPECT_EQ(b.bulk->answered(), 0u);
    EXPECT_EQ(stats("o").orderedAmbiguousFailover, 0u);
}

// I95: with A's window full (four bulks held), a search goes and comes back Ok, and the window's inFlight does not
// move.
TEST_F(BulkLimiterTest, QueriesIgnoreWindow)
{
    const auto a = startNode(BulkScript::items().held());
    Rule search;
    search.method = "POST";
    search.pathRegex = "/idx/_search";
    search.body = R"({"took":1,"timed_out":false,"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}})";
    a.fake->addRule(search);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < kWindowMax; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(kWindowMax, scaled(3000ms)));
    ASSERT_EQ(senderNode(0).inFlight, kWindowMax);

    const auto out = c->query()->search("idx", {{"query", {{"match_all", nlohmann::json::object()}}}}, {}, now() + 5s);
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(senderNode(0).inFlight, kWindowMax);
    EXPECT_EQ(a.fake->heldNow(), kWindowMax);

    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(kWindowMax, scaled(3000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), kWindowMax);
}

// I97b: two weight-1 buckets of ~2 KB one-op batches and the default DRR quantum (1 MiB), against a node that answers
// after 20 ms: the first bucket holds 300 batches, yet the second one's first batch leaves < 500 ms after it was queued
// (without DRR_MAX_BATCHES_PER_TURN the 1 MiB quantum would keep the first bucket's turn for ~1.5 s).
TEST_F(BulkLimiterTest, DefaultQuantumYieldsSoon)
{
    constexpr std::uint64_t FIRST = 300;
    constexpr std::uint64_t SECOND = 10;
    auto script = BulkScript::items();
    script.latency = 20ms;
    bulk_component::FakeIndexerOptions options;
    options.recordBodies = true;
    const auto a = startNode(std::move(script), "green", options);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("one", 1), loadBucket("two", 1)});
    auto results = Results::create();
    for (std::uint64_t k = 0; k < FIRST; ++k)
    {
        ASSERT_TRUE(c->writer("one")->submit(indexOp(id(k), 2000, "idx-one"), results->callback(k)).accepted);
    }
    const auto queued = Clock::now();
    for (std::uint64_t k = FIRST; k < FIRST + SECOND; ++k)
    {
        ASSERT_TRUE(c->writer("two")->submit(indexOp(id(k), 2000, "idx-two"), results->callback(k)).accepted);
    }
    std::optional<Clock::time_point> firstTwo;
    ASSERT_TRUE(eventually(
        [&]
        {
            for (const auto& request : bulkRequests(a))
            {
                if (request.body.find("idx-two") != std::string::npos)
                {
                    firstTwo = request.receivedAt;
                    return true;
                }
            }
            return false;
        },
        scaled(5000ms)));
    EXPECT_LT(*firstTwo - queued, scaled(500ms)) << "the second bucket waited for the first one's turn";
    ASSERT_TRUE(results->waitTotal(FIRST + SECOND, scaled(10000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), FIRST + SECOND);
}

// I97b (G-diff E5a obj. 2): one bucket, ~2 MiB of ~2 KB documents pending at once (maxAge 2 s, maxBytes and maxDocs out
// of the way) and the default configuration: the batches are bounded by the 1 MiB quantum, not by the old 64 KiB one —
// some batch is larger than 64 KiB, none larger than the quantum plus one op (credit left from a previous turn is
// below the head's size).
TEST_F(BulkLimiterTest, DefaultBulkNotCappedByOldQuantum)
{
    constexpr std::uint64_t OPS = 1000;
    constexpr std::size_t OLD_QUANTUM = 64 * 1024;
    const auto quantum = ic::RuntimeConfig {}.drrQuantumBytes;
    ASSERT_EQ(quantum, 1u << 20);
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {loadBucket("b", 100000, ic::Duration {2000})});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 2000), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(OPS, scaled(10000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);

    const auto requests = bulkRequests(a);
    ASSERT_FALSE(requests.empty());
    std::size_t largest = 0;
    for (const auto& request : requests)
    {
        largest = std::max(largest, request.bodySize);
        EXPECT_LE(request.bodySize, quantum + 4096) << "a batch over the DRR quantum";
    }
    std::printf(
        "[  I97b    ] DefaultBulkNotCappedByOldQuantum: %zu requests, largest %zu bytes\n", requests.size(), largest);
    EXPECT_GT(largest, OLD_QUANTUM) << "every batch within the old 64 KiB quantum";
}

// I97b (G-diff E5a obj. 2): two weight-1 buckets of one-op batches, node_window_max = 1 so the sender takes one batch
// at a time and the dispatch order is the arrival order. A held batch of a third bucket fills the window while both are
// queued (20 ops each), so both are in the DRR ring when it is released: the first bucket's turn ends after
// weight x DRR_MAX_BATCHES_PER_TURN = 8 batches and the second one's first batch arrives before the first one's 9th;
// every run of one bucket while the other still has ops is <= 8. Mutant: no cap on the batches per turn.
TEST_F(BulkLimiterTest, TurnYieldsAfterMaxBatches)
{
    constexpr std::uint64_t PER_BUCKET = 20;
    bulk_component::FakeIndexerOptions options;
    options.recordBodies = true;
    const auto a = startNode(BulkScript::items(), "green", options);
    a.bulk->push(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"node_window_max", "1"}}));
    auto c = client("c", {loadBucket("zero", 1), loadBucket("one", 1), loadBucket("two", 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("zero")->submit(indexOp(id(0), 16, "idx-zero"), results->callback(0)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(3000ms)));
    for (std::uint64_t k = 1; k <= PER_BUCKET; ++k)
    {
        ASSERT_TRUE(c->writer("one")->submit(indexOp(id(k), 16, "idx-one"), results->callback(k)).accepted);
    }
    for (std::uint64_t k = PER_BUCKET + 1; k <= 2 * PER_BUCKET; ++k)
    {
        ASSERT_TRUE(c->writer("two")->submit(indexOp(id(k), 16, "idx-two"), results->callback(k)).accepted);
    }
    a.fake->releaseHeld();
    ASSERT_TRUE(results->waitTotal(2 * PER_BUCKET + 1, scaled(10000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2 * PER_BUCKET + 1);

    std::string order; // '1' / '2' per batch of bucket one / two, in arrival order.
    for (const auto& request : bulkRequests(a))
    {
        ASSERT_EQ(opsIn(request), 1u);
        if (request.body.find("idx-zero") == std::string::npos)
        {
            order.push_back(request.body.find("idx-one") != std::string::npos ? '1' : '2');
        }
    }
    ASSERT_EQ(order.size(), 2 * PER_BUCKET) << order;
    const auto firstRun = order.find_first_not_of(order.front());
    EXPECT_LE(firstRun, wr::DRR_MAX_BATCHES_PER_TURN) << "the second bucket waited for the first one's turn: " << order;
    // Every run before the last one (the last is the bucket left alone) stays within the cap.
    const auto last = order.find_last_not_of(order.back());
    std::size_t run = 0;
    for (std::size_t i = 0; i <= last && last != std::string::npos; ++i)
    {
        run = i > 0 && order[i] == order[i - 1] ? run + 1 : 1;
        EXPECT_LE(run, wr::DRR_MAX_BATCHES_PER_TURN) << "a turn over the cap at " << i << ": " << order;
    }
    std::printf("[  I97b    ] TurnYieldsAfterMaxBatches order: %s\n", order.c_str());
}

/// Bucket::slice with a chosen cap (I98): the test sink holds every batch and has no capacity, so the scheduler never
/// slices; the case submits, then drives slice() itself (as writeRetryLane_test.cpp).
class BulkLimiterSliceTest : public WriteTest
{
protected:
    static constexpr std::uint64_t ALL = std::numeric_limits<std::uint64_t>::max();

    /// Submits `count` ops (keys firstKey..) and holds the single batch the bucket forms (its bulk.maxDocs must be
    /// reached by exactly these ops). The sink's capacity is 0 again afterwards.
    wr::Batch deliver(const std::shared_ptr<ic::IWriter>& writer,
                      const std::shared_ptr<Results>& results,
                      std::uint64_t firstKey,
                      std::size_t count,
                      std::size_t bodyBytes = 100)
    {
        const auto before = m_sink->dispatched();
        m_sink->setCapacity(1);
        for (std::size_t i = 0; i < count; ++i)
        {
            EXPECT_TRUE(writer->submit(indexOp(id(firstKey + i), bodyBytes), results->callback(firstKey + i)).accepted);
        }
        EXPECT_TRUE(m_sink->waitDispatched(before + 1));
        auto held = m_sink->take();
        EXPECT_EQ(held.size(), 1U);
        if (held.size() != 1)
        {
            return {};
        }
        EXPECT_EQ(held[0].ops.size(), count);
        return std::move(held[0]);
    }

    void resolveAll(const std::vector<std::shared_ptr<wr::OpState>>& ops)
    {
        for (const auto& op : ops)
        {
            m_path->resolve(op, TestSink::ok());
        }
    }

    /// Ops per slice until the bucket is empty.
    std::vector<std::size_t> drainSizes(const std::shared_ptr<wr::Bucket>& bucket, std::uint64_t cap)
    {
        std::vector<std::size_t> sizes;
        for (int i = 0; i < 100 && !bucket->empty(); ++i)
        {
            auto batch = bucket->slice(ALL, now(), cap);
            sizes.push_back(batch.ops.size());
            resolveAll(batch.ops);
        }
        return sizes;
    }
};

// I98: cap = 0 is the slice of before E5a (bulk.maxDocs, the credit), the same as a cap no batch reaches.
TEST_F(BulkLimiterSliceTest, SliceCapZeroUnchanged)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c",
                    {bucketSpec("zero", 1u << 20, ic::Overflow::Kind::Reject, 0, 4),
                     bucketSpec("huge", 1u << 20, ic::Overflow::Kind::Reject, 0, 4)});
    auto results = Results::create();
    auto zero = deliver(c->writer("zero"), results, 0, 4);
    auto huge = deliver(c->writer("huge"), results, 100, 4);
    ASSERT_TRUE(zero.bucket && huge.bucket);
    resolveAll(zero.ops);
    resolveAll(huge.ops);
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        ASSERT_TRUE(c->writer("zero")->submit(indexOp(id(10 + k)), results->callback(10 + k)).accepted);
        ASSERT_TRUE(c->writer("huge")->submit(indexOp(id(110 + k)), results->callback(110 + k)).accepted);
    }
    const auto w = wireSize(indexOp(id(0)));
    const auto credited = zero.bucket->slice(5 * w / 2, now(), 0);
    EXPECT_EQ(credited.ops.size(), 2u) << "the credit still limits";
    resolveAll(credited.ops);
    const auto creditedHuge = huge.bucket->slice(5 * w / 2, now(), ALL);
    EXPECT_EQ(creditedHuge.ops.size(), 2u);
    resolveAll(creditedHuge.ops);
    EXPECT_EQ(drainSizes(zero.bucket, 0), (std::vector<std::size_t> {4, 4}));
    EXPECT_EQ(drainSizes(huge.bucket, ALL), (std::vector<std::size_t> {4, 4}));
    ASSERT_TRUE(results->waitTotal(28));
}

// I98: an op larger than the cap at the head of the batch leaves alone (a document is never split), and the next op
// does not join it; the ops after it are batched under the cap.
TEST_F(BulkLimiterSliceTest, SliceFirstOpOverCapGoesAlone)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 10)});
    auto results = Results::create();
    auto first = deliver(c->writer("b"), results, 0, 10);
    ASSERT_TRUE(first.bucket);
    resolveAll(first.ops);
    const auto w = wireSize(indexOp(id(0)));
    const auto big = wireSize(indexOp(id(10), 3000));
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(10), 3000), results->callback(10)).accepted);
    for (std::uint64_t k = 11; k < 14; ++k)
    {
        ASSERT_TRUE(c->writer("b")->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    const auto cap = 5 * w / 2;
    ASSERT_GT(big, cap);
    const auto alone = first.bucket->slice(ALL, now(), cap);
    ASSERT_EQ(alone.ops.size(), 1u) << "the head op over the cap must leave alone";
    EXPECT_EQ(alone.bytes, big);
    resolveAll(alone.ops);
    EXPECT_EQ(drainSizes(first.bucket, cap), (std::vector<std::size_t> {2, 1}));
    ASSERT_TRUE(results->waitTotal(14));
}

// I98: the cap also bounds the batches taken from the retry lane (and a batch mixing the lane and the pending queue).
TEST_F(BulkLimiterSliceTest, SliceCapAppliesToRetryLane)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 6)});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 6);
    ASSERT_TRUE(batch.bucket);
    std::vector<wr::RequeueOp> requeue;
    for (const auto& op : batch.ops)
    {
        requeue.push_back(wr::RequeueOp {op, wr::LastError {ic::Cause::Throttled, 429, {}, "throttled"}});
    }
    wr::RequeueSpec spec;
    spec.countAttempt = false;
    spec.delay = wr::RequeueSpec::Delay::Now;
    const auto requeued = batch.bucket->requeue(std::move(requeue), spec, now());
    ASSERT_TRUE(requeued.exhausted.empty());
    for (std::uint64_t k = 6; k < 9; ++k)
    {
        ASSERT_TRUE(c->writer("b")->submit(indexOp(id(k), 100), results->callback(k)).accepted);
    }
    const auto w = wireSize(indexOp(id(0), 100)); // deliver()'s ops.
    EXPECT_EQ(drainSizes(batch.bucket, 2 * w), (std::vector<std::size_t> {2, 2, 2, 2, 1}));
    ASSERT_TRUE(results->waitTotal(9));
}
