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

// The scheduler: batches by threshold, DRR by weight, whole documents, and the thread budget with buckets
// (plan-E3a §Tests: I63, I23, RF-3, T3a, CA-1/T1).

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"

using namespace write_component;
using component::eventually;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;
    constexpr std::uint64_t QUANTUM = 64 * 1024;

    std::string id(std::size_t n)
    {
        auto digits = std::to_string(n);
        return "s" + std::string(7 - digits.size(), '0') + digits;
    }

    /// Bytes and batches per bucket over a slice of the dispatch log.
    struct Share final
    {
        std::map<std::string, std::uint64_t> bytes;
        std::map<std::string, std::uint64_t> batches;
    };

    Share shareOf(const std::vector<DispatchRecord>& log, std::size_t from, std::size_t to)
    {
        Share share;
        for (std::size_t i = from; i < to && i < log.size(); ++i)
        {
            share.bytes[log[i].bucket] += log[i].bytes;
            ++share.batches[log[i].bucket];
        }
        return share;
    }

    /// Submits `count` ops of `bodyBytes` to `writer`; all must be accepted.
    void fill(const std::shared_ptr<ic::IWriter>& writer, std::size_t count, std::size_t bodyBytes, std::size_t base)
    {
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto submit = writer->submit(indexOp(id(base + i), bodyBytes));
            ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause) << " at " << i;
        }
    }
} // namespace

// I63: a batch forms when the pending bytes reach bulk.maxBytes, when the pending docs reach bulk.maxDocs, and, for a
// single op under every threshold, when it reaches bulk.maxAge — and not before.
TEST_F(WriteTest, ThresholdsFormBatches)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto size = wireSize(indexOp(id(0), 500));
    auto c = client("c",
                    {bucketSpec("bytes", 1u << 20, ic::Overflow::Kind::Reject, 4 * size),
                     bucketSpec("docs", 1u << 20, ic::Overflow::Kind::Reject, 0, 5),
                     bucketSpec("age", 1u << 20, ic::Overflow::Kind::Reject, 0, 1000000, ic::Duration {300})});

    // maxBytes: 3 ops stay pending, the 4th reaches it.
    auto bytes = c->writer("bytes");
    fill(bytes, 3, 500, 0);
    std::this_thread::sleep_for(100ms); // Measured window: nothing may leave below every threshold.
    EXPECT_EQ(sink->dispatched(), 0u);
    fill(bytes, 1, 500, 3);
    ASSERT_TRUE(sink->waitDispatched(1, 2s));
    auto log = sink->log();
    EXPECT_EQ(log[0].bucket, "bytes");
    EXPECT_EQ(log[0].ops, 4u);
    EXPECT_EQ(log[0].bytes, 4 * size);

    // maxDocs: 4 ops stay pending, the 5th reaches it.
    auto docs = c->writer("docs");
    fill(docs, 4, 500, 10);
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(sink->dispatched(), 1u);
    fill(docs, 1, 500, 14);
    ASSERT_TRUE(sink->waitDispatched(2, 2s));
    log = sink->log();
    EXPECT_EQ(log[1].bucket, "docs");
    EXPECT_EQ(log[1].ops, 5u);

    // maxAge: one op, under every threshold, leaves at 300 ms and not before.
    auto age = c->writer("age");
    const auto t0 = now();
    fill(age, 1, 500, 20);
    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(sink->dispatched(), 2u) << "not before maxAge";
    ASSERT_TRUE(sink->waitDispatched(3, 2s));
    log = sink->log();
    EXPECT_EQ(log[2].bucket, "age");
    EXPECT_EQ(log[2].ops, 1u);
    EXPECT_GE(log[2].at - t0, 290ms);
    EXPECT_LT(log[2].at - t0, 1s);
    EXPECT_GE(m_path->scheduler()->stats().timerFires, 1u);

    EXPECT_EQ(sink->resolveHeld(), 10u);
}

// T3a/I23: weights 1 and 8 with a continuous backlog and a sink that takes 20 batches per window (a full DRR round is
// 2 + 16): the weight-1 bucket gets batches in every window.
TEST_F(WriteTest, DrrNoStarvation)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"drr_quantum_bytes", std::to_string(QUANTUM)}}));
    auto sink = installSink(TestSink::Mode::Hold, 0);
    auto light = bucketSpec("light", 32u << 20, ic::Overflow::Kind::Reject, 32 * 1024);
    light.weight = 1;
    auto heavy = bucketSpec("heavy", 32u << 20, ic::Overflow::Kind::Reject, 32 * 1024);
    heavy.weight = 8;
    auto c = client("c", {light, heavy});
    fill(c->writer("light"), 1500, 1000, 0);
    fill(c->writer("heavy"), 7000, 1000, 100000);

    constexpr std::size_t WINDOWS = 10;
    constexpr std::size_t PER_WINDOW = 20;
    for (std::size_t w = 0; w < WINDOWS; ++w)
    {
        SCOPED_TRACE("window " + std::to_string(w));
        const auto before = sink->dispatched();
        sink->grant(PER_WINDOW);
        ASSERT_TRUE(sink->waitDispatched(before + PER_WINDOW));
        const auto share = shareOf(sink->log(), before, before + PER_WINDOW);
        EXPECT_GT(share.batches.count("light") ? share.batches.at("light") : 0u, 0u) << "the light bucket starved";
        EXPECT_GT(share.batches.count("heavy") ? share.batches.at("heavy") : 0u, 0u);
        sink->resolveHeld();
    }
    const auto total = shareOf(sink->log(), 0, WINDOWS * PER_WINDOW);
    EXPECT_GT(total.bytes.at("heavy"), 4 * total.bytes.at("light")) << "the weight still shows";
    closeNow(*c); // The backlog left: Dropped(ClientClosed) at the sweep (the sink has no capacity).
    expectInvariants(stats("light"));
    expectInvariants(stats("heavy"));
}

// RF-3/I23: with a fixed capacity the bytes sent follow the weights within 10 %: 1:3, and 1:8 with bulk.maxBytes
// below quantum x weight (several batches per turn).
TEST_F(WriteTest, DrrShareByWeight)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"drr_quantum_bytes", std::to_string(QUANTUM)}}));
    auto sink = installSink(TestSink::Mode::Hold, 0);
    const std::size_t maxBytes = 16 * 1024;
    const auto size = wireSize(indexOp(id(0), 4000));
    ASSERT_LT(maxBytes, QUANTUM);
    ASSERT_EQ(maxBytes / size, 4u) << "four ops per batch";

    struct Scenario final
    {
        std::string consumer;
        std::uint32_t heavyWeight;
        std::size_t lightOps;
        std::size_t heavyOps;
        std::size_t perWindow; ///< One DRR round in batches: 4 + 4 x weight.
        std::size_t windows;
    };
    std::size_t base = 0;
    for (const auto& sc : {Scenario {"a", 3, 400, 1100, 16, 20}, Scenario {"b", 8, 260, 1450, 36, 10}})
    {
        SCOPED_TRACE("1:" + std::to_string(sc.heavyWeight));
        auto light = bucketSpec("light", 12u << 20, ic::Overflow::Kind::Reject, maxBytes);
        light.weight = 1;
        auto heavy = bucketSpec("heavy", 12u << 20, ic::Overflow::Kind::Reject, maxBytes);
        heavy.weight = sc.heavyWeight;
        ASSERT_LT(maxBytes, QUANTUM * heavy.weight);
        auto c = client(sc.consumer, {light, heavy});
        fill(c->writer("light"), sc.lightOps, 4000, base);
        fill(c->writer("heavy"), sc.heavyOps, 4000, base + 100000);
        base += 1000000;

        const auto first = sink->dispatched();
        for (std::size_t w = 0; w < sc.windows; ++w)
        {
            const auto before = sink->dispatched();
            sink->grant(sc.perWindow);
            ASSERT_TRUE(sink->waitDispatched(before + sc.perWindow));
            sink->resolveHeld();
        }
        const auto share = shareOf(sink->log(), first, first + sc.windows * sc.perWindow);
        ASSERT_EQ(share.bytes.size(), 2u);
        const double ratio = static_cast<double>(share.bytes.at("heavy")) / share.bytes.at("light");
        EXPECT_NEAR(ratio, sc.heavyWeight, 0.1 * sc.heavyWeight)
            << "light " << share.bytes.at("light") << " heavy " << share.bytes.at("heavy");
        EXPECT_GT(stats("heavy", sc.consumer).retained, 4u) << "the backlog lasted the whole measurement";
        EXPECT_GT(stats("light", sc.consumer).retained, 4u);
        closeNow(*c);
        expectInvariants(stats("light", sc.consumer));
        expectInvariants(stats("heavy", sc.consumer));
    }
}

// I23: a document larger than the quantum is never split: it leaves whole once its bucket has accumulated the credit
// over several turns (the credit carries over).
TEST_F(WriteTest, DocumentNeverSplitCreditCarries)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"drr_quantum_bytes", std::to_string(QUANTUM)}}));
    auto sink = installSink();
    auto c = client("c", {bucketSpec("big", 1u << 20, ic::Overflow::Kind::Reject, 512 * 1024, 1)});
    auto writer = c->writer("big");
    const auto size = wireSize(indexOp(id(0), 200 * 1024));
    ASSERT_GT(size, 3 * QUANTUM);

    ASSERT_TRUE(writer->submit(indexOp(id(0), 200 * 1024)).accepted);
    const bool sent = sink->waitDispatched(1, 3s);
    if (!sent)
    {
        c->requestClose(); // A scheduler that never covers the head spins on loop 0: closing empties the bucket.
    }
    ASSERT_TRUE(sent) << "the document never left";
    auto batches = sink->take();
    ASSERT_EQ(batches.size(), 1u);
    ASSERT_EQ(batches[0].ops.size(), 1u);
    EXPECT_EQ(batches[0].bytes, size) << "whole";
    EXPECT_EQ(batches[0].ops[0]->lines.size(), size);
    m_path->resolve(batches[0].ops[0], TestSink::ok());

    // The credit left after it (4 quanta - size) still serves the next small op in the same way.
    ASSERT_TRUE(writer->submit(indexOp(id(1), 100)).accepted);
    ASSERT_TRUE(sink->waitDispatched(2, 3s));
    EXPECT_EQ(sink->resolveHeld(), 1u);
    expectInvariants(stats("big"));
}

// CA-1/T1: C clients x B buckets writing through the scheduler and the production sink (the bulk sender, E3b-2, to a
// fake node started before the base sample) add no thread: the runtime's own threads stay K + M (K = 1 and 3).
TEST_F(BulkTest, ThreadsStayKPlusMWithBuckets)
{
    constexpr std::uint32_t M = 2;
    constexpr std::size_t CLIENTS = 3;
    constexpr std::size_t BUCKETS = 3;
    constexpr std::size_t OPS = 20; // A multiple of maxDocs (4): every batch leaves by maxDocs, none waits on maxAge.
    const auto node = startNode();  // Its server threads belong to the base.
    for (const std::uint32_t k : {1u, 3u})
    {
        SCOPED_TRACE("K=" + std::to_string(k));
        const auto base = component::settledTasks();
        hooks::clearRuntimeThreads();
        ASSERT_NO_FATAL_FAILURE(startOn({node.url()},
                                        std::chrono::hours(1),
                                        {{"network_threads", std::to_string(k)}, {"cpu_threads", std::to_string(M)}}));
        {
            auto results = Results::create();
            std::vector<std::shared_ptr<ic::Client>> clients;
            std::uint64_t key = 0;
            for (std::size_t ci = 0; ci < CLIENTS; ++ci)
            {
                std::vector<ic::BucketSpec> specs;
                for (std::size_t bi = 0; bi < BUCKETS; ++bi)
                {
                    specs.push_back(bucketSpec(
                        "b" + std::to_string(bi), 1u << 20, ic::Overflow::Kind::Reject, 0, 4, ic::Duration {50}));
                }
                clients.push_back(client("c" + std::to_string(ci), specs));
                for (std::size_t bi = 0; bi < BUCKETS; ++bi)
                {
                    auto writer = clients.back()->writer("b" + std::to_string(bi));
                    for (std::size_t i = 0; i < OPS; ++i)
                    {
                        ASSERT_TRUE(writer->submit(indexOp(id(key), 200), results->callback(key)).accepted);
                        ++key;
                    }
                }
            }
            ASSERT_TRUE(results->waitTotal(key, 10s)) << results->total() << " of " << key;
            EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), key) << "written by the production sink";

            const auto sample = component::settledTasks();
            std::set<std::string> delta;
            std::set_difference(
                sample.begin(), sample.end(), base.begin(), base.end(), std::inserter(delta, delta.begin()));
            EXPECT_EQ(delta.size(), k + M) << "threads over the base with " << CLIENTS * BUCKETS << " buckets";
            ASSERT_TRUE(eventually([&] { return hooks::runtimeThreads().size() >= k + M; }, 5s));
            EXPECT_EQ(hooks::runtimeThreads().size(), k + M) << "own TIDs";
            ASSERT_TRUE(eventually([this] { return drainedNow(); }, 5s)) << describe(m_path->stats());
        }
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        m_path.reset();
    }
}

// I23 (root fix, step 6): with a quantum tiny against the documents (1 byte against ~4 KB), DRR fast-forwards the idle
// rounds instead of spinning through them on loop 0, and the share by weight holds.
TEST_F(WriteTest, DrrTinyQuantumFastForwards)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"drr_quantum_bytes", "1"}}));
    auto sink = installSink(TestSink::Mode::Hold, 0);
    const std::size_t maxBytes = 16 * 1024;
    auto light = bucketSpec("light", 12u << 20, ic::Overflow::Kind::Reject, maxBytes);
    light.weight = 1;
    auto heavy = bucketSpec("heavy", 12u << 20, ic::Overflow::Kind::Reject, maxBytes);
    heavy.weight = 3;
    auto c = client("c", {light, heavy});
    fill(c->writer("light"), 400, 4000, 0);
    fill(c->writer("heavy"), 1100, 4000, 100000);

    const auto first = sink->dispatched();
    const auto started = std::chrono::steady_clock::now();
    constexpr std::size_t WINDOWS = 20;
    constexpr std::size_t PER_WINDOW = 16;
    for (std::size_t w = 0; w < WINDOWS; ++w)
    {
        const auto before = sink->dispatched();
        sink->grant(PER_WINDOW);
        ASSERT_TRUE(sink->waitDispatched(before + PER_WINDOW));
        sink->resolveHeld();
    }
    EXPECT_LT(std::chrono::steady_clock::now() - started, 5s) << "the scheduler spun on loop 0";
    EXPECT_GT(m_path->scheduler()->stats().fastForwards, 0u);
    const auto share = shareOf(sink->log(), first, first + WINDOWS * PER_WINDOW);
    ASSERT_EQ(share.bytes.size(), 2u);
    const double ratio = static_cast<double>(share.bytes.at("heavy")) / share.bytes.at("light");
    EXPECT_NEAR(ratio, 3.0, 0.3) << "light " << share.bytes.at("light") << " heavy " << share.bytes.at("heavy");
    closeNow(*c);
}

namespace
{
    /// Resolves Ok; a dispatch of bucket "slow" takes 100 ms on loop 0 (a long pass).
    class SlowSink final : public wr::BatchSink
    {
    public:
        explicit SlowSink(std::weak_ptr<wr::WritePath> path)
            : m_path(std::move(path))
        {
        }
        std::size_t capacity() override
        {
            return 1000;
        }
        void dispatch(wr::Batch batch) override
        {
            if (batch.bucket->spec().name == "slow")
            {
                std::this_thread::sleep_for(100ms);
            }
            if (batch.bucket->spec().name == "aged")
            {
                aged.store(true);
            }
            if (auto path = m_path.lock())
            {
                for (auto& op : batch.ops)
                {
                    path->resolve(op, TestSink::ok());
                }
            }
        }
        void stop() override {}
        std::atomic<bool> aged {false};

    private:
        std::weak_ptr<wr::WritePath> m_path;
    };
} // namespace

// I63 (defect found in step 5, fixed by the root in step 6): an op whose maxAge expires while a scheduling pass runs
// (here a dispatch of another bucket lasting 100 ms on loop 0) was neither served nor given a timer; it is served.
TEST_F(WriteTest, MaxAgeExpiringDuringAPassIsServed)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = std::make_shared<SlowSink>(m_path);
    m_path->setSink(sink);
    auto c = client("c",
                    {bucketSpec("aged", 1u << 20, ic::Overflow::Kind::Reject, 0, 1000, ic::Duration {50}),
                     bucketSpec("slow", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    ASSERT_TRUE(c->writer("aged")->submit(indexOp("a")).accepted); // Due at t + 50 ms.
    ASSERT_TRUE(c->writer("slow")->submit(indexOp("s")).accepted); // A pass now; its dispatch lasts until t + 100 ms.
    EXPECT_TRUE(component::eventually([&] { return sink->aged.load(); }, 2s))
        << "the aged op never left (maxAge 50 ms)";
    c->requestClose();
}
