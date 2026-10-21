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

// CA-3, T3 (plan-E3c-2 §Tests, step 6b): a bucket whose every item is rejected does not starve another bucket on the
// same node. Item rejections are the rejecting bucket's own business (its retry lane and its backoff); the node keeps
// serving everybody. The production sender runs over the real transport against one fake node (bulkFixture.hpp) that
// answers B's `_bulk` after 20 ms, so the node's throughput is set by its window (NODE_WINDOW bulks in flight), not by
// the machine; A's rejections are answered at once (a write block costs the node nothing), so A's own slot time is
// not what the case measures. Every case ends with the charge and the retained ops at 0 (TearDown).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

#include "bulkFixture.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;

namespace
{
    constexpr auto LATENCY = std::chrono::milliseconds(20);
    constexpr auto PHASE = std::chrono::seconds(10);
    constexpr auto WARMUP = std::chrono::seconds(1);
    constexpr std::int64_t A_BACKOFF_MS = 200;
    constexpr std::uint64_t A_OPS = 5;
    constexpr const char* A_INDEX = "a-blocked";
    constexpr const char* B_INDEX = "b-states";

    std::string id(std::uint64_t key)
    {
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "k%010llu", static_cast<unsigned long long>(key));
        return buffer;
    }
} // namespace

// CA-3, T3: one node. Phase 1: B alone for 10 s (its baseline, after a 1 s warm-up). Phase 2: B goes on and A joins
// with A_OPS ops whose every item is `cluster_block_exception` (item Retry), unlimited attempts and a 200 ms backoff,
// for another 10 s (DRR quantum 4 KiB): B completes >= 0.9 x its baseline and A's retries keep growing (counted at the
// middle and at the end of the phase). A is then cancelled by tag. Small documents (16 B bodies), batches of 20 for B.
// Total ~22 s (~3x under TSAN). Mutant: an item Retry puts the node's notBefore (the bucket's backoff) instead of the
// bucket's backoff.
TEST_F(BulkTest, ItemRejectionsDoNotStarveOtherBucket)
{
    auto blocked = std::make_shared<bulk_component::BulkResponder>(BulkScript::all(
        BulkItem::failed(403, "cluster_block_exception", "index [a-blocked] blocked by: [FORBIDDEN/8]")));
    auto served = BulkScript::items();
    served.latency = LATENCY;
    const auto a = startNode(served,
                             "green",
                             {},
                             [blocked](const httplib::Request& request, indexer_client::testing::Rule& reply)
                             {
                                 if (request.body.find(A_INDEX) != std::string::npos)
                                 {
                                     auto answer = blocked->answer(request.path, request.body);
                                     reply.status = answer.status;
                                     reply.body = std::move(answer.body);
                                     reply.latency = std::chrono::milliseconds(0); // A block is answered at once.
                                 }
                             });
    // A small DRR quantum (4 KiB, two of B's batches): with the default 1 MiB a turn of B lasts ~550 batches (~3 s at
    // this node's pace), so A would get a turn, hence a retry, only every ~3 s.
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::milliseconds(3600000), {{"drr_quantum_bytes", "4096"}}));
    auto bSpec = bucketSpec("b", 1u << 20, ic::Overflow::Kind::Block, 0, 20, ic::Duration {5});
    auto aSpec = bucketSpec("a", 1u << 20, ic::Overflow::Kind::Reject, 0, A_OPS, ic::Duration {5});
    aSpec.retry.maxAttempts.reset();
    aSpec.retry.maxDuration.reset();
    aSpec.retry.base = ic::Duration {A_BACKOFF_MS};
    aSpec.retry.cap = ic::Duration {A_BACKOFF_MS};
    aSpec.retry.jitter = 0.0;
    auto c = client("c", {bSpec, aSpec});
    auto bWriter = c->writer("b");
    auto aWriter = c->writer("a");

    auto completed = std::make_shared<std::atomic<std::uint64_t>>(0);
    std::atomic<bool> producing {true};
    std::thread producer(
        [&]
        {
            std::uint64_t n = 0;
            while (producing.load())
            {
                bWriter->submit(indexOp(id(n++), 16, B_INDEX),
                                [completed](const ic::OpResult& result)
                                {
                                    if (result.status == ic::Status::Ok)
                                    {
                                        completed->fetch_add(1);
                                    }
                                });
            }
        });
    struct StopProducer
    {
        std::atomic<bool>& flag;
        std::thread& thread;
        ~StopProducer()
        {
            flag.store(false);
            if (thread.joinable())
            {
                thread.join();
            }
        }
    } stopProducer {producing, producer};

    // Phase 1: B alone.
    std::this_thread::sleep_for(WARMUP);
    const auto c0 = completed->load();
    std::this_thread::sleep_for(PHASE);
    const auto baseline = completed->load() - c0;

    // Phase 2: A joins with every item rejected.
    auto aResults = Results::create();
    for (std::uint64_t k = 0; k < A_OPS; ++k)
    {
        auto op = indexOp(id(k), 16, A_INDEX);
        op.tag = "agent-a";
        ASSERT_TRUE(aWriter->submit(std::move(op), aResults->callback(k)).accepted);
    }
    ASSERT_TRUE(eventually([&] { return blocked->answered() >= 1; }, 3s)) << "A never reached the node";
    const auto c1 = completed->load();
    std::this_thread::sleep_for(PHASE / 2);
    const auto aMiddle = blocked->answered();
    std::this_thread::sleep_for(PHASE / 2);
    const auto withA = completed->load() - c1;
    const auto aEnd = blocked->answered();

    producing.store(false);
    producer.join();
    std::printf("[ CA-3     ] B completed %llu alone, %llu with A rejected (%.3f); A's bulks %zu at mid-phase, %zu at "
                "the end\n",
                static_cast<unsigned long long>(baseline),
                static_cast<unsigned long long>(withA),
                baseline == 0 ? 0.0 : static_cast<double>(withA) / static_cast<double>(baseline),
                aMiddle,
                aEnd);
    EXPECT_GE(baseline, 1000u) << "the baseline is too small to compare";
    EXPECT_GE(static_cast<double>(withA), 0.9 * static_cast<double>(baseline))
        << "B starved by A's item rejections: " << withA << " vs " << baseline;
    EXPECT_GE(aMiddle, 10u) << "A did not retry";
    EXPECT_GT(aEnd, aMiddle) << "A's retries stopped growing";
    EXPECT_EQ(aResults->total(), 0u) << "A's ops resolved: unlimited retries expected";

    // A goes away by tag: its lane ops at once, a bulk in flight with its answer.
    const auto cancelled = aWriter->cancel("agent-a");
    ASSERT_TRUE(cancelled.wait(now() + 5s).ok());
    ASSERT_TRUE(aResults->waitTotal(A_OPS, 3s));
    EXPECT_EQ(aResults->countWith(ic::Status::Dropped, ic::Cause::Cancelled), A_OPS);
    expectInvariants(stats("a"));
    expectInvariants(stats("b"));
}
