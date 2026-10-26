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

// RESULT_RESERVE (plan-E3a §Tests: ResultReserveMeasured, CA-12, I62): the heap an accepted op keeps besides its
// encoded lines, measured with an allocation counter, must fit in the constant. The counter replaces the global
// operator new/delete of this executable; under ASAN/TSAN (which own the allocator) it is compiled out and the case
// is skipped.

#include <malloc.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

#include "writeFixture.hpp"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define WRITE_RESERVE_COUNTER 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define WRITE_RESERVE_COUNTER 0
#else
#define WRITE_RESERVE_COUNTER 1
#endif
#else
#define WRITE_RESERVE_COUNTER 1
#endif

namespace
{
    /// Live heap bytes (usable size of every block) obtained through operator new, process-wide.
    std::atomic<std::int64_t> g_liveBytes {0};

    /// E6d (CA-E6d-1, CA-E6d-4): calls to operator new and the bytes they asked for (not the live ones), counted only
    /// on a thread whose AllocationWindow is open. Constant-initialized thread_locals: reading them allocates nothing.
    thread_local bool t_counting = false;
    thread_local std::uint64_t t_calls = 0;
    thread_local std::uint64_t t_requested = 0;
} // namespace

#if WRITE_RESERVE_COUNTER
void* operator new(std::size_t size)
{
    void* block = std::malloc(size == 0 ? 1 : size);
    if (block == nullptr)
    {
        throw std::bad_alloc();
    }
    g_liveBytes.fetch_add(static_cast<std::int64_t>(malloc_usable_size(block)), std::memory_order_relaxed);
    if (t_counting)
    {
        ++t_calls;
        t_requested += size;
    }
    return block;
}

void operator delete(void* block) noexcept
{
    if (block != nullptr)
    {
        g_liveBytes.fetch_sub(static_cast<std::int64_t>(malloc_usable_size(block)), std::memory_order_relaxed);
        std::free(block);
    }
}

void operator delete(void* block, std::size_t /*size*/) noexcept
{
    ::operator delete(block);
}

void* operator new[](std::size_t size)
{
    return ::operator new(size);
}

void operator delete[](void* block) noexcept
{
    ::operator delete(block);
}

void operator delete[](void* block, std::size_t /*size*/) noexcept
{
    ::operator delete(block);
}
#endif

using namespace write_component;

namespace
{
    std::int64_t liveBytes()
    {
        return g_liveBytes.load();
    }

    /// An op whose strings all fit in the small-string buffer: the op itself allocates nothing, so the counter sees
    /// only what the library keeps for it (and its encoded lines, subtracted below).
    ic::Op smallOp(std::size_t n)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::Index;
        op.index = "w-states";
        op.id = "i" + std::to_string(100000 + n);
        op.body = R"({"a":1})";
        return op;
    }

    /// The largest result the resolution path keeps: both strings at their caps.
    ic::OpResult cappedResult()
    {
        ic::OpResult result;
        result.status = ic::Status::Failed;
        result.cause = ic::Cause::ItemPermanent;
        result.httpStatus = 400;
        result.itemErrorType.assign(ic::OpResult::MAX_ITEM_ERROR_TYPE, 't');
        result.reason.assign(ic::OpResult::MAX_REASON, 'r');
        return result;
    }

    /// RAII: counts the operator new calls and requested bytes of the CURRENT thread (the producer) while alive.
    class AllocationWindow final
    {
    public:
        AllocationWindow()
        {
            t_calls = 0;
            t_requested = 0;
            t_counting = true;
        }

        ~AllocationWindow()
        {
            t_counting = false;
        }

        AllocationWindow(const AllocationWindow&) = delete;
        AllocationWindow& operator=(const AllocationWindow&) = delete;

        std::uint64_t calls() const
        {
            return t_calls;
        }

        std::uint64_t requested() const
        {
            return t_requested;
        }
    };

    constexpr std::size_t WINDOW_OPS = 1024;
    constexpr std::size_t WINDOW_BODY = 1500;
    constexpr std::uint64_t DEQUE_CALLS = 64; ///< The bucket's queue blocks and the first op's scheduler wake-up.

    /// An op of WINDOW_BODY bytes whose other strings fit the small-string buffer, built before the window opens.
    ic::Op windowOp(std::size_t n)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::Index;
        op.index = "w-states";
        op.id = "i" + std::to_string(100000 + n);
        op.body = body(WINDOW_BODY);
        return op;
    }

    /// A bucket that cannot become eligible during the window: maxBytes 8 MiB (the ops add up to ~1.6 MB), maxDocs
    /// above the op count, maxAge 1 h; with the sink at capacity 0 nothing leaves it either (as ResultReserveMeasured).
    ic::BucketSpec windowBucket()
    {
        return bucketSpec("b", 16u << 20, ic::Overflow::Kind::Reject, 8u << 20, WINDOW_OPS + 1, ic::Duration {3600000});
    }

    std::uint64_t linesOf(const std::vector<wr::Batch>& batches)
    {
        std::uint64_t total = 0;
        for (const auto& batch : batches)
        {
            for (const auto& op : batch.ops)
            {
                total += op->wire();
            }
        }
        return total;
    }
} // namespace

// CA-12: per accepted op, the heap kept besides its lines (OpState, TicketState, control blocks, the bucket's queue and
// delivered set, the callback, the completion queued on the pool with an OpResult at its caps, the result stored in
// the ticket, the reserve handle) is <= RESULT_RESERVE. Phases: (1) retained with a callback; (2) resolved, its
// completion queued behind a busy pool, the batch still held by the sink; (3) callback run, the Ticket still alive
// (reported: with a callback the reserve is already released); (4) without a callback, resolved, the Ticket alive;
// (5, E3b-2) with a callback, requeued into the retry lane with its LastError at its caps (the batch gone); (6, G-diff
// E3b-2 obj. 1) the composed worst case: requeued with its LastError at its caps, sliced again, then resolved
// Failed(ItemPermanent) with a capped OpResult while its completion waits behind a busy pool, the batch still held
// (the resolution frees the op's last-error strings); (7, E3c-1) an op of a group, Building, then resolved with a
// capped OpResult in its slot while the batches are still held; (8, E3c-2) an op of an ordered bucket with a tag at its
// cap and its key: retained, then pinned in the lane with its LastError at its caps, then resolved from the lane.
TEST_F(WriteTest, ResultReserveMeasured)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "the allocation counter is compiled out under ASAN/TSAN (they own operator new)";
#else
    constexpr std::size_t N = 1024;
    constexpr std::size_t PER_BATCH = 64;
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    auto sink = installSink();
    // E3c-2: an ordered bucket whose single batch takes all N ops (one bulk in flight per ordered bucket).
    auto ordered = bucketSpec("o", 8u << 20, ic::Overflow::Kind::Reject, 1u << 20, N);
    ordered.ordered = true;
    auto c = client("c", {bucketSpec("b", 64u << 20, ic::Overflow::Kind::Reject, 1u << 20, PER_BATCH), ordered});
    auto writer = c->writer("b");
    const auto result = cappedResult();
    auto calls = std::make_shared<std::atomic<std::size_t> >(0);
    std::atomic<std::size_t>* counter = calls.get(); // An 8-byte capture: the callback fits std::function's buffer.

    std::vector<ic::Ticket> tickets;
    tickets.reserve(N);
    std::vector<wr::Batch> batches;
    batches.reserve(N);
    const auto perOp = [&](std::int64_t base)
    {
        return static_cast<double>(liveBytes() - base - static_cast<std::int64_t>(linesOf(batches))) / N;
    };

    // (1) Retained with a callback.
    const auto base = liveBytes();
    for (std::size_t i = 0; i < N; ++i)
    {
        auto submit = writer->submit(smallOp(i), [counter](const ic::OpResult&) { counter->fetch_add(1); });
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(std::move(submit.ticket));
    }
    ASSERT_TRUE(sink->waitDispatched(N / PER_BATCH));
    for (auto& batch : sink->take())
    {
        batches.push_back(std::move(batch));
    }
    const double retained = perOp(base);

    // (2) Resolved; the completions wait behind a busy pool (M = 1); the batches are still held.
    auto blocker = component::Blocker::create();
    component::ReleaseOnExit releaseOnExit(blocker);
    ASSERT_TRUE(ic::detail::testing::postToPool(blocker->task()));
    ASSERT_TRUE(blocker->waitStarted(1, 5s));
    for (const auto& batch : batches)
    {
        for (const auto& op : batch.ops)
        {
            ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
        }
    }
    const double queued = perOp(base);
    blocker->release();
    ASSERT_TRUE(component::eventually([&] { return calls->load() == N; }, 5s));
    ASSERT_TRUE(component::eventually([&] { return stats("b").charge == 0; }, 5s));

    // (3) Callbacks run; the Tickets hold the stored result.
    const double afterCallback = perOp(base);
    tickets.clear();
    batches.clear();

    // (4) Without a callback: resolved, the Ticket alive (it owns the reserve), the batch held.
    const auto base4 = liveBytes();
    for (std::size_t i = 0; i < N; ++i)
    {
        auto submit = writer->submit(smallOp(N + i));
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(std::move(submit.ticket));
    }
    ASSERT_TRUE(sink->waitDispatched(2 * N / PER_BATCH));
    for (auto& batch : sink->take())
    {
        batches.push_back(std::move(batch));
    }
    for (const auto& batch : batches)
    {
        for (const auto& op : batch.ops)
        {
            ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
        }
    }
    const double noCallback = perOp(base4);
    EXPECT_EQ(stats("b").charge, N * wr::RESULT_RESERVE) << "the tickets hold the reserves";
    tickets.clear();
    batches.clear();

    // (5) With a callback, back in the retry lane (an hour away) with the largest LastError the sender keeps; the
    // batches are gone, so the lane is the ops' only holder besides the test's handles (reserved beforehand).
    std::vector<std::shared_ptr<wr::OpState> > lane;
    lane.reserve(N);
    const auto base5 = liveBytes();
    for (std::size_t i = 0; i < N; ++i)
    {
        auto submit = writer->submit(smallOp(2 * N + i), [counter](const ic::OpResult&) { counter->fetch_add(1); });
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(std::move(submit.ticket));
    }
    ASSERT_TRUE(sink->waitDispatched(3 * N / PER_BATCH));
    for (auto& batch : sink->take())
    {
        batches.push_back(std::move(batch));
    }
    const std::uint64_t laneLines = linesOf(batches);
    wr::RequeueSpec later;
    later.countAttempt = true;
    later.delay = wr::RequeueSpec::Delay::At;
    later.at = now() + std::chrono::hours(1);
    for (auto& batch : batches)
    {
        std::vector<wr::RequeueOp> ops;
        ops.reserve(batch.ops.size());
        for (const auto& op : batch.ops)
        {
            lane.push_back(op);
            ops.push_back(wr::RequeueOp {op,
                                         wr::LastError {ic::Cause::ItemRetryable,
                                                        429,
                                                        std::string(ic::OpResult::MAX_ITEM_ERROR_TYPE, 't'),
                                                        std::string(ic::OpResult::MAX_REASON, 'r')}});
        }
        const auto requeued = batch.bucket->requeue(std::move(ops), later, now());
        ASSERT_TRUE(requeued.exhausted.empty());
        ASSERT_TRUE(requeued.closed.empty());
    }
    batches.clear();
    const double inLane =
        static_cast<double>(liveBytes() - base5 - static_cast<std::int64_t>(laneLines)) / static_cast<double>(N);
    EXPECT_EQ(stats("b").retained, N) << "in the lane";
    for (const auto& op : lane)
    {
        ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
    }
    lane.clear();
    ASSERT_TRUE(component::eventually([&] { return calls->load() == 2 * N; }, 5s));
    ASSERT_TRUE(component::eventually([&] { return stats("b").charge == 0; }, 5s));
    tickets.clear();

    // (6) Requeued with the largest LastError, re-sliced by the scheduler, resolved behind a busy pool.
    const auto base6 = liveBytes();
    for (std::size_t i = 0; i < N; ++i)
    {
        auto submit = writer->submit(smallOp(3 * N + i), [counter](const ic::OpResult&) { counter->fetch_add(1); });
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(std::move(submit.ticket));
    }
    ASSERT_TRUE(sink->waitDispatched(4 * N / PER_BATCH));
    for (auto& batch : sink->take())
    {
        batches.push_back(std::move(batch));
    }
    wr::RequeueSpec again;
    again.countAttempt = true;
    again.delay = wr::RequeueSpec::Delay::Now;
    std::shared_ptr<wr::Bucket> bucket6;
    for (auto& batch : batches)
    {
        std::vector<wr::RequeueOp> ops;
        ops.reserve(batch.ops.size());
        for (const auto& op : batch.ops)
        {
            ops.push_back(wr::RequeueOp {op,
                                         wr::LastError {ic::Cause::ItemRetryable,
                                                        429,
                                                        std::string(ic::OpResult::MAX_ITEM_ERROR_TYPE, 't'),
                                                        std::string(ic::OpResult::MAX_REASON, 'r')}});
        }
        bucket6 = batch.bucket;
        const auto requeued = batch.bucket->requeue(std::move(ops), again, now());
        ASSERT_TRUE(requeued.exhausted.empty());
        ASSERT_TRUE(requeued.closed.empty());
    }
    batches.clear();
    ASSERT_NE(bucket6, nullptr);
    m_path->scheduler()->notify(bucket6);
    std::size_t resliced = 0;
    ASSERT_TRUE(component::eventually(
        [&]
        {
            for (auto& batch : sink->take())
            {
                resliced += batch.ops.size();
                batches.push_back(std::move(batch));
            }
            return resliced == N;
        },
        5s))
        << resliced << " of " << N << " re-sliced";
    for (const auto& batch : batches)
    {
        for (const auto& op : batch.ops)
        {
            ASSERT_EQ(op->lastReason.size(), ic::OpResult::MAX_REASON) << "the op carries its capped last error";
        }
    }
    auto blocker6 = component::Blocker::create();
    component::ReleaseOnExit releaseOnExit6(blocker6);
    ASSERT_TRUE(ic::detail::testing::postToPool(blocker6->task()));
    ASSERT_TRUE(blocker6->waitStarted(1, 5s));
    for (const auto& batch : batches)
    {
        for (const auto& op : batch.ops)
        {
            ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
        }
    }
    const double composed = perOp(base6);
    blocker6->release();
    ASSERT_TRUE(component::eventually([&] { return calls->load() == 3 * N; }, 5s));
    ASSERT_TRUE(component::eventually([&] { return stats("b").charge == 0; }, 5s));
    tickets.clear();
    batches.clear();
    bucket6.reset();

    // (7, E3c-1) A group of N ops: (a) Building (the ops in the GroupState, charged, outside the queue); (b) committed,
    // sliced, every op resolved Failed(ItemPermanent) with a capped OpResult (its slot filled), the batches still held
    // (the group's own state, its result vector and the ticket's completion amortized over its ops).
    const auto base7 = liveBytes();
    std::uint64_t groupLines = 0;
    double groupBuilding = 0.0;
    double groupResolved = 0.0;
    {
        auto group = writer->group();
        for (std::size_t i = 0; i < N; ++i)
        {
            groupLines += wireSize(smallOp(4 * N + i));
        }
        const auto baseAdds = liveBytes();
        for (std::size_t i = 0; i < N; ++i)
        {
            ASSERT_EQ(group.add(smallOp(4 * N + i)), ic::Cause::None);
        }
        groupBuilding = static_cast<double>(liveBytes() - baseAdds - static_cast<std::int64_t>(groupLines)) /
                        static_cast<double>(N);
        auto groupTicket = group.commit();
        std::size_t sliced = 0;
        ASSERT_TRUE(component::eventually(
            [&]
            {
                for (auto& batch : sink->take())
                {
                    sliced += batch.ops.size();
                    batches.push_back(std::move(batch));
                }
                return sliced == N;
            },
            5s))
            << sliced << " of " << N << " sliced";
        for (const auto& batch : batches)
        {
            for (const auto& op : batch.ops)
            {
                ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
            }
        }
        ASSERT_TRUE(groupTicket.ready());
        groupResolved = perOp(base7);
        batches.clear();
        const auto outcome = groupTicket.wait(now() + 5s);
        ASSERT_TRUE(outcome.ok());
        ASSERT_EQ(outcome.value.size(), N);
    }
    ASSERT_TRUE(component::eventually([&] { return stats("b").charge == 0; }, 5s));

    // (8, E3c-2) An ordered bucket: each op with a tag at its cap (OpState::tag) and its key (keyHash), (a) retained
    // with a callback, the batch held; (b) requeued into the lane with its LastError at its caps and pinned (the
    // ambiguous anchor), the batch gone; (c) resolved from the lane with a capped OpResult behind a busy pool.
    const std::size_t dispatchedBefore = sink->dispatched();
    auto orderedWriter = c->writer("o");
    const auto base8 = liveBytes();
    for (std::size_t i = 0; i < N; ++i)
    {
        auto op = smallOp(5 * N + i);
        op.tag.assign(wr::MAX_TAG_SIZE, 'g');
        auto submit = orderedWriter->submit(std::move(op), [counter](const ic::OpResult&) { counter->fetch_add(1); });
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(std::move(submit.ticket));
    }
    ASSERT_TRUE(sink->waitDispatched(dispatchedBefore + 1));
    for (auto& batch : sink->take())
    {
        batches.push_back(std::move(batch));
    }
    ASSERT_EQ(batches.size(), 1u);
    ASSERT_EQ(batches[0].ops.size(), N);
    ASSERT_TRUE(batches[0].ops[0]->hasKey) << "an ordered bucket's op carries its key";
    const double orderedRetained = perOp(base8);
    const std::uint64_t orderedLines = linesOf(batches);
    wr::RequeueSpec pinned;
    pinned.countAttempt = false;
    pinned.delay = wr::RequeueSpec::Delay::At;
    pinned.at = now() + std::chrono::hours(1);
    pinned.pin = wr::RequeueSpec::Pin::Set;
    pinned.pinNode = 0;
    pinned.pinUntil = now() + std::chrono::hours(1);
    {
        std::vector<wr::RequeueOp> ops;
        ops.reserve(N);
        for (const auto& op : batches[0].ops)
        {
            lane.push_back(op);
            ops.push_back(wr::RequeueOp {op,
                                         wr::LastError {ic::Cause::TransportTimeout,
                                                        0,
                                                        std::string(ic::OpResult::MAX_ITEM_ERROR_TYPE, 't'),
                                                        std::string(ic::OpResult::MAX_REASON, 'r')}});
        }
        const auto requeued = batches[0].bucket->requeue(std::move(ops), pinned, now());
        ASSERT_TRUE(requeued.exhausted.empty());
        ASSERT_TRUE(requeued.closed.empty());
        ASSERT_TRUE(requeued.cancelled.empty());
    }
    batches.clear();
    const double orderedPinned =
        static_cast<double>(liveBytes() - base8 - static_cast<std::int64_t>(orderedLines)) / static_cast<double>(N);
    EXPECT_EQ(stats("o").orderedAmbiguous, N) << "pinned in the lane";
    auto blocker8 = component::Blocker::create();
    component::ReleaseOnExit releaseOnExit8(blocker8);
    ASSERT_TRUE(ic::detail::testing::postToPool(blocker8->task()));
    ASSERT_TRUE(blocker8->waitStarted(1, 5s));
    for (const auto& op : lane)
    {
        ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, result));
    }
    const double orderedResolved =
        static_cast<double>(liveBytes() - base8 - static_cast<std::int64_t>(orderedLines)) / static_cast<double>(N);
    blocker8->release();
    lane.clear();
    ASSERT_TRUE(component::eventually([&] { return calls->load() == 4 * N; }, 5s));
    ASSERT_TRUE(component::eventually([&] { return stats("o").charge == 0; }, 5s));
    tickets.clear();

    const double measured = std::max({retained,
                                      queued,
                                      noCallback,
                                      inLane,
                                      composed,
                                      groupBuilding,
                                      groupResolved,
                                      orderedRetained,
                                      orderedPinned,
                                      orderedResolved});
    std::printf(
        "[ RESERVE  ] bytes per op besides its lines: retained %.1f, queued completion %.1f, after the callback "
        "(ticket alive) %.1f, no callback %.1f, requeued in the lane %.1f, requeued then resolved (queued completion) "
        "%.1f, group building %.1f, group resolved (batches held) %.1f, ordered with a 256 B tag and its key: retained "
        "%.1f, pinned in the lane %.1f, resolved from the lane (queued completion) %.1f; max %.1f (x 1.25 = %.1f); "
        "RESULT_RESERVE %llu\n",
        retained,
        queued,
        afterCallback,
        noCallback,
        inLane,
        composed,
        groupBuilding,
        groupResolved,
        orderedRetained,
        orderedPinned,
        orderedResolved,
        measured,
        measured * 1.25,
        static_cast<unsigned long long>(wr::RESULT_RESERVE));
    EXPECT_GT(measured, 0.0) << "the counter saw nothing: is the replacement operator new linked?";
    EXPECT_LE(measured, static_cast<double>(wr::RESULT_RESERVE)) << "RESULT_RESERVE is below what an op keeps";
#endif
}

// CA-E6d-1 (I121, I122): 1 024 post() of a 1 500 B body into a bucket that cannot form a batch: the producer thread
// asks operator new for < 1 024 B per op (the body is moved, never copied: m1 makes it >= 1 500) in <= 2 calls per op
// (the OpState and the head) + 64 in total (the bucket's queue). The ops are built before the window opens.
TEST_F(WriteTest, PostBodyNotCopied)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "the allocation counter is compiled out under ASAN/TSAN (they own operator new)";
#else
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {windowBucket()});
    auto writer = c->writer("b");
    std::vector<ic::Op> ops;
    ops.reserve(WINDOW_OPS);
    for (std::size_t i = 0; i < WINDOW_OPS; ++i)
    {
        ops.push_back(windowOp(i));
    }
    std::vector<char> accepted(WINDOW_OPS, 0);
    std::uint64_t calls = 0;
    std::uint64_t requested = 0;
    {
        AllocationWindow window;
        for (std::size_t i = 0; i < WINDOW_OPS; ++i)
        {
            accepted[i] = writer->post(std::move(ops[i])).accepted ? 1 : 0;
        }
        calls = window.calls();
        requested = window.requested();
    }
    EXPECT_EQ(std::count(accepted.begin(), accepted.end(), 1), static_cast<std::ptrdiff_t>(WINDOW_OPS));
    EXPECT_EQ(stats("b").retained, WINDOW_OPS) << "the bucket formed a batch during the window";
    const double perOp = static_cast<double>(requested) / WINDOW_OPS;
    std::printf("[  E6d     ] PostBodyNotCopied: %llu calls (%.2f per op), %llu bytes requested (%.1f per op)\n",
                static_cast<unsigned long long>(calls),
                static_cast<double>(calls) / WINDOW_OPS,
                static_cast<unsigned long long>(requested),
                perOp);
    EXPECT_GT(calls, 0u) << "the counter saw nothing: is the replacement operator new linked?";
    EXPECT_LT(perOp, 1024.0) << "the producer copied the body";
    EXPECT_LE(calls, 2 * WINDOW_OPS + DEQUE_CALLS);
    closeNow(*c);
    expectInvariants(stats("b"));
#endif
}

// I125 (a): 1 024 post() of an IndexDataStream op of 1 500 B into one index, with the window and bucket of
// PostBodyNotCopied: the action line is the cached shared head, so the producer asks operator new for <= 1 call per op
// (the OpState) + 64 in total (the bucket's queue and the first op's head). The ops are built before the window opens.
TEST_F(WriteTest, PostSharedHeadSingleAllocation)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "the allocation counter is compiled out under ASAN/TSAN (they own operator new)";
#else
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {windowBucket()});
    auto writer = c->writer("b");
    std::vector<ic::Op> ops;
    ops.reserve(WINDOW_OPS);
    for (std::size_t i = 0; i < WINDOW_OPS; ++i)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexDataStream;
        op.index = "w-events";
        op.body = body(WINDOW_BODY);
        ops.push_back(std::move(op));
    }
    std::vector<char> accepted(WINDOW_OPS, 0);
    std::uint64_t calls = 0;
    std::uint64_t requested = 0;
    {
        AllocationWindow window;
        for (std::size_t i = 0; i < WINDOW_OPS; ++i)
        {
            accepted[i] = writer->post(std::move(ops[i])).accepted ? 1 : 0;
        }
        calls = window.calls();
        requested = window.requested();
    }
    EXPECT_EQ(std::count(accepted.begin(), accepted.end(), 1), static_cast<std::ptrdiff_t>(WINDOW_OPS));
    EXPECT_EQ(stats("b").retained, WINDOW_OPS) << "the bucket formed a batch during the window";
    std::printf("[  E6d     ] PostSharedHeadSingleAllocation: %llu calls (%.2f per op), %llu bytes requested (%.1f per "
                "op)\n",
                static_cast<unsigned long long>(calls),
                static_cast<double>(calls) / WINDOW_OPS,
                static_cast<unsigned long long>(requested),
                static_cast<double>(requested) / WINDOW_OPS);
    EXPECT_GT(calls, 0u) << "the counter saw nothing: is the replacement operator new linked?";
    EXPECT_LE(calls, WINDOW_OPS + DEQUE_CALLS) << "the action line is allocated per op";
    closeNow(*c);
    expectInvariants(stats("b"));
#endif
}

// CA-E6d-4: submit() without a callback with the same window and ops: <= 3 operator new calls per op + 64 (E6c: 4 —
// the lines, TicketState, ReserveHandle, OpState; E6d fuses the reserve handle into the TicketState and moves the
// body).
TEST_F(WriteTest, SubmitAllocationsFused)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "the allocation counter is compiled out under ASAN/TSAN (they own operator new)";
#else
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {windowBucket()});
    auto writer = c->writer("b");
    std::vector<ic::Op> ops;
    ops.reserve(WINDOW_OPS);
    for (std::size_t i = 0; i < WINDOW_OPS; ++i)
    {
        ops.push_back(windowOp(i));
    }
    std::vector<ic::Submit> submits; // Reserved: keeping the tickets alive allocates nothing in the window.
    submits.reserve(WINDOW_OPS);
    std::uint64_t calls = 0;
    std::uint64_t requested = 0;
    {
        AllocationWindow window;
        for (std::size_t i = 0; i < WINDOW_OPS; ++i)
        {
            submits.push_back(writer->submit(std::move(ops[i])));
        }
        calls = window.calls();
        requested = window.requested();
    }
    for (const auto& submit : submits)
    {
        ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause);
    }
    EXPECT_EQ(stats("b").retained, WINDOW_OPS) << "the bucket formed a batch during the window";
    std::printf("[  E6d     ] SubmitAllocationsFused: %llu calls (%.2f per op), %llu bytes requested (%.1f per op)\n",
                static_cast<unsigned long long>(calls),
                static_cast<double>(calls) / WINDOW_OPS,
                static_cast<unsigned long long>(requested),
                static_cast<double>(requested) / WINDOW_OPS);
    EXPECT_GT(calls, 0u) << "the counter saw nothing: is the replacement operator new linked?";
    EXPECT_LE(calls, 3 * WINDOW_OPS + DEQUE_CALLS);
    closeNow(*c);
    submits.clear();
    expectInvariants(stats("b"));
#endif
}

// CA-E6d-4 (I124b): the charge of a posted op is its wire size + the heap slack of its body + RESULT_RESERVE: a 1 500 B
// body with reserve(3 000) charges wire + 1 500 + R; a Delete and an SSO body charge wire + R (so no exact charge of
// the other suites changes). The sink receives the wire bytes only, and the charge returns to 0 at resolution. Mutant
// m6: charge = wire.
TEST_F(WriteTest, PostChargesCapacity)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "with the allocation counter: compiled out under ASAN/TSAN";
#else
    constexpr std::uint64_t R = wr::RESULT_RESERVE;
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 3, ic::Duration {3600000})});
    auto writer = c->writer("b");

    ic::Op heap;
    heap.kind = ic::Op::Kind::Index;
    heap.index = "w-states";
    heap.id = "heap";
    {
        const auto content = body(WINDOW_BODY);
        std::string reserved;
        reserved.reserve(2 * WINDOW_BODY);
        reserved.assign(content.data(), content.size());
        heap.body = std::move(reserved);
    }
    ASSERT_EQ(heap.body.size(), WINDOW_BODY);
    ASSERT_EQ(heap.body.capacity(), 2 * WINDOW_BODY) << "precondition: 1 500 B of heap slack";
    const auto heapWire = wireSize(heap);

    ic::Op del;
    del.kind = ic::Op::Kind::Delete;
    del.index = "w-states";
    del.id = "gone";
    const auto delWire = wireSize(del);
    EXPECT_EQ(chargeOf(del), delWire);

    ic::Op sso;
    sso.kind = ic::Op::Kind::Index;
    sso.index = "w-states";
    sso.id = "sso";
    sso.body = R"({"a":1})";
    ASSERT_LE(sso.body.capacity(), std::string().capacity()) << "precondition: the body fits the SSO buffer";
    const auto ssoWire = wireSize(sso);
    EXPECT_EQ(chargeOf(sso), ssoWire);

    ASSERT_TRUE(writer->post(std::move(heap)).accepted);
    EXPECT_EQ(stats("b").charge, heapWire + WINDOW_BODY + R) << "wire + the body's heap slack + RESULT_RESERVE";
    EXPECT_EQ(globalCharge(), heapWire + WINDOW_BODY + R);
    auto before = stats("b").charge;
    ASSERT_TRUE(writer->post(std::move(del)).accepted);
    EXPECT_EQ(stats("b").charge - before, delWire + R) << "Delete: wire + RESULT_RESERVE";
    before = stats("b").charge;
    ASSERT_TRUE(writer->post(std::move(sso)).accepted);
    EXPECT_EQ(stats("b").charge - before, ssoWire + R) << "SSO body: wire + RESULT_RESERVE";

    sink->grant(1);
    ASSERT_TRUE(sink->waitDispatched(1));
    auto log = sink->log();
    ASSERT_EQ(log.size(), 1u);
    EXPECT_EQ(log[0].ops, 3u);
    EXPECT_EQ(log[0].bytes, heapWire + delWire + ssoWire) << "the bulk carries the wire bytes, not the charge";
    EXPECT_EQ(sink->resolveHeld(), 3u);
    EXPECT_TRUE(component::eventually([&] { return stats("b").charge == 0 && globalCharge() == 0; }, 5s))
        << describe(stats("b"));
    expectInvariants(stats("b"));
#endif
}
