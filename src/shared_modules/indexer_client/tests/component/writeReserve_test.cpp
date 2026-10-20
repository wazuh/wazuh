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

    std::uint64_t linesOf(const std::vector<wr::Batch>& batches)
    {
        std::uint64_t total = 0;
        for (const auto& batch : batches)
        {
            for (const auto& op : batch.ops)
            {
                total += op->lines.size();
            }
        }
        return total;
    }
} // namespace

// CA-12: per accepted op, the heap kept besides its lines (OpState, TicketState, control blocks, the bucket's queue and
// delivered set, the callback, the completion queued on the pool with an OpResult at its caps, the result stored in
// the ticket, the reserve handle) is <= RESULT_RESERVE. Phases: (1) retained with a callback; (2) resolved, its
// completion queued behind a busy pool, the batch still held by the sink; (3) callback run, the Ticket still alive
// (reported: with a callback the reserve is already released); (4) without a callback, resolved, the Ticket alive.
TEST_F(WriteTest, ResultReserveMeasured)
{
#if !WRITE_RESERVE_COUNTER
    GTEST_SKIP() << "the allocation counter is compiled out under ASAN/TSAN (they own operator new)";
#else
    constexpr std::size_t N = 1024;
    constexpr std::size_t PER_BATCH = 64;
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 64u << 20, ic::Overflow::Kind::Reject, 1u << 20, PER_BATCH)});
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
            ASSERT_TRUE(m_path->resolve(op, result));
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
            ASSERT_TRUE(m_path->resolve(op, result));
        }
    }
    const double noCallback = perOp(base4);
    EXPECT_EQ(stats("b").charge, N * wr::RESULT_RESERVE) << "the tickets hold the reserves";
    tickets.clear();
    batches.clear();

    const double measured = std::max({retained, queued, noCallback});
    std::printf(
        "[ RESERVE  ] bytes per op besides its lines: retained %.1f, queued completion %.1f, after the callback "
        "(ticket alive) %.1f, no callback %.1f; max %.1f; RESULT_RESERVE %llu\n",
        retained,
        queued,
        afterCallback,
        noCallback,
        measured,
        static_cast<unsigned long long>(wr::RESULT_RESERVE));
    EXPECT_GT(measured, 0.0) << "the counter saw nothing: is the replacement operator new linked?";
    EXPECT_LE(measured, static_cast<double>(wr::RESULT_RESERVE)) << "RESULT_RESERVE is below what an op keeps";
#endif
}
