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

// Admission: the real charge, the four overflow policies, the global cap and the wake-ups (plan-E3a §Tests: CA-11,
// CA-12, RF-17, RF-27, I62).

#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "write/budget.hpp"
#include "writeFixture.hpp"

using namespace write_component;
using component::AsyncCall;
using component::eventually;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;

    /// Ids of a fixed width: every op of a case has the same wire size.
    std::string id(std::size_t n)
    {
        auto digits = std::to_string(n);
        return "k" + std::string(6 - digits.size(), '0') + digits;
    }

    /// A gate a callback can wait on (held by shared_ptr: the callback may outlive a failed case's frame).
    struct Gate final
    {
        std::promise<void> promise;
        std::shared_future<void> future {promise.get_future().share()};
        std::atomic<int> entered {0};

        void open()
        {
            try
            {
                promise.set_value();
            }
            catch (const std::future_error&)
            {
            }
        }
    };
} // namespace

// CA-12: the charge is the wire size plus RESULT_RESERVE; the payload is released at resolution and the reserve when
// the callback has run or, without a callback, when the last Ticket dies (never by wait()).
TEST_F(WriteTest, ChargeIsWireBytesPlusReserve)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
    auto writer = c->writer("b");
    const auto size = wireSize(indexOp(id(0), 300));

    // Without a callback.
    {
        auto submit = writer->submit(indexOp(id(0), 300));
        ASSERT_TRUE(submit.accepted);
        ASSERT_TRUE(sink->waitDispatched(1));
        EXPECT_EQ(stats("b").charge, size + R);
        EXPECT_EQ(globalCharge(), size + R);
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        ASSERT_EQ(batches[0].ops.size(), 1u);
        EXPECT_EQ(batches[0].ops[0]->wire(), size);

        ASSERT_TRUE(m_path->resolve(bucketOf(*batches[0].ops[0]), batches[0].ops[0], TestSink::ok()));
        EXPECT_EQ(stats("b").charge, R) << "the payload is released at resolution";
        EXPECT_EQ(globalCharge(), R);

        const auto waited = submit.ticket.wait(now() + 2s);
        ASSERT_TRUE(waited.ok()) << ic::toString(waited.cause);
        EXPECT_EQ(waited.value.status, ic::Status::Ok);
        EXPECT_EQ(stats("b").charge, R) << "wait() does not consume the reserve";
        EXPECT_EQ(submit.ticket.wait(now() + 2s).value.status, ic::Status::Ok) << "wait() can be repeated";

        ic::Ticket copy = submit.ticket;
        submit.ticket = ic::Ticket {};
        batches.clear();
        EXPECT_EQ(stats("b").charge, R) << "a copy of the Ticket still holds the reserve";
        EXPECT_TRUE(copy.ready());
        copy = ic::Ticket {};
        EXPECT_EQ(stats("b").charge, 0u) << "the last Ticket returns the reserve";
        EXPECT_EQ(globalCharge(), 0u);
    }

    // With a callback: the reserve survives the ticket's completion and the wait, and goes after the callback.
    {
        auto gate = std::make_shared<Gate>();
        auto submit = writer->submit(indexOp(id(1), 300),
                                     [gate](const ic::OpResult&)
                                     {
                                         ++gate->entered;
                                         gate->future.wait();
                                     });
        ASSERT_TRUE(submit.accepted);
        ASSERT_TRUE(sink->waitDispatched(2));
        EXPECT_EQ(stats("b").charge, size + R);
        ASSERT_EQ(sink->resolveHeld(), 1u);
        EXPECT_EQ(stats("b").charge, R);
        ASSERT_TRUE(eventually([&] { return gate->entered.load() == 1; }, 5s));
        const auto waited = submit.ticket.wait(now() + 2s);
        ASSERT_TRUE(waited.ok());
        EXPECT_EQ(stats("b").charge, R) << "the callback is still running";
        submit.ticket = ic::Ticket {};
        EXPECT_EQ(stats("b").charge, R) << "with a callback the Ticket does not own the reserve";
        gate->open();
        EXPECT_TRUE(eventually([&] { return stats("b").charge == 0 && globalCharge() == 0; }, 5s));
    }
    expectInvariants(stats("b"));
}

// CA-12: the global cap binds across buckets whose quotas add up to more than it: the bucket that hits it applies its
// own policy although its quota has room, and the global charge never exceeds the cap.
TEST_F(WriteTest, GlobalCapAcrossBuckets)
{
    const std::uint64_t cap = 96 * 1024;
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"global_quota_bytes", std::to_string(cap)}}));
    installSink();
    const std::size_t quota = 64 * 1024;
    auto blocking = bucketSpec("block", quota, ic::Overflow::Kind::Block);
    blocking.overflow.blockTimeout = ic::Duration {200};
    auto c = client("c",
                    {bucketSpec("a", quota),
                     bucketSpec("b", quota),
                     bucketSpec("dropNewest", quota, ic::Overflow::Kind::DropNewest),
                     blocking});
    const auto charge = wireSize(indexOp(id(0), 2000)) + R;

    std::size_t n = 0;
    auto wa = c->writer("a");
    while (wa->submit(indexOp(id(n++), 2000)).accepted)
    {
        ASSERT_LE(globalCharge(), cap);
    }
    const auto a = stats("a");
    EXPECT_EQ(a.rejectedQueueFull, 1u);
    EXPECT_GT(a.charge + charge, quota) << "a stops at its own quota";

    auto wb = c->writer("b");
    while (wb->submit(indexOp(id(n++), 2000)).accepted)
    {
        ASSERT_LE(globalCharge(), cap);
    }
    const auto b = stats("b");
    EXPECT_EQ(b.rejectedQueueFull, 1u);
    EXPECT_LE(b.charge + charge, quota) << "b had room in its quota: the cap refused it";
    EXPECT_GT(globalCharge() + charge, cap);
    EXPECT_LE(globalCharge(), cap);

    // The other policies on the cap: DropNewest drops (counted), Block times out (counted).
    auto dropped = c->writer("dropNewest")->submit(indexOp(id(n++), 2000));
    ASSERT_TRUE(dropped.accepted);
    ASSERT_TRUE(dropped.ticket.ready());
    EXPECT_EQ(dropped.ticket.wait(now() + 1s).value.cause, ic::Cause::QueueFull);
    EXPECT_EQ(stats("dropNewest").droppedNewest, 1u);
    EXPECT_EQ(stats("dropNewest").charge, 0u);
    const auto t0 = now();
    EXPECT_EQ(c->writer("block")->submit(indexOp(id(n++), 2000)).cause, ic::Cause::SubmitTimeout);
    EXPECT_GE(now() - t0, 200ms);
    EXPECT_EQ(stats("block").submitTimeout, 1u);
    EXPECT_LE(globalCharge(), cap);

    closeNow(*c); // I99: the ops of a and b drain into the held sink, then the sweep drops them.
    for (const auto* name : {"a", "b", "dropNewest", "block"})
    {
        expectInvariants(stats(name));
    }
}

// CA-11/T4: Reject refuses (no ticket, no callback) and counts; room again admits.
TEST_F(WriteTest, OverflowReject)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto size = wireSize(indexOp(id(0), 1000));
    // Room for one more reserve but not for one more op: a drop policy would accept (and drop) here, Reject refuses.
    auto c = client("c", {bucketSpec("b", 3 * (size + R) + R, ic::Overflow::Kind::Reject, 0, 3)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    const auto refused = writer->submit(indexOp(id(3), 1000), results->callback(3));
    EXPECT_FALSE(refused.accepted);
    EXPECT_EQ(refused.cause, ic::Cause::QueueFull);
    EXPECT_FALSE(refused.ticket.ready());
    const auto refusedNoCallback = writer->submit(indexOp(id(5), 1000));
    EXPECT_FALSE(refusedNoCallback.accepted);
    EXPECT_EQ(refusedNoCallback.cause, ic::Cause::QueueFull);
    auto s = stats("b");
    EXPECT_EQ(s.rejectedQueueFull, 2u);
    EXPECT_EQ(s.accepted, 3u);
    EXPECT_EQ(s.droppedNewest + s.droppedOldest, 0u);
    EXPECT_EQ(s.charge, 3 * (size + R));

    ASSERT_TRUE(sink->waitDispatched(1)); // maxDocs 3: the three ops went to the sink.
    ASSERT_EQ(sink->resolveHeld(), 3u);
    ASSERT_TRUE(results->waitTotal(3));
    ASSERT_TRUE(eventually([&] { return stats("b").charge == 0; }, 5s));
    EXPECT_TRUE(writer->submit(indexOp(id(4), 1000), results->callback(4)).accepted) << "room again";
    closeNow(*c); // I99: the held sink never answers; the sweep resolves op 4.
    ASSERT_TRUE(results->waitTotal(4));
    EXPECT_EQ(results->count(3), 0) << "a refused submit never calls back";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    expectInvariants(stats("b"));
}

// CA-11/T4: Block waits for room up to blockTimeout, then SubmitTimeout (counted).
TEST_F(WriteTest, OverflowBlockTimeout)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const auto size = wireSize(indexOp(id(0), 1000));
    auto spec = bucketSpec("b", 3 * (size + R), ic::Overflow::Kind::Block);
    spec.overflow.blockTimeout = ic::Duration {300};
    auto c = client("c", {spec});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000)).accepted);
    }
    const auto t0 = now();
    const auto timedOut = writer->submit(indexOp(id(3), 1000), results->callback(3));
    const auto elapsed = now() - t0;
    EXPECT_FALSE(timedOut.accepted);
    EXPECT_EQ(timedOut.cause, ic::Cause::SubmitTimeout);
    EXPECT_GE(elapsed, 300ms) << "Block waits for its blockTimeout";
    EXPECT_LT(elapsed, 2s);
    auto s = stats("b");
    EXPECT_EQ(s.submitTimeout, 1u);
    EXPECT_EQ(s.rejectedQueueFull, 0u);
    EXPECT_EQ(s.accepted, 3u);
    closeNow(*c);
    EXPECT_EQ(results->total(), 0u);
    expectInvariants(stats("b"));
}

// CA-11/T4: DropNewest accepts and drops the new op (QueueFull): without a callback the ticket is complete at once and
// nothing is charged; with one only RESULT_RESERVE is charged until it runs, and if even that does not fit the submit
// is refused. The pending ops are never touched.
TEST_F(WriteTest, OverflowDropNewest)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 0); // Nothing leaves the bucket until granted.
    const auto size = wireSize(indexOp(id(0), 1000));
    auto c = client("c", {bucketSpec("b", 3 * (size + R) + R, ic::Overflow::Kind::DropNewest, 0, 3)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    const auto full = stats("b").charge;
    EXPECT_EQ(full, 3 * (size + R));

    const auto noCallback = writer->submit(indexOp(id(3), 1000));
    ASSERT_TRUE(noCallback.accepted);
    ASSERT_TRUE(noCallback.ticket.ready()) << "completed in line, without the pool";
    const auto dropped = noCallback.ticket.wait(now() + 1s);
    EXPECT_EQ(dropped.value.status, ic::Status::Dropped);
    EXPECT_EQ(dropped.value.cause, ic::Cause::QueueFull);
    EXPECT_EQ(stats("b").charge, full) << "nothing charged for a drop without callback";

    auto gate = std::make_shared<Gate>();
    auto withCallback = writer->submit(indexOp(id(4), 1000),
                                       [gate, results](const ic::OpResult& result)
                                       {
                                           results->callback(4)(result);
                                           gate->future.wait();
                                       });
    ASSERT_TRUE(withCallback.accepted);
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->result(4)->cause, ic::Cause::QueueFull);
    EXPECT_EQ(results->result(4)->status, ic::Status::Dropped);
    EXPECT_EQ(stats("b").charge, full + R) << "the reserve of the dropped op until its callback ends";

    const auto noRoom = writer->submit(indexOp(id(5), 1000), results->callback(5));
    EXPECT_FALSE(noRoom.accepted) << "not even the reserve fits";
    EXPECT_EQ(noRoom.cause, ic::Cause::QueueFull);
    gate->open();
    ASSERT_TRUE(eventually([&] { return stats("b").charge == full; }, 5s));

    auto s = stats("b");
    EXPECT_EQ(s.droppedNewest, 2u);
    EXPECT_EQ(s.droppedOldest, 0u);
    EXPECT_EQ(s.rejectedQueueFull, 1u);
    EXPECT_EQ(s.retained, 3u);

    sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(sink->waitDispatched(1));
    ASSERT_EQ(sink->resolveHeld(), 3u);
    ASSERT_TRUE(results->waitTotal(4));
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        EXPECT_EQ(results->result(k)->status, ic::Status::Ok) << "pending op " << k << " was never dropped";
    }
    EXPECT_EQ(results->count(5), 0);
    expectInvariants(stats("b"));
}

// CA-11/T4: DropOldest evicts the oldest PENDING op (Dropped(QueueFull), counted), never one delivered to the sink;
// with nothing pending it falls back to DropNewest.
TEST_F(WriteTest, OverflowDropOldest)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 1); // One batch: op0 and op1.
    const auto size = wireSize(indexOp(id(0), 1000));
    auto c = client("c", {bucketSpec("b", 4 * (size + R) + R, ic::Overflow::Kind::DropOldest, 0, 2)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 2; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    ASSERT_TRUE(sink->waitDispatched(1));
    for (std::uint64_t k = 2; k < 4; ++k) // Pending: the sink has no capacity left.
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 1000), results->callback(k)).accepted);
    }
    EXPECT_EQ(stats("b").charge, 4 * (size + R));

    ASSERT_TRUE(writer->submit(indexOp(id(4), 1000), results->callback(4)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->count(2), 1) << "the oldest pending op (op2) is the one evicted";
    EXPECT_EQ(results->result(2)->cause, ic::Cause::QueueFull);
    EXPECT_EQ(results->result(2)->status, ic::Status::Dropped);
    ASSERT_TRUE(eventually([&] { return stats("b").charge == 4 * (size + R); }, 5s));

    ASSERT_TRUE(writer->submit(indexOp(id(5), 1000), results->callback(5)).accepted);
    ASSERT_TRUE(results->waitTotal(2));
    EXPECT_EQ(results->count(3), 1) << "then op3";
    ASSERT_TRUE(eventually([&] { return stats("b").charge == 4 * (size + R); }, 5s));

    // op4 and op5 go to the sink; nothing is pending: a new op cannot evict the delivered ones and is dropped.
    sink->grant(1);
    ASSERT_TRUE(sink->waitDispatched(2));
    ASSERT_TRUE(writer->submit(indexOp(id(6), 1000), results->callback(6)).accepted);
    ASSERT_TRUE(results->waitTotal(3));
    EXPECT_EQ(results->result(6)->cause, ic::Cause::QueueFull) << "fallback to DropNewest";

    auto s = stats("b");
    EXPECT_EQ(s.droppedOldest, 2u);
    EXPECT_EQ(s.droppedNewest, 1u);
    EXPECT_EQ(sink->resolveHeld(), 4u) << "op0, op1, op4 and op5 were never evicted";
    ASSERT_TRUE(results->waitTotal(7));
    for (const std::uint64_t k : {0u, 1u, 4u, 5u})
    {
        EXPECT_EQ(results->result(k)->status, ic::Status::Ok) << "op" << k;
    }
    for (const std::uint64_t k : {2u, 3u, 6u})
    {
        EXPECT_EQ(results->count(k), 1) << "op" << k;
    }
    expectInvariants(stats("b"));
}

// CA-11/I62: a producer blocked in Block wakes on a LOCAL release (its bucket's payload) and on a GLOBAL release
// (another bucket's payload, with the cap the binding limit) and is admitted in < 500 ms, far from its 5 s timeout.
TEST_F(WriteTest, OverflowBlockWakes)
{
    const auto size = wireSize(indexOp(id(0), 1000));
    const std::uint64_t cap = 3 * (size + R) + R;
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"global_quota_bytes", std::to_string(cap)}}));
    auto sink = installSink();
    auto l = client("l", {bucketSpec("local", 2 * (size + R) + R, ic::Overflow::Kind::Block, 0, 2)});
    auto g = client("g",
                    {bucketSpec("filler", cap, ic::Overflow::Kind::Reject, 0, 3),
                     bucketSpec("waiter", cap, ic::Overflow::Kind::Block, 0, 3)});

    // Local: two ops in the sink fill the quota; the third blocks until one is resolved.
    {
        auto writer = l->writer("local");
        ASSERT_TRUE(writer->submit(indexOp(id(0), 1000)).accepted);
        ASSERT_TRUE(writer->submit(indexOp(id(1), 1000)).accepted);
        ASSERT_TRUE(sink->waitDispatched(1));
        auto admitted = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([writer, admitted]
                           { *admitted = static_cast<int>(writer->submit(indexOp(id(2), 1000)).cause); });
        // submitted is counted under the bucket mutex, which the producer only lets go inside the wait.
        ASSERT_TRUE(eventually([&] { return stats("local", "l").submitted == 3; }, 5s));
        EXPECT_FALSE(producer.done());
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        const auto t0 = now();
        ASSERT_TRUE(m_path->resolve(bucketOf(*batches[0].ops[0]), batches[0].ops[0], TestSink::ok()));
        ASSERT_TRUE(producer.wait(5s));
        EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(now() - t0).count(), 500)
            << "ms until woken by the local release";
        EXPECT_EQ(*admitted, static_cast<int>(ic::Cause::None));
        m_path->resolve(bucketOf(*batches[0].ops[1]), batches[0].ops[1], TestSink::ok());
        closeNow(*l); // The admitted op is still pending (I99: drained into the held sink, then swept).
        sink->take(); // That batch, already resolved by the sweep.
        ASSERT_TRUE(eventually([&] { return globalCharge() == 0; }, 5s));
        expectInvariants(stats("local", "l"));
    }
    const auto dispatchedBefore = sink->dispatched();

    // Global: the filler takes the cap; the waiter, with room in its own quota, blocks on the cap until a filler op
    // is resolved (a release in ANOTHER bucket).
    {
        auto filler = g->writer("filler");
        for (std::size_t k = 0; k < 3; ++k)
        {
            ASSERT_TRUE(filler->submit(indexOp(id(10 + k), 1000)).accepted);
        }
        ASSERT_TRUE(sink->waitDispatched(dispatchedBefore + 1));
        ASSERT_EQ(stats("filler", "g").rejectedQueueFull, 0u);
        auto waiter = g->writer("waiter");
        auto admitted = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([waiter, admitted]
                           { *admitted = static_cast<int>(waiter->submit(indexOp(id(20), 1000)).cause); });
        ASSERT_TRUE(eventually([&] { return stats("waiter", "g").submitted == 1; }, 5s));
        EXPECT_FALSE(producer.done());
        auto batches = sink->take();
        ASSERT_EQ(batches.size(), 1u);
        const auto t0 = now();
        ASSERT_TRUE(m_path->resolve(bucketOf(*batches[0].ops[0]), batches[0].ops[0], TestSink::ok()));
        ASSERT_TRUE(producer.wait(6s));
        EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(now() - t0).count(), 500)
            << "ms until woken by the global release";
        EXPECT_EQ(*admitted, static_cast<int>(ic::Cause::None));
        for (std::size_t k = 1; k < batches[0].ops.size(); ++k)
        {
            m_path->resolve(bucketOf(*batches[0].ops[k]), batches[0].ops[k], TestSink::ok());
        }
    }
    closeNow(*g); // The waiter's op is still pending (I99: drained into the held sink, then swept).
    expectInvariants(stats("filler", "g"));
    expectInvariants(stats("waiter", "g"));
}

// RF-17/I62: a producer asleep in Block wakes on requestClose() (ClientClosed) and on shutdown() (Shutdown) in
// < 500 ms, counted as rejectedClosed. The quota is held by an op already delivered to the sink, which the close does
// not sweep: no payload release can be what wakes the producer, only the close itself.
TEST_F(WriteTest, BlockedProducerWakesOnClose)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto size = wireSize(indexOp(id(0), 1000));
    const auto spec = bucketSpec("b", (size + R) + R, ic::Overflow::Kind::Block, 0, 1);

    auto closing = client("c", {spec});
    {
        auto writer = closing->writer("b");
        ASSERT_TRUE(writer->submit(indexOp(id(0), 1000)).accepted);
        ASSERT_TRUE(sink->waitDispatched(1));
        auto cause = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([writer, cause] { *cause = static_cast<int>(writer->submit(indexOp(id(1), 1000)).cause); });
        ASSERT_TRUE(eventually([&] { return stats("b").submitted == 2; }, 5s));
        EXPECT_FALSE(producer.done());
        const auto t0 = now();
        closing->requestClose();
        ASSERT_TRUE(producer.wait(6s));
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now() - t0);
        EXPECT_LT(elapsed.count(), 500) << "ms until the blocked producer woke";
        EXPECT_EQ(*cause, static_cast<int>(ic::Cause::ClientClosed));
        EXPECT_EQ(stats("b").retained, 1u) << "the delivered op was not swept by the close";
        EXPECT_EQ(sink->resolveHeld(), 1u);
        auto s = stats("b");
        EXPECT_EQ(s.rejectedClosed, 1u);
        EXPECT_EQ(s.submitTimeout, 0u);
        expectInvariants(s);
    }

    auto shutting = client("s", {spec});
    {
        auto writer = shutting->writer("b");
        ASSERT_TRUE(writer->submit(indexOp(id(0), 1000)).accepted);
        ASSERT_TRUE(sink->waitDispatched(2));
        auto cause = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([writer, cause] { *cause = static_cast<int>(writer->submit(indexOp(id(1), 1000)).cause); });
        ASSERT_TRUE(eventually([&] { return stats("b", "s").submitted == 2; }, 5s));
        EXPECT_FALSE(producer.done());
        const auto t0 = now();
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        ASSERT_TRUE(producer.wait(6s));
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now() - t0);
        EXPECT_LT(elapsed.count(), 500) << "ms until the blocked producer woke";
        EXPECT_EQ(*cause, static_cast<int>(ic::Cause::Shutdown));
        auto s = stats("b", "s");
        EXPECT_EQ(s.rejectedClosed, 1u);
        expectInvariants(s);
    }
}

// CA-11: 8 producers on each of the 4 policies under pressure: the I62 invariants hold, every drop the producers saw
// is counted (droppedNewest + droppedOldest), every refusal too, and the pool's queue stays bounded by
// quota / RESULT_RESERVE (each queued completion holds a reserve).
TEST_F(WriteTest, NoDropWithoutCounter)
{
    constexpr std::size_t PRODUCERS = 8;
    constexpr std::size_t PER_PRODUCER = 150;
    ASSERT_NO_FATAL_FAILURE(start(1, 2));
    auto sink = installSink();
    const auto size = wireSize(indexOp(id(0), 1000));
    const std::size_t quota = 16 * (size + R);
    auto blocking = bucketSpec("block", quota, ic::Overflow::Kind::Block, 0, 4, ic::Duration {20});
    blocking.overflow.blockTimeout = ic::Duration {20};
    const std::vector<ic::BucketSpec> specs {
        bucketSpec("reject", quota, ic::Overflow::Kind::Reject, 0, 4, ic::Duration {20}),
        blocking,
        bucketSpec("dropNewest", quota, ic::Overflow::Kind::DropNewest, 0, 4, ic::Duration {20}),
        bucketSpec("dropOldest", quota, ic::Overflow::Kind::DropOldest, 0, 4, ic::Duration {20}),
    };
    auto c = client("c", specs);

    struct Observed final
    {
        std::atomic<std::uint64_t> accepted {0};
        std::atomic<std::uint64_t> queueFull {0};
        std::atomic<std::uint64_t> timeout {0};
        std::atomic<std::uint64_t> other {0};
        std::atomic<std::uint64_t> droppedSeen {0}; ///< Results Dropped(QueueFull), tickets and callbacks.
        std::atomic<std::uint64_t> withCallback {0};
        std::atomic<std::uint64_t> callbacks {0};
    };
    std::vector<std::shared_ptr<Observed>> observed;
    for (std::size_t i = 0; i < specs.size(); ++i)
    {
        observed.push_back(std::make_shared<Observed>());
    }

    std::atomic<bool> draining {true};
    std::thread drainer(
        [&]
        {
            while (draining.load())
            {
                sink->resolveHeld();
                std::this_thread::sleep_for(1ms); // Pacing: lets the quotas fill.
            }
        });

    std::vector<std::thread> producers;
    for (std::size_t b = 0; b < specs.size(); ++b)
    {
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            producers.emplace_back(
                [&, b, p]
                {
                    auto writer = c->writer(specs[b].name);
                    auto seen = observed[b];
                    std::vector<ic::Ticket> tickets;
                    const auto settle = [&]
                    {
                        for (const auto& ticket : tickets)
                        {
                            const auto result = ticket.wait(now() + 5s);
                            if (!result.ok())
                            {
                                ++seen->other;
                            }
                            else if (result.value.status == ic::Status::Dropped &&
                                     result.value.cause == ic::Cause::QueueFull)
                            {
                                ++seen->droppedSeen;
                            }
                        }
                        tickets.clear();
                    };
                    for (std::size_t i = 0; i < PER_PRODUCER; ++i)
                    {
                        const bool withCallback = i % 2 == 0;
                        ic::Callback callback;
                        if (withCallback)
                        {
                            callback = [seen](const ic::OpResult& result)
                            {
                                if (result.status == ic::Status::Dropped && result.cause == ic::Cause::QueueFull)
                                {
                                    ++seen->droppedSeen;
                                }
                                ++seen->callbacks;
                            };
                        }
                        auto submit = writer->submit(indexOp(id(p * 1000 + i), 1000), std::move(callback));
                        if (submit.accepted)
                        {
                            ++seen->accepted;
                            if (withCallback)
                            {
                                ++seen->withCallback;
                            }
                            else
                            {
                                tickets.push_back(std::move(submit.ticket));
                            }
                        }
                        else if (submit.cause == ic::Cause::QueueFull)
                        {
                            ++seen->queueFull;
                        }
                        else if (submit.cause == ic::Cause::SubmitTimeout)
                        {
                            ++seen->timeout;
                        }
                        else
                        {
                            ++seen->other;
                        }
                        if (tickets.size() >= 4)
                        {
                            settle();
                        }
                    }
                    settle();
                });
        }
    }
    for (auto& producer : producers)
    {
        producer.join();
    }
    for (std::size_t b = 0; b < specs.size(); ++b)
    {
        const auto& seen = *observed[b];
        ASSERT_TRUE(eventually([&] { return seen.callbacks.load() == seen.withCallback.load(); }, 10s))
            << specs[b].name;
    }
    ASSERT_TRUE(eventually([&] { return drainedNow(); }, 10s)) << describe(m_path->stats());
    draining = false;
    drainer.join();

    const auto pool = ic::detail::runtimePoolStats();
    EXPECT_LE(pool.peakPostsPending, specs.size() * quota / R) << "completions queued on the pool";
    for (std::size_t b = 0; b < specs.size(); ++b)
    {
        SCOPED_TRACE(specs[b].name);
        const auto& seen = *observed[b];
        const auto s = stats(specs[b].name);
        expectInvariants(s);
        EXPECT_EQ(seen.other.load(), 0u);
        EXPECT_EQ(s.submitted, PRODUCERS * PER_PRODUCER);
        EXPECT_EQ(s.accepted, seen.accepted.load());
        EXPECT_EQ(s.rejectedQueueFull, seen.queueFull.load());
        EXPECT_EQ(s.submitTimeout, seen.timeout.load());
        EXPECT_EQ(s.droppedNewest + s.droppedOldest, seen.droppedSeen.load()) << "every drop is counted";
        EXPECT_EQ(s.resolvedDropped, seen.droppedSeen.load());
        EXPECT_EQ(s.retained, 0u);
    }
    // The pressure was real: each policy hit its quota. A DropOldest op that evicting every pending op would not make
    // fit (the rest of the charge in flight or held by reserves) is dropped as the newest, so that bucket's pressure is
    // either counter; the eviction itself is OverflowDropOldest's (D69).
    EXPECT_GT(stats("reject").rejectedQueueFull, 0u);
    EXPECT_GT(stats("dropNewest").droppedNewest, 0u);
    EXPECT_GT(stats("dropOldest").droppedOldest + stats("dropOldest").droppedNewest, 0u);
}

// RF-27: with the quota full, a Block submit from a runtime thread (pool or network loop) returns Reentrancy at once
// instead of sleeping on a quota it may be the one to free; counted.
TEST_F(WriteTest, BlockFromRuntimeThreadIsReentrancy)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const auto size = wireSize(indexOp(id(0), 1000));
    auto c = client("c", {bucketSpec("b", (size + R) + R, ic::Overflow::Kind::Block)});
    auto writer = c->writer("b");
    ASSERT_TRUE(writer->submit(indexOp(id(0), 1000)).accepted);

    struct Answer final
    {
        std::promise<std::pair<ic::Cause, std::chrono::nanoseconds>> promise;
    };
    const auto runOn = [&](const std::function<bool(std::function<void()>)>& post)
    {
        auto outcome = std::make_shared<Answer>();
        auto future = outcome->promise.get_future();
        const bool posted = post(
            [writer, outcome]
            {
                const auto t0 = now();
                const auto cause = writer->submit(indexOp(id(1), 1000)).cause;
                outcome->promise.set_value({cause, now() - t0});
            });
        EXPECT_TRUE(posted);
        EXPECT_EQ(future.wait_for(2s), std::future_status::ready) << "the runtime thread slept";
        return future.wait_for(0s) == std::future_status::ready
                   ? future.get()
                   : std::make_pair(ic::Cause::None, std::chrono::nanoseconds {});
    };

    const auto onPool =
        runOn([](std::function<void()> task) { return ic::detail::testing::postToPool(std::move(task)); });
    EXPECT_EQ(onPool.first, ic::Cause::Reentrancy);
    EXPECT_LT(onPool.second, 100ms);
    const auto onLoop =
        runOn([](std::function<void()> task) { return ic::detail::testing::postToIoLoop(std::move(task), 0); });
    EXPECT_EQ(onLoop.first, ic::Cause::Reentrancy);
    EXPECT_LT(onLoop.second, 100ms);

    auto s = stats("b");
    EXPECT_EQ(s.reentrancy, 2u);
    EXPECT_EQ(s.submitTimeout, 0u);
    closeNow(*c);
    expectInvariants(stats("b"));
}

// I62: an encoded op over bulk.maxBytes is PayloadTooLarge at submit (counted, no ticket, no callback); exactly
// maxBytes is admitted. A charge over the quota or over the global cap is PayloadTooLarge too: registration makes that
// unreachable through the public API (maxBytes + RESULT_RESERVE <= quotaBytes <= cap), so it is checked on a Bucket.
TEST_F(WriteTest, PayloadTooLargeAtSubmit)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const std::size_t maxBytes = 2000;
    auto c = client("c", {bucketSpec("b", 64 * 1024, ic::Overflow::Kind::Reject, maxBytes, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();

    const auto overhead = wireSize(indexOp(id(0), 100)) - 100;
    const auto tooLarge = writer->submit(indexOp(id(0), maxBytes - overhead + 1), results->callback(0));
    EXPECT_FALSE(tooLarge.accepted);
    EXPECT_EQ(tooLarge.cause, ic::Cause::PayloadTooLarge);
    EXPECT_FALSE(tooLarge.ticket.ready());
    EXPECT_EQ(stats("b").payloadTooLarge, 1u);
    EXPECT_EQ(stats("b").charge, 0u);

    ASSERT_EQ(wireSize(indexOp(id(1), maxBytes - overhead)), maxBytes);
    EXPECT_TRUE(writer->submit(indexOp(id(1), maxBytes - overhead), results->callback(1)).accepted);
    ASSERT_TRUE(sink->waitDispatched(1));
    EXPECT_EQ(sink->resolveHeld(), 1u);
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->count(0), 0);
    expectInvariants(stats("b"));

    // The other two limits, on a bucket built without the registration rule.
    const auto far = now() + 1s;
    const std::uint64_t quota = 4 * R + 4096;
    {
        wr::GlobalBudget budget(1u << 30);
        ic::BucketSpec spec = bucketSpec("q", quota);
        spec.bulk.maxBytes = quota; // maxBytes + RESULT_RESERVE > quotaBytes: registration would refuse it.
        auto bucket = std::make_shared<wr::Bucket>("direct", spec, budget);
        const auto reservation = bucket->reserve(quota - R + 1, false, far);
        EXPECT_EQ(reservation.cause, ic::Cause::PayloadTooLarge) << "charge > quotaBytes";
        EXPECT_EQ(bucket->stats().payloadTooLarge, 1u);
        EXPECT_EQ(budget.charge(), 0u);
    }
    {
        wr::GlobalBudget budget(quota);
        auto bucket = std::make_shared<wr::Bucket>("direct", bucketSpec("g", 2 * quota), budget);
        const auto reservation = bucket->reserve(quota - R + 1, false, far);
        EXPECT_EQ(reservation.cause, ic::Cause::PayloadTooLarge) << "charge > the global cap";
        EXPECT_EQ(bucket->stats().payloadTooLarge, 1u);
        EXPECT_EQ(budget.charge(), 0u);
    }
}

// G-diff E3a obj. 1: an op without callback keeps its RESULT_RESERVE in the Ticket; when the bucket dies first (the
// Client and its writers are gone and only the Ticket is left), the last Ticket still returns it to the global cap.
TEST_F(WriteTest, ReserveReturnedWhenBucketDies)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    ic::Ticket ticket;
    {
        auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
        auto writer = c->writer("b");
        auto submit = writer->submit(indexOp("k1", 300));
        ASSERT_TRUE(submit.accepted);
        ticket = submit.ticket;
        ASSERT_TRUE(sink->waitDispatched(1));
        ASSERT_EQ(sink->resolveHeld(), 1u);
        EXPECT_EQ(globalCharge(), wr::RESULT_RESERVE) << "payload released, reserve in the ticket";
        writer.reset();
    } // ~Client: requestClose + awaitClosed; then the ClientState and its Bucket die (only the ticket is left).
    // A scheduler pass on loop 0 holds the bucket (weak_ptr::lock) for its duration: it may outlive ~Client by a pass
    // (E6c matrix: 1 failure in 463 under load). The bucket must go, not necessarily at once.
    EXPECT_TRUE(eventually([&] { return m_path->stats().buckets.empty(); }, 2s)) << "the bucket is gone";
    EXPECT_EQ(globalCharge(), wr::RESULT_RESERVE) << "the ticket still holds the reserve";
    ticket = ic::Ticket {};
    EXPECT_EQ(globalCharge(), 0u) << "the last Ticket returns the reserve to the global cap";
}

// G-diff E3a obj. 6: DropOldest evicts TWO pending ops for one larger op, with a global surplus (freed > charge): the
// bucket charge and the global charge agree afterwards (OverflowDropOldest only evicts 1:1 with equal sizes).
TEST_F(WriteTest, DropOldestEvictsSeveralWithGlobalSurplus)
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 1);
    const auto p = wireSize(indexOp("k00001", 4000));
    const auto P = wireSize(indexOp("k00001", 6000));
    ASSERT_GT(2 * p, P + R) << "a surplus exists";
    auto c = client("c", {bucketSpec("b", 3 * (p + R) + R, ic::Overflow::Kind::DropOldest, 0, 1)});
    auto writer = c->writer("b");
    std::vector<ic::Ticket> tickets;
    for (int k = 0; k < 3; ++k)
    {
        auto s = writer->submit(indexOp("k0000" + std::to_string(k), 4000));
        ASSERT_TRUE(s.accepted);
        tickets.push_back(s.ticket);
    }
    ASSERT_TRUE(sink->waitDispatched(1));
    EXPECT_EQ(stats("b").charge, 3 * (p + R));
    auto big = writer->submit(indexOp("k00009", 6000));
    ASSERT_TRUE(big.accepted) << ic::toString(big.cause);
    EXPECT_FALSE(big.ticket.ready()) << "admitted, pending";
    auto s = stats("b");
    EXPECT_EQ(s.droppedOldest, 2u);
    EXPECT_EQ(s.droppedNewest, 0u);
    EXPECT_EQ(s.retained, 2u);
    EXPECT_EQ(s.charge, (p + R) + (P + R) + 2 * R) << describe(s);
    EXPECT_EQ(globalCharge(), s.charge) << "surplus released globally";
    EXPECT_TRUE(tickets[1].ready());
    EXPECT_TRUE(tickets[2].ready());
    EXPECT_EQ(tickets[1].wait(now() + 1s).value.cause, ic::Cause::QueueFull);
    tickets.clear();
    sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(sink->waitDispatched(2));
    EXPECT_EQ(sink->resolveHeld(), 2u);
    big.ticket = ic::Ticket {};
    expectInvariants(stats("b"));
}

// G-diff E3a obj. 3 (I63): a consumer callback that throws still returns its RESULT_RESERVE, leaves no completion
// in flight and does not take the pool thread down: a later op is served and its callback runs.
TEST_F(WriteTest, CallbackThrowsStillReleasesReserve)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 1)});
    auto writer = c->writer("b");
    std::atomic<int> thrown {0};
    ASSERT_TRUE(writer
                    ->submit(indexOp("k1"),
                             [&thrown](const ic::OpResult&)
                             {
                                 thrown.fetch_add(1);
                                 throw std::runtime_error("consumer callback failure");
                             })
                    .accepted);
    ASSERT_TRUE(sink->waitDispatched(1));
    ASSERT_EQ(sink->resolveHeld(), 1u);
    ASSERT_TRUE(eventually([&] { return thrown.load() == 1 && globalCharge() == 0; }, 5s))
        << "charge " << globalCharge();
    EXPECT_EQ(stats("b").charge, 0u);

    std::atomic<bool> later {false};
    ASSERT_TRUE(writer->submit(indexOp("k2"), [&later](const ic::OpResult&) { later.store(true); }).accepted);
    ASSERT_TRUE(sink->waitDispatched(2));
    ASSERT_EQ(sink->resolveHeld(), 1u);
    EXPECT_TRUE(eventually([&] { return later.load(); }, 5s)) << "the pool still serves callbacks";
    writer.reset();
    const auto report = c->awaitClosed(now() + 5s);
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.callbacksInFlight, 0u);
}

// CA-E6d-2 (I122): 1 000 post() into a sink that resolves every op Ok: each is accepted (Posted carries no ticket); the
// result exists only in the counters — the client's metrics count ok = 1 000 — and the charge, RESULT_RESERVE included,
// is 0 once they are resolved (nobody else returns a post op's reserve). Mutant m2: resolve keeps a post op's reserve.
TEST_F(WriteTest, PostResolvesInMetrics)
{
    constexpr std::size_t N = 1000;
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::ResolveOk);
    auto c = client("c", {bucketSpec("b", 8u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 100)});
    auto writer = c->writer("b");
    std::size_t accepted = 0;
    for (std::size_t k = 0; k < N; ++k)
    {
        const auto posted = writer->post(indexOp(id(k)));
        EXPECT_EQ(posted.cause, ic::Cause::None);
        EXPECT_TRUE(posted.reason.empty()) << posted.reason;
        accepted += posted.accepted ? 1 : 0;
    }
    EXPECT_EQ(accepted, N);
    const auto okOf = [&c]() -> std::uint64_t
    {
        for (const auto& bucket : c->metrics().buckets)
        {
            if (bucket.bucket == "b")
            {
                return bucket.ok;
            }
        }
        return 0;
    };
    EXPECT_TRUE(eventually([&] { return okOf() == N; }, 5s)) << "ok = " << okOf();
    EXPECT_TRUE(eventually([&] { return stats("b").charge == 0 && globalCharge() == 0; }, 5s))
        << describe(stats("b")) << " global " << globalCharge();
    const auto s = stats("b");
    EXPECT_EQ(s.accepted, N);
    EXPECT_EQ(s.resolvedOk, N);
    EXPECT_EQ(s.retained, 0u);
    expectInvariants(s);
}

// CA-E6d-2 (I122): post() refuses exactly as submit(): a '\n' in the body is InvalidArgument with a reason that names
// the field first; a full Reject bucket is QueueFull; a Block bucket from a runtime thread is Reentrancy (at once);
// after requestClose() it is ClientClosed. A refusal charges nothing.
TEST_F(WriteTest, PostRefusals)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    const auto one = chargeOf(indexOp(id(0), 1000)) + R;
    auto c = client("c",
                    {bucketSpec("reject", one + R, ic::Overflow::Kind::Reject),
                     bucketSpec("block", one + R, ic::Overflow::Kind::Block)});
    auto reject = c->writer("reject");
    auto block = c->writer("block");

    auto bad = indexOp(id(9));
    bad.body = "{\"a\":\n1}";
    const auto invalid = reject->post(std::move(bad));
    EXPECT_FALSE(invalid.accepted);
    EXPECT_EQ(invalid.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(invalid.reason.rfind("body", 0), 0u) << invalid.reason;
    EXPECT_EQ(stats("reject").charge, 0u);
    EXPECT_EQ(stats("reject").invalidArgument, 1u);

    ASSERT_TRUE(reject->post(indexOp(id(0), 1000)).accepted);
    EXPECT_EQ(stats("reject").charge, one);
    const auto full = reject->post(indexOp(id(1), 1000));
    EXPECT_FALSE(full.accepted);
    EXPECT_EQ(full.cause, ic::Cause::QueueFull);
    EXPECT_EQ(stats("reject").charge, one) << "a refusal charges nothing";
    EXPECT_EQ(stats("reject").rejectedQueueFull, 1u);

    ASSERT_TRUE(block->post(indexOp(id(2), 1000)).accepted);
    EXPECT_EQ(stats("block").charge, one);
    auto answer = std::make_shared<std::promise<std::pair<ic::Cause, std::chrono::nanoseconds>>>();
    auto future = answer->get_future();
    ASSERT_TRUE(ic::detail::testing::postToPool(
        [block, answer]
        {
            const auto t0 = now();
            const auto cause = block->post(indexOp(id(3), 1000)).cause;
            answer->set_value({cause, now() - t0});
        }));
    ASSERT_EQ(future.wait_for(2s), std::future_status::ready) << "the runtime thread slept";
    const auto onPool = future.get();
    EXPECT_EQ(onPool.first, ic::Cause::Reentrancy);
    EXPECT_LT(onPool.second, 100ms);
    EXPECT_EQ(stats("block").charge, one);
    EXPECT_EQ(stats("block").reentrancy, 1u);

    c->requestClose();
    const auto closed = reject->post(indexOp(id(4)));
    EXPECT_FALSE(closed.accepted);
    EXPECT_EQ(closed.cause, ic::Cause::ClientClosed);
    EXPECT_EQ(block->post(indexOp(id(5))).cause, ic::Cause::ClientClosed);
    EXPECT_EQ(stats("reject").charge, one);
    EXPECT_EQ(stats("block").charge, one);
    EXPECT_EQ(stats("reject").rejectedClosed, 1u);
    closeNow(*c);
    expectInvariants(stats("reject"));
    expectInvariants(stats("block"));
}

// CA-E6d-2 (I122): with DropNewest or DropOldest full, post() is accepted and the overflow is only counted
// (droppedNewest / droppedOldest + 1): the producer is never told. Σ charge returns to 0 once the rest resolve.
TEST_F(WriteTest, PostDropPolicies)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 0);
    const auto one = chargeOf(indexOp(id(0), 1000)) + R;
    auto c = client("c",
                    {bucketSpec("newest", 3 * one + R, ic::Overflow::Kind::DropNewest, 0, 3),
                     bucketSpec("oldest", 3 * one + R, ic::Overflow::Kind::DropOldest, 0, 3)});
    std::uint64_t key = 0;
    for (const char* name : {"newest", "oldest"})
    {
        SCOPED_TRACE(name);
        auto writer = c->writer(name);
        for (int k = 0; k < 3; ++k)
        {
            ASSERT_TRUE(writer->post(indexOp(id(key++), 1000)).accepted);
        }
        // I209 (E6e B): a DropNewest bucket stages post(); the snapshot moves when the stripes are flushed.
        m_path->flushStaged();
        EXPECT_EQ(stats(name).charge, 3 * one);
        const auto overflow = writer->post(indexOp(id(key++), 1000));
        EXPECT_TRUE(overflow.accepted) << ic::toString(overflow.cause);
        EXPECT_EQ(overflow.cause, ic::Cause::None);
        m_path->flushStaged(); // I209.
        EXPECT_TRUE(eventually([&] { return stats(name).charge == 3 * one; }, 5s)) << describe(stats(name));
        EXPECT_EQ(stats(name).retained, 3u);
    }
    EXPECT_EQ(stats("newest").droppedNewest, 1u);
    EXPECT_EQ(stats("newest").droppedOldest, 0u);
    EXPECT_EQ(stats("oldest").droppedOldest, 1u);
    EXPECT_EQ(stats("oldest").droppedNewest, 0u);

    sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(sink->waitDispatched(2));
    EXPECT_EQ(sink->resolveHeld(), 6u);
    EXPECT_TRUE(eventually([&] { return globalCharge() == 0; }, 5s)) << describe(m_path->stats());
    EXPECT_EQ(stats("newest").charge, 0u);
    EXPECT_EQ(stats("oldest").charge, 0u);
    expectInvariants(stats("newest"));
    expectInvariants(stats("oldest"));
}

// CA-E6d-2 (I122, obj. 6): posted ops, some delivered to the sink and one still queued, when the client is destroyed
// before any of them resolved: the close sweeps and resolves all of them while their bucket is still alive (a post op
// has no ticket and no callback, so resolve returns its RESULT_RESERVE with its payload), the bucket then dies, the
// sink's late answers find them already resolved (won == 0), and the global cap is back to 0. It does not reach the
// branch of resolve without a bucket nor the reserve net of ~Bucket (G-diff E6d obj. 4; D66/D67).
TEST_F(WriteTest, PostReserveReturnedOnClientDestroyed)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"drain_ms", "300"}}));
    auto sink = installSink();
    const auto one = chargeOf(indexOp(id(0), 300)) + R;
    std::vector<std::shared_ptr<wr::OpState>> delivered;
    {
        auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 2)});
        auto writer = c->writer("b");
        for (std::uint64_t k = 0; k < 5; ++k)
        {
            ASSERT_TRUE(writer->post(indexOp(id(k), 300)).accepted);
        }
        ASSERT_TRUE(sink->waitDispatched(2));
        // The test keeps the delivered OpStates but not their batches: nothing but the client keeps the bucket.
        for (auto& batch : sink->take())
        {
            for (auto& op : batch.ops)
            {
                delivered.push_back(op);
            }
        }
        ASSERT_EQ(delivered.size(), 4u);
        EXPECT_EQ(stats("b").retained, 5u);
        EXPECT_EQ(globalCharge(), 5 * one);
        writer.reset();
    } // ~Client: requestClose + awaitClosed(now + drain_ms): the queued op and the delivered ones are swept.
    for (auto& batch : sink->take()) // The close flushed the queued op into the sink (D43): keep only its OpState.
    {
        for (auto& op : batch.ops)
        {
            delivered.push_back(op);
        }
    }
    EXPECT_GE(delivered.size(), 4u);
    EXPECT_TRUE(eventually([&] { return m_path->stats().buckets.empty(); }, 2s)) << "the bucket is gone";
    std::size_t won = 0;
    for (const auto& op : delivered)
    {
        // The sink's late answer, after its bucket died (E6e D: no bucket to pass, the branch of D66b/D67b).
        won += m_path->resolve(nullptr, op, TestSink::ok()) ? 1 : 0;
    }
    EXPECT_EQ(won, 0u) << "the close had resolved them";
    delivered.clear();
    EXPECT_TRUE(eventually([&] { return globalCharge() == 0; }, 2s)) << "global " << globalCharge();
}

// D67: posted ops delivered to the sink, whose client is destroyed on a runtime thread (the close does not wait and
// what is delivered keeps its course) and whose batches the sink lets go unresolved: the bucket dies with them in
// m_delivered. ~Bucket returns their payload to the global cap and their late resolution, through the branch of
// resolve without a bucket, returns their RESULT_RESERVE: the global cap is back to 0, each charge returned once.
TEST_F(WriteTest, DeliveredPayloadReturnedWhenBucketDiesFirst)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2));
    auto sink = installSink();
    const auto one = chargeOf(indexOp(id(0), 300)) + R;
    std::vector<std::shared_ptr<wr::OpState>> delivered;
    {
        auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 64 * 1024, 2)});
        {
            auto writer = c->writer("b");
            for (std::uint64_t k = 0; k < 4; ++k)
            {
                ASSERT_TRUE(writer->post(indexOp(id(k), 300)).accepted);
            }
        }
        ASSERT_TRUE(sink->waitDispatched(2));
        EXPECT_EQ(stats("b").retained, 4u);
        EXPECT_EQ(globalCharge(), 4 * one);
        // The test keeps the delivered OpStates but not their batches: nothing but the client keeps the bucket.
        for (auto& batch : sink->take())
        {
            for (auto& op : batch.ops)
            {
                delivered.push_back(op);
            }
        }
        ASSERT_EQ(delivered.size(), 4u);
        std::promise<void> destroyed;
        auto holder = std::make_shared<std::shared_ptr<ic::Client>>(std::move(c));
        ASSERT_TRUE(m_path->postToPool(
            [holder, &destroyed]
            {
                holder->reset(); // On a runtime thread: closed without waiting; the delivered ops keep their course.
                destroyed.set_value();
            }));
        destroyed.get_future().wait();
    }
    ASSERT_TRUE(eventually([&] { return m_path->stats().buckets.empty(); }, 2s)) << "the bucket is gone";
    EXPECT_EQ(globalCharge(), 4 * R) << "~Bucket returned the delivered payloads; the reserves are the ops' own";
    std::size_t won = 0;
    for (const auto& op : delivered)
    {
        won += m_path->resolve(nullptr, op, TestSink::ok()) ? 1 : 0; // The sink's late answer.
    }
    EXPECT_EQ(won, 4u) << "nothing had resolved them";
    delivered.clear();
    EXPECT_EQ(globalCharge(), 0u);
}

namespace
{
    /// An OpState of post as WriterImpl::prepare builds it (no ticket, callback nor group), for a bucket built
    /// directly.
    std::shared_ptr<wr::OpState> directOp(const std::string& key)
    {
        auto encoded = wr::encode(indexOp(key, 64), ic::ConflictPolicy {});
        EXPECT_TRUE(encoded.ok()) << encoded.reason;
        auto op = std::make_shared<wr::OpState>();
        op->head = std::move(encoded.value.head);
        op->body = std::move(encoded.value.body);
        op->payload = wr::chargeSize(op->headView(), op->body);
        op->reserveCharged = true;
        op->firstSubmit = now();
        return op;
    }
} // namespace

// Issue 15 (D64): a bucket destroyed with operations still queued (the close makes it unreachable: forced here on a
// bucket built directly, never closed). No abort in any build: ~Bucket logs an internal error, counts it and a usage
// error, and completes what is left as its comment says — the ticket gets Dropped(ClientClosed) — while the queued
// post op has nobody to tell. Mutant: the assert back in ~Bucket (this case aborts the suite).
TEST_F(WriteInternalErrorTest, BucketDestroyedWithQueuedOpsCompletesThem)
{
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", bucketSpec("q", 1u << 20), budget);
    auto withTicket = directOp("a");
    auto ticket = std::make_shared<ic::detail::TicketState>();
    withTicket->ticket = ticket;
    ASSERT_EQ(bucket->admit(withTicket, now(), now()).cause, ic::Cause::None);
    auto posted = directOp("b");
    ASSERT_EQ(bucket->admit(posted, now(), now()).cause, ic::Cause::None);
    ASSERT_EQ(bucket->stats().retained, 2u);

    const auto internalBefore = ic::testing_hooks::internalErrors();
    const auto usageBefore = ic::detail::testing::usageErrors();
    bucket.reset(); // The last reference: ~Bucket with two ops queued.

    EXPECT_EQ(ic::testing_hooks::internalErrors(), internalBefore + 1);
    EXPECT_EQ(ic::detail::testing::usageErrors(), usageBefore + 1);
    EXPECT_EQ(errors("a bucket destroyed with queued operations"), 1u);
    ASSERT_TRUE(ticket->isReady()) << "the ticket of a queued op is completed by ~Bucket";
    const auto result = ticket->waitUntil(now());
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value.status, ic::Status::Dropped);
    EXPECT_EQ(result.value.cause, ic::Cause::ClientClosed);
    EXPECT_TRUE(withTicket->claimed.load());
    EXPECT_TRUE(posted->claimed.load());
}

// Issue 15 (D64): an op resolved through a bucket other than its own (OpState::owner) — WritePath::resolve, and
// resolveBulk's Bucket::settleBulk for a post op. No abort in any build: each mismatch is logged and counted, and the
// resolution goes on with the caller's bucket (two twin buckets, so the swapped charges still balance to 0). Mutant:
// either assert back (this case aborts the suite).
TEST_F(WriteInternalErrorTest, ForeignBucketResolutionLoggedNotAborted)
{
    ASSERT_NO_FATAL_FAILURE(start());
    wr::GlobalBudget budget(1u << 30);
    // Two ops per bucket, one batch of exactly two (maxDocs), so both are delivered when sliced.
    auto first =
        std::make_shared<wr::Bucket>("direct", bucketSpec("one", 1u << 20, ic::Overflow::Kind::Reject, 0, 2), budget);
    auto second =
        std::make_shared<wr::Bucket>("direct", bucketSpec("two", 1u << 20, ic::Overflow::Kind::Reject, 0, 2), budget);
    std::vector<std::shared_ptr<wr::OpState>> ofFirst;
    std::vector<std::shared_ptr<wr::OpState>> ofSecond;
    for (const auto& key : {"k1", "k2"})
    {
        ofFirst.push_back(directOp(key));
        ofFirst.back()->owner = first.get();
        ASSERT_EQ(first->admit(ofFirst.back(), now(), now()).cause, ic::Cause::None);
        ofSecond.push_back(directOp(key));
        ofSecond.back()->owner = second.get();
        ASSERT_EQ(second->admit(ofSecond.back(), now(), now()).cause, ic::Cause::None);
    }
    ASSERT_EQ(first->slice(now()).ops.size(), 2u);
    ASSERT_EQ(second->slice(now()).ops.size(), 2u);
    const auto before = ic::testing_hooks::internalErrors();

    // WritePath::resolve: each op through the other bucket.
    EXPECT_TRUE(m_path->resolve(second, ofFirst[0], TestSink::ok()));
    EXPECT_TRUE(m_path->resolve(first, ofSecond[0], TestSink::ok()));
    EXPECT_EQ(ic::testing_hooks::internalErrors(), before + 2);
    EXPECT_EQ(errors("resolved through a bucket other than its own"), 2u);

    // resolveBulk -> Bucket::settleBulk (post ops): the same, one per op.
    std::vector<wr::BulkItem> intoSecond {wr::BulkItem {ofFirst[1].get(), TestSink::ok()}};
    std::vector<wr::BulkItem> intoFirst {wr::BulkItem {ofSecond[1].get(), TestSink::ok()}};
    EXPECT_EQ(m_path->resolveBulk(second, intoSecond), 1u);
    EXPECT_EQ(m_path->resolveBulk(first, intoFirst), 1u);
    EXPECT_EQ(ic::testing_hooks::internalErrors(), before + 4);
    EXPECT_EQ(errors("settled by a bucket other than its own"), 2u);

    for (const auto& bucket : {first, second})
    {
        const auto s = bucket->stats();
        EXPECT_EQ(s.resolvedOk, 2u);
        EXPECT_EQ(s.retained, 0u);
        EXPECT_EQ(s.charge, 0u) << "twin ops: the swapped releases still balance";
        expectInvariants(s);
    }
    EXPECT_EQ(budget.charge(), 0u);
}
