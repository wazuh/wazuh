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

// Writer::cancel(tag) end to end (plan-E3c-2 §Tests, step 6b; CA-26, T11, I25, I76-I78, I80): the pending and lane
// ops of the tag resolve Dropped(Cancelled) at once, the delivered ones are never sent again (also when cancel() lands
// between the slice and the assembly of their bulk) and the ticket completes with the last of them; an op answered
// with success stays Ok; other tags, other buckets and Building groups are untouched; the waiters' accounting (two
// cancels, an op of the tag enqueued after the cancel); the tag's validation; a wait from a callback; and the
// scheduler woken when a cancelled lane op unblocks an ordered bucket. The BulkTest cases run the production sender
// against a fake node (bulkFixture.hpp); the WriteTest ones use the TestSink (writeFixture.hpp). Every case ends with
// the charge and the retained ops at 0 (TearDown).

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;

namespace
{
    using Clock = std::chrono::steady_clock;

    ic::Deadline in(std::chrono::milliseconds timeout)
    {
        return now() + timeout;
    }

    /// Fixed-width ids: the key is recoverable from the `_id` the fake received.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    ic::Op tagged(std::uint64_t key, std::string tag, std::size_t bodyBytes = 16)
    {
        auto op = indexOp(id(key), bodyBytes);
        op.tag = std::move(tag);
        return op;
    }

    /// An ordered bucket of `maxDocs`-op batches with maxAge = 200 ms and a retry of `backoff` ms (base = cap, no
    /// jitter), unlimited attempts and no maxDuration (as bulkOrdered_test.cpp).
    ic::BucketSpec orderedBucket(std::string name, std::size_t maxDocs, std::int64_t backoff = 5)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs, ic::Duration {200});
        spec.ordered = true;
        spec.retry.maxAttempts.reset();
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {backoff};
        spec.retry.cap = ic::Duration {backoff};
        spec.retry.jitter = 0.0;
        return spec;
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

    std::vector<std::string> ids(const std::vector<indexer_client::testing::BulkOp>& ops)
    {
        std::vector<std::string> out;
        for (const auto& op : ops)
        {
            out.push_back(op.id.value_or("<none>"));
        }
        return out;
    }

    /// The beforeAssembly seam as a gate: while armed, the pool task that reaches it reports it and waits (<= 5 s)
    /// until open(); open() disarms it.
    class AssemblyGate final : public std::enable_shared_from_this<AssemblyGate>
    {
    public:
        static std::shared_ptr<AssemblyGate> install()
        {
            auto gate = std::shared_ptr<AssemblyGate>(new AssemblyGate());
            indexer_client::testing_hooks::setBeforeAssembly([gate] { gate->pass(); });
            return gate;
        }

        void arm()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_armed = true;
            m_entered = 0;
        }

        bool waitEntered(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [this] { return m_entered > 0; });
        }

        void open()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_armed = false;
            }
            m_cv.notify_all();
        }

    private:
        AssemblyGate() = default;

        void pass()
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (!m_armed)
            {
                return;
            }
            ++m_entered;
            m_cv.notify_all();
            m_cv.wait_for(lock, 5s, [this] { return !m_armed; });
        }

        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_armed {false};
        int m_entered {0};
    };

    /// Pending ops the TestSink cannot take yet: capacity 0 until the case grants it.
    ic::BucketSpec heldBack(std::string name, std::size_t maxDocs = 2)
    {
        return bucketSpec(std::move(name), 1u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
    }
} // namespace

// CA-26, T11: an ordered bucket (one bulk in flight) holds 1 000 pending ops of agent X while a bulk of X is in flight
// and comes back 503. cancel(X): the pending ones resolve Dropped(Cancelled) at once and the ticket waits; the 503
// makes the in-flight op Dropped(Cancelled) too, at the requeue (never back to the lane, whose 30 s backoff would
// keep the ticket waiting): 0 bulks after the cancel, every op Dropped(Cancelled), the ticket complete. Mutant: requeue
// puts a cancelled op back into the lane (the assembly would still drop it unsent, 30 s later).
TEST_F(BulkTest, CancelPendingAndInFlight503)
{
    constexpr std::uint64_t PENDING = 1000;
    const auto a = startNode();
    a.bulk->push(BulkScript::serverError(503).held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {orderedBucket("b", 1, 30000)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(tagged(0, "agent-x"), results->callback(0)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s)) << "the first bulk of X never reached the node";
    for (std::uint64_t k = 1; k <= PENDING; ++k)
    {
        ASSERT_TRUE(writer->submit(tagged(k, "agent-x"), results->callback(k)).accepted);
    }
    ASSERT_EQ(stats("b").retained, PENDING + 1);
    ASSERT_EQ(wr::senderStats().sent, 1u) << "precondition: the pending ops wait behind the bulk in flight";

    const auto ticket = writer->cancel("agent-x");
    ASSERT_TRUE(results->waitTotal(PENDING, 3s)) << results->total();
    EXPECT_FALSE(ticket.ready()) << "the bulk in flight has not resolved yet";
    EXPECT_EQ(results->total(), PENDING) << "the op in flight resolved before its answer";
    a.fake->releaseHeld();

    const auto outcome = ticket.wait(in(3s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
    ASSERT_TRUE(results->waitTotal(PENDING + 1, 3s)) << results->total();
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Cancelled), PENDING + 1);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 300ms)) << "an op of X was sent after cancel()";
    EXPECT_EQ(wr::senderStats().sent, 1u);
    const auto s = stats("b");
    EXPECT_EQ(s.cancelled, PENDING + 1);
    EXPECT_EQ(s.resolvedDropped, PENDING + 1);
    expectInvariants(s);
}

// I78: the same, but the bulk in flight is answered with success: its op stays Ok (it was applied) and the ticket
// completes only after it; the pending ones are Dropped(Cancelled).
TEST_F(BulkTest, CancelInFlightOkStaysOk)
{
    constexpr std::uint64_t PENDING = 10;
    const auto a = startNode();
    a.bulk->push(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {orderedBucket("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(tagged(0, "agent-x"), results->callback(0)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, 3s));
    for (std::uint64_t k = 1; k <= PENDING; ++k)
    {
        ASSERT_TRUE(writer->submit(tagged(k, "agent-x"), results->callback(k)).accepted);
    }

    const auto ticket = writer->cancel("agent-x");
    ASSERT_TRUE(results->waitTotal(PENDING, 3s));
    EXPECT_FALSE(eventually([&] { return ticket.ready(); }, 200ms)) << "ready with an op of the tag in flight";
    a.fake->releaseHeld();
    ASSERT_TRUE(ticket.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(PENDING + 1, 3s));
    ASSERT_TRUE(results->result(0).has_value());
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << "an applied op stays Ok";
    EXPECT_EQ(results->result(0)->outcome, ic::ItemOutcome::Created);
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Cancelled), PENDING);
    EXPECT_EQ(a.bulk->answered(), 1u);
    const auto s = stats("b");
    EXPECT_EQ(s.cancelled, PENDING);
    EXPECT_EQ(s.resolvedOk, 1u);
    expectInvariants(s);
}

// I80 (sender.hpp): cancel() lands between the slice and the assembly (the beforeAssembly seam holds the pool task).
// (1) A batch of X (tag T) and Y (tag U): the body carries only Y; X ends Dropped(Cancelled) and the ticket completes
// with it. (2) A batch of two ops of T2 only: no request at all, the slot back. Mutant: the assembly ignores the mark.
TEST_F(BulkTest, CancelSlicedBeforeSubmitNotSent)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto gate = AssemblyGate::install();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 2)});
    auto writer = c->writer("b");
    auto results = Results::create();

    // (1) X and Y in one batch.
    gate->arm();
    ASSERT_TRUE(writer->submit(tagged(0, "tag-t"), results->callback(0)).accepted);
    ASSERT_TRUE(writer->submit(tagged(1, "tag-u"), results->callback(1)).accepted);
    ASSERT_TRUE(gate->waitEntered(3s)) << "the batch never reached the assembly";
    const auto ticket = writer->cancel("tag-t");
    EXPECT_FALSE(ticket.ready()) << "X was delivered: the ticket waits for its resolution";
    gate->open();
    ASSERT_TRUE(ticket.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(2, 3s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Dropped);
    EXPECT_EQ(results->result(0)->cause, ic::Cause::Cancelled);
    EXPECT_EQ(results->result(1)->status, ic::Status::Ok);
    auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(ids(received[0]), (std::vector<std::string> {id(1)})) << "the body carried an op of the cancelled tag";

    // (2) A batch emptied by the cancel: no submit, the slot given back.
    const auto sentBefore = wr::senderStats().sent;
    gate->arm();
    ASSERT_TRUE(writer->submit(tagged(2, "tag-t2"), results->callback(2)).accepted);
    ASSERT_TRUE(writer->submit(tagged(3, "tag-t2"), results->callback(3)).accepted);
    ASSERT_TRUE(gate->waitEntered(3s));
    const auto emptied = writer->cancel("tag-t2");
    EXPECT_FALSE(emptied.ready());
    gate->open();
    ASSERT_TRUE(emptied.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(4, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Cancelled), 3u);
    ASSERT_TRUE(eventually([] { return inFlightTotal() == 0; }, 1s)) << "the emptied batch kept its slot";
    EXPECT_EQ(wr::senderStats().sent, sentBefore) << "an emptied batch was submitted";
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 200ms));
    const auto s = stats("b");
    EXPECT_EQ(s.cancelled, 3u);
    expectInvariants(s);
}

// I80: cancel(A) removes only A's ops of its own bucket: B's, the untagged ones and another bucket's op of tag A go on
// and end Ok. With nothing of A delivered the ticket is ready at once.
TEST_F(WriteTest, CancelOtherTagsUntouched)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::ResolveOk, 0);
    auto c = client("c", {heldBack("b"), heldBack("other", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    const char* tags[] = {"tag-a", "tag-b", ""};
    for (std::uint64_t k = 0; k < 6; ++k)
    {
        ASSERT_TRUE(writer->submit(tagged(k, tags[k % 3]), results->callback(k)).accepted);
    }
    ASSERT_TRUE(c->writer("other")->submit(tagged(6, "tag-a"), results->callback(6)).accepted);
    EXPECT_EQ(sink->dispatched(), 0u);

    const auto ticket = writer->cancel("tag-a");
    EXPECT_TRUE(ticket.ready()) << "nothing of the tag was delivered";
    ASSERT_TRUE(ticket.wait(in(1s)).ok());
    ASSERT_TRUE(results->waitTotal(2, 3s));
    sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(results->waitTotal(7, 3s)) << results->total();
    for (std::uint64_t k = 0; k < 7; ++k)
    {
        SCOPED_TRACE(k);
        ASSERT_TRUE(results->result(k).has_value());
        const bool cancelled = k == 0 || k == 3;
        EXPECT_EQ(results->result(k)->status, cancelled ? ic::Status::Dropped : ic::Status::Ok);
        EXPECT_EQ(results->result(k)->cause, cancelled ? ic::Cause::Cancelled : ic::Cause::None);
        EXPECT_EQ(results->count(k), 1);
    }
    EXPECT_EQ(stats("b").cancelled, 2u);
    EXPECT_EQ(stats("other").cancelled, 0u);
    expectInvariants(stats("b"));
    expectInvariants(stats("other"));
}

// I80: the ops of a committed group still queued are cancelled like any other: their slots end Dropped(Cancelled) and
// the GroupTicket completes once the rest of the group resolves.
TEST_F(WriteTest, CancelCommittedGroupOps)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::ResolveOk, 0);
    auto c = client("c", {heldBack("b", 1000)});
    auto writer = c->writer("b");
    auto group = writer->group();
    ASSERT_EQ(group.add(tagged(0, "tag-t")), ic::Cause::None);
    ASSERT_EQ(group.add(tagged(1, "tag-u")), ic::Cause::None);
    ASSERT_EQ(group.add(tagged(2, "tag-t")), ic::Cause::None);
    const auto groupTicket = group.commit();
    EXPECT_FALSE(eventually([&] { return sink->dispatched() > 0; }, 100ms));

    const auto ticket = writer->cancel("tag-t");
    ASSERT_TRUE(ticket.ready());
    ASSERT_TRUE(ticket.wait(in(1s)).ok());
    EXPECT_FALSE(groupTicket.ready()) << "the group's op of another tag is still queued";
    sink->grant(TestSink::UNLIMITED);
    const auto outcome = groupTicket.wait(in(5s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
    ASSERT_EQ(outcome.value.size(), 3u);
    EXPECT_EQ(outcome.value[0].status, ic::Status::Dropped);
    EXPECT_EQ(outcome.value[0].cause, ic::Cause::Cancelled);
    EXPECT_EQ(outcome.value[1].status, ic::Status::Ok);
    EXPECT_EQ(outcome.value[2].status, ic::Status::Dropped);
    EXPECT_EQ(outcome.value[2].cause, ic::Cause::Cancelled);
    const auto s = stats("b");
    EXPECT_EQ(s.cancelled, 2u);
    expectInvariants(s);
}

// I76: a group still Building is out of cancel()'s reach: its ops stay reserved (groupBuilding) and go out Ok once
// committed, while a plain pending op of the same tag is cancelled; the ticket is ready at once.
TEST_F(WriteTest, CancelIgnoresBuildingGroup)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::ResolveOk);
    auto c = client("c", {heldBack("b", 1000)});
    auto writer = c->writer("b");
    auto results = Results::create();
    auto group = writer->group();
    ASSERT_EQ(group.add(tagged(0, "tag-t")), ic::Cause::None);
    ASSERT_EQ(group.add(tagged(1, "tag-t")), ic::Cause::None);
    ASSERT_TRUE(writer->submit(tagged(2, "tag-t"), results->callback(2)).accepted);
    ASSERT_EQ(stats("b").groupBuilding, 2u);

    const auto ticket = writer->cancel("tag-t");
    EXPECT_TRUE(ticket.ready());
    ASSERT_TRUE(ticket.wait(in(1s)).ok());
    ASSERT_TRUE(results->waitTotal(1, 3s));
    EXPECT_EQ(results->result(2)->cause, ic::Cause::Cancelled);
    auto s = stats("b");
    EXPECT_EQ(s.groupBuilding, 2u) << "cancel() touched a Building group";
    EXPECT_EQ(s.cancelled, 1u);

    const auto outcome = group.commit().wait(in(5s));
    ASSERT_TRUE(outcome.ok());
    ASSERT_EQ(outcome.value.size(), 2u);
    EXPECT_EQ(outcome.value[0].status, ic::Status::Ok);
    EXPECT_EQ(outcome.value[1].status, ic::Status::Ok);
    s = stats("b");
    EXPECT_EQ(s.cancelled, 1u);
    expectInvariants(s);
}

// I80: the ticket waits only for the delivered ops of the tag. A tag with nothing queued, or with pending ops only, is
// ready at once; with one op delivered (held by the sink) it is ready only after that op resolves, which keeps its
// own result (Ok, I78).
TEST_F(WriteTest, CancelTicketWaitsInFlightOnly)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 1);
    auto c = client("c", {heldBack("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    const auto none = writer->cancel("tag-none");
    EXPECT_TRUE(none.ready());
    EXPECT_TRUE(none.wait(in(1s)).ok());

    ASSERT_TRUE(writer->submit(tagged(0, "tag-t"), results->callback(0)).accepted);
    ASSERT_TRUE(sink->waitDispatched(1, 3s));
    ASSERT_TRUE(writer->submit(tagged(1, "tag-t"), results->callback(1)).accepted);
    ASSERT_TRUE(writer->submit(tagged(2, "tag-t"), results->callback(2)).accepted);
    ASSERT_TRUE(writer->submit(tagged(3, "tag-u"), results->callback(3)).accepted);

    const auto pendingOnly = writer->cancel("tag-u");
    EXPECT_TRUE(pendingOnly.ready()) << "only pending ops of the tag";
    EXPECT_TRUE(pendingOnly.wait(in(1s)).ok());
    const auto ticket = writer->cancel("tag-t");
    ASSERT_TRUE(results->waitTotal(3, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Cancelled), 3u);
    EXPECT_FALSE(eventually([&] { return ticket.ready(); }, 200ms)) << "ready with the delivered op unresolved";

    EXPECT_EQ(sink->resolveHeld(), 1u);
    ASSERT_TRUE(ticket.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(4, 3s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    EXPECT_EQ(sink->dispatched(), 1u);
    const auto s = stats("b");
    EXPECT_EQ(s.cancelled, 3u);
    expectInvariants(s);
}

// RF-27, I80: a callback (a runtime thread) calls cancel(), which never blocks, and waits on its ticket: Reentrancy at
// once. From the consumer thread the same ticket is a success and the pending op of the tag is Dropped(Cancelled).
TEST_F(BulkTest, CancelFromCallbackReentrancy)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1), bucketSpec("p", 4u << 20)});
    auto pending = c->writer("p");
    auto results = Results::create();
    ASSERT_TRUE(pending->submit(tagged(1, "tag-t"), results->callback(1)).accepted);

    struct Made
    {
        ic::CancelTicket ticket;
        ic::Cause waited {ic::Cause::None};
        std::chrono::nanoseconds took {};
    };
    auto made = std::make_shared<std::promise<Made>>();
    auto madeFuture = made->get_future();
    const auto submit = c->writer("t")->submit(tagged(0, "tag-x"),
                                               [made, pending](const ic::OpResult&)
                                               {
                                                   Made out;
                                                   const auto t0 = now();
                                                   out.ticket = pending->cancel("tag-t");
                                                   out.waited = out.ticket.wait(in(2s)).cause;
                                                   out.took = now() - t0;
                                                   made->set_value(std::move(out));
                                               });
    ASSERT_TRUE(submit.accepted);
    ASSERT_EQ(madeFuture.wait_for(10s), std::future_status::ready) << "the callback never finished";
    const auto out = madeFuture.get();
    EXPECT_EQ(out.waited, ic::Cause::Reentrancy) << ic::toString(out.waited);
    EXPECT_LT(out.took, 100ms) << "the runtime thread slept";
    ASSERT_TRUE(out.ticket.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(1, 3s));
    EXPECT_EQ(results->result(1)->cause, ic::Cause::Cancelled);
    ASSERT_TRUE(submit.ticket.wait(in(5s)).ok());
    expectInvariants(stats("p"));
}

// I80, D42: Op::tag over 256 bytes or with a control byte is InvalidArgument (field `tag`) in submit and Group::add;
// 256 bytes is accepted. cancel() refuses the same tags and the empty one (it would match every untagged op), with a
// ready ticket; a valid tag with nothing queued is a success.
TEST_F(WriteTest, TagValidation)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::ResolveOk);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto writer = c->writer("b");
    const std::string atCap(wr::MAX_TAG_SIZE, 'a');
    const std::string tooLong(wr::MAX_TAG_SIZE + 1, 'a');
    const std::vector<std::string> invalid {tooLong, std::string("a\nb"), std::string("a\x7f"), std::string(1, '\x01')};

    for (const auto& tag : invalid)
    {
        SCOPED_TRACE(tag.size());
        const auto submit = writer->submit(tagged(0, tag));
        EXPECT_FALSE(submit.accepted);
        EXPECT_EQ(submit.cause, ic::Cause::InvalidArgument);
        EXPECT_EQ(submit.reason.rfind("tag", 0), 0u) << submit.reason;
        auto group = writer->group();
        EXPECT_EQ(group.add(tagged(1, tag)), ic::Cause::InvalidArgument);
        EXPECT_EQ(group.lastAddReason().rfind("tag", 0), 0u) << group.lastAddReason();
        const auto ticket = writer->cancel(tag);
        EXPECT_TRUE(ticket.ready());
        const auto outcome = ticket.wait(in(1s));
        EXPECT_EQ(outcome.cause, ic::Cause::InvalidArgument);
        EXPECT_EQ(outcome.reason.rfind("tag", 0), 0u) << outcome.reason;
    }
    const auto empty = writer->cancel("");
    EXPECT_TRUE(empty.ready());
    const auto emptyOutcome = empty.wait(in(1s));
    EXPECT_EQ(emptyOutcome.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(emptyOutcome.reason.rfind("tag", 0), 0u) << emptyOutcome.reason;

    const auto accepted = writer->submit(tagged(2, atCap));
    ASSERT_TRUE(accepted.accepted) << accepted.reason;
    EXPECT_EQ(accepted.ticket.wait(in(5s)).value.status, ic::Status::Ok);
    EXPECT_TRUE(writer->cancel(atCap).wait(in(1s)).ok());
    const auto s = stats("b");
    EXPECT_EQ(s.invalidArgument, 2 * invalid.size());
    expectInvariants(s);
}

// I80 accounting: two cancel() of one tag with two ops delivered register two waiters; neither completes while one op
// is unresolved, and both complete with the last one.
TEST_F(WriteTest, CancelTwiceSameTag)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 2);
    auto c = client("c", {heldBack("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(tagged(0, "tag-t"), results->callback(0)).accepted);
    ASSERT_TRUE(writer->submit(tagged(1, "tag-t"), results->callback(1)).accepted);
    ASSERT_TRUE(sink->waitDispatched(2, 3s));
    auto batches = sink->take();
    ASSERT_EQ(batches.size(), 2u);

    const auto first = writer->cancel("tag-t");
    const auto second = writer->cancel("tag-t");
    EXPECT_FALSE(first.ready());
    EXPECT_FALSE(second.ready());
    ASSERT_TRUE(m_path->resolve(bucketOf(*batches[0].ops.at(0)), batches[0].ops.at(0), TestSink::ok()));
    EXPECT_FALSE(eventually([&] { return first.ready() || second.ready(); }, 200ms))
        << "a waiter completed with one delivered op unresolved";
    ASSERT_TRUE(m_path->resolve(bucketOf(*batches[1].ops.at(0)), batches[1].ops.at(0), TestSink::ok()));
    ASSERT_TRUE(first.wait(in(5s)).ok());
    ASSERT_TRUE(second.wait(in(5s)).ok());
    ASSERT_TRUE(results->waitTotal(2, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    expectInvariants(stats("b"));
}

// I80 accounting: an op of the tag enqueued (and delivered) after the cancel() is not the ticket's: the ticket
// completes with the op that was delivered at the cancel while the later one is still held, which ends Ok on its own.
TEST_F(WriteTest, CancelAfterTagReenqueued)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 1);
    auto c = client("c", {heldBack("b", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(tagged(0, "tag-t"), results->callback(0)).accepted);
    ASSERT_TRUE(sink->waitDispatched(1, 3s));
    auto before = sink->take();
    ASSERT_EQ(before.size(), 1u);

    const auto ticket = writer->cancel("tag-t");
    EXPECT_FALSE(ticket.ready());
    ASSERT_TRUE(writer->submit(tagged(1, "tag-t"), results->callback(1)).accepted);
    sink->grant(1);
    ASSERT_TRUE(sink->waitDispatched(2, 3s)) << "the op enqueued after the cancel was not delivered";
    auto after = sink->take();
    ASSERT_EQ(after.size(), 1u);

    ASSERT_TRUE(m_path->resolve(bucketOf(*before[0].ops.at(0)), before[0].ops.at(0), TestSink::ok()));
    ASSERT_TRUE(ticket.wait(in(2s)).ok()) << "the later op of the tag delayed the ticket";
    EXPECT_EQ(results->count(1), 0) << "the later op is still held";
    ASSERT_TRUE(m_path->resolve(bucketOf(*after[0].ops.at(0)), after[0].ops.at(0), TestSink::ok()));
    ASSERT_TRUE(results->waitTotal(2, 3s));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    EXPECT_EQ(stats("b").cancelled, 0u);
    expectInvariants(stats("b"));
}

// Finding 1 of step 3b (WriterImpl::cancel): an ordered bucket's op of key X and tag T waits a 30 s backoff in the
// lane (429 item) and blocks a later op of X with tag U, so the scheduler's timer is armed at the lane head (30 s).
// cancel(T) removes the lane op: the op of U leaves in < 1 s. Mutant: no Scheduler::notify in WriterImpl::cancel.
TEST_F(BulkTest, CancelWakesOrderedBucket)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::all(BulkItem::rejected()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {orderedBucket("b", 1, 30000)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(tagged(1, "tag-t"), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().retries >= 1 && inFlightTotal() == 0; }, 3s))
        << "the 429 item never sent the op to the lane";
    ASSERT_TRUE(writer->submit(tagged(1, "tag-u", 32), results->callback(1)).accepted);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 500ms))
        << "precondition: the op of U leaves while its key waits in the lane";

    const auto t0 = Clock::now();
    const auto ticket = writer->cancel("tag-t");
    EXPECT_TRUE(ticket.ready()) << "the lane op is removed, nothing delivered";
    ASSERT_TRUE(results->waitTotal(2, 1s)) << "the op of U did not leave after the cancel";
    EXPECT_LT(Clock::now() - t0, 1s);
    EXPECT_EQ(results->result(0)->cause, ic::Cause::Cancelled);
    EXPECT_EQ(results->result(1)->status, ic::Status::Ok);
    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 2u);
    ASSERT_EQ(received[1].size(), 1u);
    EXPECT_EQ(received[1][0].source, body(32));
    expectInvariants(stats("b"));
}
