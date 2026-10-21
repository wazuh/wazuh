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

// Re-entrancy from a real completion (plan-E3c-1 §Tests: T13, T18, CA-27; RF-27, I37): a callback run by the pool for
// an op the production sender wrote to a fake node calls back into the library. Every blocking call there is
// Reentrancy at once; requestClose() never waits for the drain; destroying a Client is a counted usage error, with
// no self-join and no deadlock while M callbacks do it at the same time. Every wait is bounded; every case ends with
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
#include <vector>

#include "bulkFixture.hpp"

using namespace write_component;
using component::eventually;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;

    std::string key(std::uint64_t n)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(n));
        return buffer;
    }

    ic::Op op(std::uint64_t n)
    {
        return indexOp(key(n), 1000);
    }

    ic::Deadline in(std::chrono::milliseconds timeout)
    {
        return now() + timeout;
    }

    /// One call made from the callback: its cause and how long it took.
    struct Call final
    {
        ic::Cause cause {ic::Cause::None};
        std::chrono::nanoseconds took {};
    };

    template<class F>
    Call timed(F&& call)
    {
        const auto t0 = now();
        const ic::Cause cause = call();
        return Call {cause, now() - t0};
    }

    /// A rendezvous of `parties` callbacks, bounded: true when every party arrived within `timeout`.
    class Rendezvous final
    {
    public:
        explicit Rendezvous(int parties)
            : m_parties(parties)
        {
        }

        bool arriveAndWait(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            ++m_arrived;
            m_cv.notify_all();
            return m_cv.wait_for(lock, timeout, [&] { return m_arrived >= m_parties; });
        }

    private:
        const int m_parties;
        int m_arrived {0};
        std::mutex m_mutex;
        std::condition_variable m_cv;
    };
} // namespace

// T13, CA-27: from the callback of an op the sender wrote, with the "full" bucket's quota held by a Building group:
// submit with Block, Ticket::wait of a ticket made outside, GroupTicket::wait and Group::add with Block are all
// Reentrancy at once (none sleeps on a quota or a result the runtime thread may be the one to produce). Mutant: the
// onRuntimeThread check removed from reserveForGroup.
TEST_F(BulkTest, CallbackBlockingCallsAreReentrancy)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto trigger = bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1);
    auto full = bucketSpec("full", 2 * charge, ic::Overflow::Kind::Block);
    full.overflow.blockTimeout = ic::Duration {2000};
    auto pending = bucketSpec("pending", 4u << 20); // maxDocs and maxAge large: its op stays queued.
    auto c = client("c", {trigger, full, pending});
    auto fullWriter = c->writer("full");

    auto holder = fullWriter->group(); // Holds the whole "full" quota while Building.
    ASSERT_EQ(holder.add(op(1)), ic::Cause::None);
    ASSERT_EQ(holder.add(op(2)), ic::Cause::None);
    auto second = std::make_shared<ic::Group>(fullWriter->group());
    const auto outside = c->writer("pending")->submit(op(3));
    ASSERT_TRUE(outside.accepted);
    auto committed = c->writer("t")->group();
    ASSERT_EQ(committed.add(op(4)), ic::Cause::None);
    const auto groupTicket = committed.commit();

    auto calls = std::make_shared<std::promise<std::vector<Call>>>();
    auto callsFuture = calls->get_future();
    const auto ticket = outside.ticket;
    const auto submit =
        c->writer("t")->submit(op(5),
                               [calls, fullWriter, ticket, groupTicket, second](const ic::OpResult&)
                               {
                                   std::vector<Call> made;
                                   made.push_back(timed([&] { return fullWriter->submit(op(6)).cause; }));
                                   made.push_back(timed([&] { return ticket.wait(in(2s)).cause; }));
                                   made.push_back(timed([&] { return groupTicket.wait(in(2s)).cause; }));
                                   made.push_back(timed([&] { return second->add(op(7)); }));
                                   calls->set_value(std::move(made));
                               });
    ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause);
    ASSERT_EQ(callsFuture.wait_for(10s), std::future_status::ready) << "the callback never finished";
    const auto made = callsFuture.get();
    const char* names[] = {"submit Block", "Ticket::wait", "GroupTicket::wait", "Group::add Block"};
    ASSERT_EQ(made.size(), 4u);
    for (std::size_t i = 0; i < made.size(); ++i)
    {
        SCOPED_TRACE(names[i]);
        EXPECT_EQ(made[i].cause, ic::Cause::Reentrancy) << ic::toString(made[i].cause);
        EXPECT_LT(made[i].took, 100ms) << "the runtime thread slept";
    }
    const auto s = stats("full");
    EXPECT_EQ(s.reentrancy, 2u);
    EXPECT_EQ(s.submitTimeout, 0u);
    EXPECT_EQ(s.rejectedQueueFull, 0u);
    expectInvariants(s);
    // From this (consumer) thread the same tickets complete normally.
    ASSERT_TRUE(groupTicket.wait(in(5s)).ok());
    ASSERT_TRUE(submit.ticket.wait(in(5s)).ok());
    c->requestClose(); // Drops the pending op; the Building groups are abandoned below.
    EXPECT_EQ(ticket.wait(in(5s)).value.cause, ic::Cause::ClientClosed);
}

// T18, I37: K = 1, M = 2, at most 8 ops pending. requestClose() from a callback of the same client returns in < 1 s
// (it never waits for the drain the callback is part of) and its pending ops are dropped; two clients destroyed from
// two callbacks running at the same time (one per pool thread) are two usage errors, each destructor returns at once
// (no self-join, no deadlock).
TEST_F(BulkTest, CallbackRequestCloseAndClientDestroy)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()})); // K = 1, M = 2.
    auto trigger = bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1);
    auto pending = bucketSpec("p", 4u << 20);

    // requestClose() from a callback.
    auto closing = client("closing", {trigger, pending});
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 7; ++k)
    {
        ASSERT_TRUE(closing->writer("p")->submit(op(k), results->callback(k)).accepted);
    }
    auto closeTook = std::make_shared<std::promise<std::chrono::nanoseconds>>();
    auto closeFuture = closeTook->get_future();
    ic::Client* self = closing.get(); // The test keeps the client alive until the callback has run.
    ASSERT_TRUE(closing->writer("t")
                    ->submit(op(7),
                             [closeTook, self](const ic::OpResult&)
                             {
                                 const auto t0 = now();
                                 self->requestClose();
                                 closeTook->set_value(now() - t0);
                             })
                    .accepted);
    ASSERT_EQ(closeFuture.wait_for(5s), std::future_status::ready) << "requestClose() from a callback hung";
    EXPECT_LT(closeFuture.get(), 1s);
    ASSERT_TRUE(results->waitTotal(7));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 7u);
    const auto report = closing->awaitClosed(in(5s));
    EXPECT_TRUE(report.ok()) << ic::toString(report.cause);

    // Two Clients destroyed from two callbacks at once.
    constexpr int PARTIES = 2;
    const auto errorsBefore = ic::detail::testing::usageErrors();
    auto rendezvous = std::make_shared<Rendezvous>(PARTIES);
    struct Destroyed final
    {
        bool together {false};
        std::chrono::nanoseconds took {};
    };
    std::vector<std::shared_ptr<std::promise<Destroyed>>> done;
    std::vector<std::future<Destroyed>> futures;
    for (int i = 0; i < PARTIES; ++i)
    {
        auto owned = std::make_shared<std::shared_ptr<ic::Client>>(
            client("destroyed-" + std::to_string(i), {bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1)}));
        auto writer = (*owned)->writer("t");
        done.push_back(std::make_shared<std::promise<Destroyed>>());
        futures.push_back(done.back()->get_future());
        ASSERT_TRUE(writer
                        ->submit(op(100 + i),
                                 [owned, rendezvous, promise = done.back()](const ic::OpResult&)
                                 {
                                     Destroyed destroyed;
                                     destroyed.together = rendezvous->arriveAndWait(2s);
                                     const auto t0 = now();
                                     owned->reset(); // The last handle: ~Client on a pool thread.
                                     destroyed.took = now() - t0;
                                     promise->set_value(destroyed);
                                 })
                        .accepted);
        // `owned` (in the callback) is now the client's only handle.
    }
    for (int i = 0; i < PARTIES; ++i)
    {
        SCOPED_TRACE(i);
        ASSERT_EQ(futures[i].wait_for(10s), std::future_status::ready) << "a callback destroying its client hung";
        const auto destroyed = futures[i].get();
        EXPECT_TRUE(destroyed.together) << "the M = 2 callbacks did not run at the same time";
        EXPECT_LT(destroyed.took, 1s) << "~Client waited on a runtime thread";
    }
    EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + PARTIES);
}
