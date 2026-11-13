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

// Close and shutdown of the write path, and the production sink (the bulk sender).

#include <future>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"
#include "testTimeScale.hpp"
#include "write/sender.hpp"

using namespace write_component;
using component::AsyncCall;
using component::eventually;

namespace
{
    std::string id(std::size_t n)
    {
        auto digits = std::to_string(n);
        return "c" + std::string(7 - digits.size(), '0') + digits;
    }

    /// One call of a race round.
    struct RaceCall final
    {
        std::uint64_t key {0};
        bool post {false};
        bool afterClose {false}; ///< Started after requestClose() / shutdown() had returned.
        bool accepted {false};
        ic::Cause cause {ic::Cause::None};
    };

    /// The producer of a race round: submit() with a callback (even keys) and post() (odd keys) alternately, until it
    /// has made one call that started after `closed` was set (set right after requestClose() / shutdown() returned).
    /// `made` counts the calls finished. No seam: where the close lands in the admission is the scheduler's choice.
    void raceProducer(const std::shared_ptr<ic::IWriter>& writer,
                      const std::shared_ptr<Results>& results,
                      const std::atomic<bool>& closed,
                      std::atomic<std::size_t>& made,
                      std::vector<RaceCall>& calls)
    {
        constexpr std::uint64_t MAX_BEFORE_CLOSE = 64;
        for (std::uint64_t key = 0;; ++key)
        {
            if (key == MAX_BEFORE_CLOSE)
            {
                while (!closed.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
            }
            RaceCall call;
            call.key = key;
            call.post = key % 2 == 1;
            call.afterClose = closed.load(std::memory_order_acquire);
            if (call.post)
            {
                const auto posted = writer->post(indexOp(id(key)));
                call.accepted = posted.accepted;
                call.cause = posted.cause;
            }
            else
            {
                const auto submitted = writer->submit(indexOp(id(key)), results->callback(key));
                call.accepted = submitted.accepted;
                call.cause = submitted.cause;
            }
            calls.push_back(call);
            made.fetch_add(1, std::memory_order_release);
            if (call.afterClose)
            {
                return;
            }
        }
    }
} // namespace

// No seam: submit() and post() from one thread racing requestClose() (200 rounds) or shutdown() (20
// rounds) from another, the close landing after 0-3 calls. Oracle, every round: an accepted call has exactly one
// result, Ok or Dropped(ClientClosed|Shutdown) (submit: its callback; post: the bucket's counters); a refused one has
// the close cause and no callback; every call started after requestClose() returned is ClientClosed (after shutdown():
// Shutdown); retained 0, Σ charge 0 and drained + droppedClientClosed + droppedShutdown == accepted. Between the two,
// many producers racing a close: every accepted op resolves once. Mutant m4: admit enqueues after closeAdmission.
TEST_F(WriteTest, SubmitRacesClose)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto spec = bucketSpec("b", 8u << 20, ic::Overflow::Kind::Reject, 0, 1); // 1600 racing ops fit.

    /// Checks one round once everything it accepted is resolved; `closeCause` is the cause of a late call.
    const auto checkRound = [this](const std::string& consumer,
                                   const std::vector<RaceCall>& calls,
                                   const Results& results,
                                   const ic::CloseReport& report,
                                   ic::Cause closeCause)
    {
        std::size_t accepted = 0;
        for (const auto& call : calls)
        {
            SCOPED_TRACE((call.post ? "post " : "submit ") + std::to_string(call.key));
            if (call.afterClose)
            {
                EXPECT_FALSE(call.accepted) << "started after the close returned";
                EXPECT_EQ(call.cause, closeCause) << ic::toString(call.cause);
            }
            if (call.accepted)
            {
                ++accepted;
            }
            else
            {
                EXPECT_TRUE(call.cause == closeCause || call.cause == ic::Cause::ClientClosed)
                    << ic::toString(call.cause);
            }
            if (!call.post)
            {
                EXPECT_EQ(results.count(call.key), call.accepted ? 1 : 0);
                const auto result = results.result(call.key);
                if (call.accepted && result)
                {
                    const bool closedDrop =
                        result->status == ic::Status::Dropped &&
                        (result->cause == ic::Cause::ClientClosed || result->cause == ic::Cause::Shutdown);
                    EXPECT_TRUE(result->status == ic::Status::Ok || closedDrop)
                        << "status " << static_cast<int>(result->status) << " " << ic::toString(result->cause);
                }
            }
        }
        const auto s = stats("b", consumer);
        EXPECT_EQ(s.accepted, accepted) << describe(s);
        EXPECT_EQ(s.resolvedOk + s.resolvedDropped, accepted) << describe(s);
        EXPECT_EQ(s.resolvedFailed, 0u) << describe(s);
        EXPECT_EQ(s.retained, 0u) << describe(s);
        expectInvariants(s);
        EXPECT_EQ(report.drained + report.droppedClientClosed + report.droppedShutdown, accepted)
            << "drained " << report.drained << " droppedClientClosed " << report.droppedClientClosed
            << " droppedShutdown " << report.droppedShutdown;
        EXPECT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s)) << describe(m_path->stats());
    };

    // requestClose() racing the producer, 200 rounds. The held sink resolves nothing before the close, so every
    // accepted op is resolved after it: by the test (Ok, drained) or swept.
    constexpr std::size_t CLOSE_ROUNDS = 200;
    for (std::size_t round = 0; round < CLOSE_ROUNDS && !HasFailure(); ++round)
    {
        SCOPED_TRACE("requestClose round " + std::to_string(round));
        const auto consumer = "closing" + std::to_string(round);
        auto c = client(consumer, {spec});
        auto writer = c->writer("b");
        ASSERT_NE(writer, nullptr);
        auto results = Results::create();
        std::atomic<bool> closed {false};
        std::atomic<std::size_t> made {0};
        std::vector<RaceCall> calls;
        calls.reserve(128);
        std::thread producer([&] { raceProducer(writer, results, closed, made, calls); });
        const std::size_t lead = round % 4;
        while (made.load(std::memory_order_acquire) < lead)
        {
            std::this_thread::yield();
        }
        c->requestClose();
        closed.store(true, std::memory_order_release);
        producer.join();
        // The bucket keeps draining into the held sink; resolve Ok until nothing of the round is retained.
        EXPECT_TRUE(eventually(
            [&]
            {
                sink->resolveHeld();
                return stats("b", consumer).retained == 0;
            },
            5s))
            << describe(stats("b", consumer));
        const auto report = c->awaitClosed(now() + 1s);
        ASSERT_TRUE(report.ok());
        std::size_t acceptedSubmits = 0;
        for (const auto& call : calls)
        {
            acceptedSubmits += (!call.post && call.accepted) ? 1 : 0;
        }
        EXPECT_TRUE(results->waitTotal(acceptedSubmits, 5s));
        checkRound(consumer, calls, *results, report.value, ic::Cause::ClientClosed);
        EXPECT_EQ(results->total(), acceptedSubmits);
    }

    // Many producers racing requestClose().
    {
        constexpr std::size_t PRODUCERS = 8;
        constexpr std::size_t PER_PRODUCER = 200;
        auto c = client("racing", {spec});
        auto results = Results::create();
        std::vector<std::vector<int>> accepted(PRODUCERS, std::vector<int>(PER_PRODUCER, -1));
        // The handles are taken before any producer starts: a closing client hands out none, and under a
        // sanitizer on a loaded host a producer thread may only start after requestClose() below.
        std::vector<std::shared_ptr<ic::IWriter>> writers;
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            writers.push_back(c->writer("b"));
            ASSERT_NE(writers.back(), nullptr);
        }
        std::vector<std::thread> producers;
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            producers.emplace_back(
                [&, p]
                {
                    const auto& writer = writers[p];
                    for (std::size_t i = 0; i < PER_PRODUCER; ++i)
                    {
                        const auto key = p * PER_PRODUCER + i;
                        const auto submit = writer->submit(indexOp(id(key)), results->callback(key));
                        accepted[p][i] = submit.accepted ? 1 : static_cast<int>(submit.cause) + 100;
                    }
                });
        }
        // EXPECT, not ASSERT: the producers must be joined whatever happens.
        EXPECT_TRUE(eventually([&] { return stats("b", "racing").submitted >= PRODUCERS * PER_PRODUCER / 4; },
                               indexer_client::testing::scaled(5000ms)));
        c->requestClose();
        for (auto& producer : producers)
        {
            producer.join();
        }
        // The held sink never answers, so nothing drains; at drainEnd the queued ops are Dropped(ClientClosed)
        // and those delivered to the sink Dropped(Shutdown).
        const auto report = c->awaitClosed(now() + 1s);
        ASSERT_TRUE(report.ok());
        std::size_t acceptedCount = 0;
        for (const auto& row : accepted)
        {
            for (const int a : row)
            {
                acceptedCount += a == 1 ? 1 : 0;
                if (a != 1)
                {
                    EXPECT_EQ(a, static_cast<int>(ic::Cause::ClientClosed) + 100);
                }
            }
        }
        // Whether the close lands before the last submit is timing: only the exactly-once and the
        // no-callback-when-refused properties are asserted; the seam blocks above pin the race deterministically.
        EXPECT_GT(acceptedCount, 0u);
        ASSERT_TRUE(results->waitTotal(acceptedCount, 5s));
        std::size_t delivered = 0;
        for (const auto& batch : sink->take()) // What the sink held was resolved by awaitClosed.
        {
            delivered += batch.ops.size();
        }
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            for (std::size_t i = 0; i < PER_PRODUCER; ++i)
            {
                EXPECT_EQ(results->count(p * PER_PRODUCER + i), accepted[p][i] == 1 ? 1 : 0)
                    << "producer " << p << " op " << i;
            }
        }
        EXPECT_EQ(results->total(), acceptedCount);
        EXPECT_EQ(report.value.droppedShutdown, delivered) << "every op delivered to the held sink";
        EXPECT_EQ(report.value.droppedClientClosed, acceptedCount - delivered) << "every op still queued";
        EXPECT_EQ(report.value.drained, 0u) << "no sink resolution: every op was dropped by the sweep";
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed) +
                      results->countWith(ic::Status::Dropped, ic::Cause::Shutdown),
                  acceptedCount);
        ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
        expectInvariants(stats("b", "racing"));
    }

    // shutdown() racing the producer, 20 rounds, each on a runtime of its own (the first on the one above).
    constexpr std::size_t SHUTDOWN_ROUNDS = 20;
    for (std::size_t round = 0; round < SHUTDOWN_ROUNDS && !HasFailure(); ++round)
    {
        SCOPED_TRACE("shutdown round " + std::to_string(round));
        if (round > 0)
        {
            ASSERT_NO_FATAL_FAILURE(start());
            sink = installSink();
        }
        const auto consumer = "shutting" + std::to_string(round);
        auto c = client(consumer, {spec});
        auto writer = c->writer("b");
        ASSERT_NE(writer, nullptr);
        auto results = Results::create();
        std::atomic<bool> closed {false};
        std::atomic<std::size_t> made {0};
        std::vector<RaceCall> calls;
        calls.reserve(128);
        std::thread producer([&] { raceProducer(writer, results, closed, made, calls); });
        const std::size_t lead = round % 4;
        while (made.load(std::memory_order_acquire) < lead)
        {
            std::this_thread::yield();
        }
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        closed.store(true, std::memory_order_release);
        producer.join();
        std::size_t acceptedSubmits = 0;
        for (const auto& call : calls)
        {
            acceptedSubmits += (!call.post && call.accepted) ? 1 : 0;
        }
        EXPECT_TRUE(results->waitTotal(acceptedSubmits, 5s));
        const auto report = c->awaitClosed(now() + 100ms);
        ASSERT_TRUE(report.ok());
        EXPECT_EQ(sink->resolveHeld(), 0u) << "the shutdown resolved every op the sink held";
        checkRound(consumer, calls, *results, report.value, ic::Cause::Shutdown);
        EXPECT_EQ(results->total(), acceptedSubmits);
    }
}

// requestClose() + awaitClosed() resolve the client's retained ops at drainEnd (the held sink drains
// nothing): pending Dropped(ClientClosed), delivered to the sink Dropped(Shutdown), and report a callback still running
// as callbacksInFlight; shutdown() resolves another client's retained ops Dropped(Shutdown). Charge 0, and the sink's
// late resolutions lose.
TEST_F(WriteTest, CloseAndShutdownResolveRetained)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 1);
    const auto spec = bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 10);

    auto c = client("c", {spec});
    {
        auto writer = c->writer("b");
        auto results = Results::create();
        auto gate = std::make_shared<std::promise<void>>();
        auto opened = gate->get_future().share();
        for (std::uint64_t k = 0; k < 10; ++k) // Delivered: one batch of maxDocs.
        {
            auto callback = results->callback(k);
            ASSERT_TRUE(writer
                            ->submit(indexOp(id(k)),
                                     [callback, opened, k](const ic::OpResult& result)
                                     {
                                         callback(result);
                                         if (k == 0)
                                         {
                                             opened.wait(); // The slow callback.
                                         }
                                     })
                            .accepted);
        }
        ASSERT_TRUE(sink->waitDispatched(1));
        for (std::uint64_t k = 10; k < 13; ++k) // Pending: the sink took its only batch.
        {
            ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        }
        EXPECT_EQ(stats("b").retained, 13u);

        c->requestClose();
        EXPECT_EQ(writer->submit(indexOp(id(99))).cause, ic::Cause::ClientClosed);
        EXPECT_EQ(stats("b").retained, 13u) << "requestClose() only closes the admission";
        // A short deadline (300 ms < 2 x callbackBudget): drainEnd = now + 150 ms, cutoff = now + 225 ms.
        const auto t0 = now();
        const auto report = c->awaitClosed(t0 + 300ms);
        const auto took = now() - t0;
        ASSERT_TRUE(report.ok());
        EXPECT_GE(took, 150ms) << "swept before drainEnd";
        EXPECT_EQ(report.value.callbacksInFlight, 1u) << "the slow callback was still running";
        EXPECT_EQ(report.value.droppedClientClosed, 3u) << "pending";
        EXPECT_EQ(report.value.droppedShutdown, 10u) << "delivered to the sink";
        EXPECT_EQ(report.value.drained, 0u);
        EXPECT_EQ(report.value.callbacksSkipped, 0u) << "every completion ran before the cutoff";
        EXPECT_EQ(stats("b").retained, 0u);
        gate->set_value();
        ASSERT_TRUE(results->waitTotal(13));
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 3u);
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 10u);
        for (std::uint64_t k = 0; k < 13; ++k)
        {
            EXPECT_EQ(results->count(k), 1) << k;
        }
        EXPECT_EQ(sink->resolveHeld(), 0u) << "the sink's late resolutions lose";
        ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
        expectInvariants(stats("b"));
    }

    auto s = client("s", {spec});
    {
        auto writer = s->writer("b");
        auto results = Results::create();
        sink->grant(1);
        for (std::uint64_t k = 0; k < 13; ++k)
        {
            ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
        }
        ASSERT_TRUE(sink->waitDispatched(2));
        EXPECT_EQ(stats("b", "s").retained, 13u);
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        ASSERT_TRUE(results->waitTotal(13));
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 13u);
        const auto report = s->awaitClosed(now() + 100ms);
        ASSERT_TRUE(report.ok());
        EXPECT_EQ(report.value.droppedShutdown, 13u);
        EXPECT_EQ(report.value.callbacksInFlight, 0u);
        expectInvariants(stats("b", "s"));
    }
}

// The sink holds a batch; shutdown() resolves each op of it (and the pending ones) Dropped(Shutdown) exactly
// once, in < 2 s; the tickets are complete and the sink was stopped.
TEST_F(WriteTest, ShutdownWithHeldBatch)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 10)});
    auto writer = c->writer("b");
    auto results = Results::create();
    std::vector<ic::Ticket> tickets;
    for (std::uint64_t k = 0; k < 13; ++k)
    {
        auto submit = writer->submit(indexOp(id(k)), k % 2 ? results->callback(k) : ic::Callback {});
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(submit.ticket);
    }
    ASSERT_TRUE(sink->waitDispatched(1));
    const auto t0 = now();
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    EXPECT_LT(now() - t0, 2s);
    EXPECT_TRUE(sink->stopped());
    ASSERT_TRUE(results->waitTotal(6, 2s));
    for (std::uint64_t k = 0; k < 13; ++k)
    {
        SCOPED_TRACE(k);
        ASSERT_TRUE(tickets[k].ready());
        const auto result = tickets[k].wait(now() + 1s);
        EXPECT_EQ(result.value.status, ic::Status::Dropped);
        EXPECT_EQ(result.value.cause, ic::Cause::Shutdown);
        EXPECT_EQ(results->count(k), k % 2 ? 1 : 0);
    }
    EXPECT_EQ(sink->resolveHeld(), 0u) << "every held op was already resolved by the sweep";
    EXPECT_EQ(sink->afterStop(), 0u) << "no batch after sink.stop()";
    EXPECT_EQ(writer->submit(indexOp(id(99))).cause, ic::Cause::Shutdown);
    const auto report = c->awaitClosed(now() + 100ms);
    EXPECT_EQ(report.value.droppedShutdown, 13u);
    tickets.clear();
    expectInvariants(stats("b"));
}

// Without replacing the sink, the production sink is the bulk sender: every op is written (Ok) to the
// configured node and the charge returns to 0.
TEST_F(BulkTest, DefaultSinkIsTheBulkSender)
{
    const auto node = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({node.url()}));
    ASSERT_NE(std::dynamic_pointer_cast<wr::BulkSink>(m_path->sink()), nullptr) << "the runtime's sink";
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 10, ic::Duration {200})});
    auto writer = c->writer("b");
    auto results = Results::create();
    std::vector<ic::Ticket> tickets;
    for (std::uint64_t k = 0; k < 25; ++k) // Two batches by maxDocs, the last five by maxAge.
    {
        auto submit = writer->submit(indexOp(id(k)), k % 2 ? results->callback(k) : ic::Callback {});
        ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause);
        tickets.push_back(submit.ticket);
    }
    for (std::uint64_t k = 0; k < 25; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = tickets[k].wait(now() + 3s);
        ASSERT_TRUE(result.ok()) << ic::toString(result.cause);
        EXPECT_EQ(result.value.status, ic::Status::Ok);
        EXPECT_EQ(result.value.cause, ic::Cause::None);
        EXPECT_EQ(result.value.outcome, ic::ItemOutcome::Created);
    }
    ASSERT_TRUE(results->waitTotal(12));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 12u);
    EXPECT_GT(globalCharge(), 0u) << "the reserves of the ops without callback live in their tickets";
    tickets.clear();
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
    auto s = stats("b");
    EXPECT_EQ(s.accepted, 25u);
    EXPECT_EQ(s.resolvedOk, 25u);
    EXPECT_EQ(s.retained, 0u);
    expectInvariants(s);

    EXPECT_EQ(node.bulk->opCount(), 25u);
    EXPECT_EQ(node.bulk->answered(), 3u) << "10 + 10 by maxDocs, 5 by maxAge";
    // The dispatching loop counts `sent` after transport->submit returns: the bulk may be answered and resolved first.
    ASSERT_TRUE(eventually([] { return wr::senderStats().sent == 3u; }, 5s)) << wr::senderStats().sent;
    const auto sender = wr::senderStats();
    EXPECT_EQ(sender.sent, 3u);
    ASSERT_EQ(sender.nodes.size(), 1u);
    EXPECT_EQ(sender.nodes[0].host, node.url());
    EXPECT_EQ(sender.nodes[0].requests, 3u);
    EXPECT_FALSE(sender.nodes[0].down);
}
