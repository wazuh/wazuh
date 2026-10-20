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

// Close and shutdown of the write path, and the production sink of E3a (plan-E3a §Tests: I63).

#include <future>
#include <string>
#include <thread>
#include <vector>

#include "writeFixture.hpp"

using namespace write_component;
using component::AsyncCall;
using component::eventually;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    std::string id(std::size_t n)
    {
        auto digits = std::to_string(n);
        return "c" + std::string(7 - digits.size(), '0') + digits;
    }

    /// Holds the first submit that reaches the afterAdmission() seam (between reserve and enqueue) until opened.
    struct SeamGate final : std::enable_shared_from_this<SeamGate>
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool held {false};
        bool open {false};
        bool used {false};

        std::function<void()> hook()
        {
            return [self = shared_from_this()]
            {
                std::unique_lock<std::mutex> lock(self->mutex);
                if (self->used)
                {
                    return;
                }
                self->used = true;
                self->held = true;
                self->cv.notify_all();
                self->cv.wait_for(lock, 10s, [&] { return self->open; });
            };
        }

        bool waitHeld(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(mutex);
            return cv.wait_for(lock, timeout, [this] { return held; });
        }

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                open = true;
            }
            cv.notify_all();
        }
    };
} // namespace

// I63: a submit that passed the reservation and has not enqueued yet when requestClose() / shutdown() sweeps its
// bucket is still resolved, exactly once (Dropped with the close cause); refused submits never call back; many
// producers racing a close: every accepted op resolves once. Charge 0 afterwards.
TEST_F(WriteTest, SubmitRacesClose)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const auto spec = bucketSpec("b", 8u << 20, ic::Overflow::Kind::Reject, 0, 1); // 1600 racing ops fit.

    // requestClose() while the submit sits in the seam.
    {
        auto gate = std::make_shared<SeamGate>();
        hooks::setAfterAdmission(gate->hook());
        auto c = client("closing", {spec});
        auto writer = c->writer("b");
        auto results = Results::create();
        auto accepted = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([writer, results, accepted]
                           { *accepted = writer->submit(indexOp(id(0)), results->callback(0)).accepted ? 1 : 0; });
        ASSERT_TRUE(gate->waitHeld(5s));
        c->requestClose();
        gate->release();
        ASSERT_TRUE(producer.wait(5s));
        EXPECT_EQ(*accepted, 1);
        ASSERT_TRUE(results->waitTotal(1, 3s)) << "the op admitted across the close was never resolved";
        EXPECT_EQ(results->count(0), 1);
        EXPECT_EQ(results->result(0)->status, ic::Status::Dropped);
        EXPECT_EQ(results->result(0)->cause, ic::Cause::ClientClosed);
        const auto late = writer->submit(indexOp(id(1)), results->callback(1));
        EXPECT_FALSE(late.accepted);
        EXPECT_EQ(late.cause, ic::Cause::ClientClosed);
        EXPECT_EQ(sink->dispatched(), 0u) << "nothing of a closed bucket reaches the sink";
        ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
        EXPECT_EQ(results->total(), 1u);
        expectInvariants(stats("b", "closing"));
        hooks::setAfterAdmission({});
    }

    // Many producers racing requestClose().
    {
        constexpr std::size_t PRODUCERS = 8;
        constexpr std::size_t PER_PRODUCER = 200;
        auto c = client("racing", {spec});
        auto results = Results::create();
        std::vector<std::vector<int>> accepted(PRODUCERS, std::vector<int>(PER_PRODUCER, -1));
        std::vector<std::thread> producers;
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            producers.emplace_back(
                [&, p]
                {
                    auto writer = c->writer("b");
                    for (std::size_t i = 0; i < PER_PRODUCER; ++i)
                    {
                        const auto key = p * PER_PRODUCER + i;
                        const auto submit = writer->submit(indexOp(id(key)), results->callback(key));
                        accepted[p][i] = submit.accepted ? 1 : static_cast<int>(submit.cause) + 100;
                    }
                });
        }
        // EXPECT, not ASSERT: the producers must be joined whatever happens.
        EXPECT_TRUE(eventually([&] { return stats("b", "racing").submitted >= PRODUCERS * PER_PRODUCER / 4; }, 5s));
        c->requestClose();
        for (auto& producer : producers)
        {
            producer.join();
        }
        const auto report = c->awaitClosed(now() + 5s); // The ops delivered to the sink: Dropped(ClientClosed).
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
        // Whether the close lands before the last submit is timing (G-diff E3a obj. 4): only the exactly-once and the
        // no-callback-when-refused properties are asserted; the seam blocks above pin the race deterministically.
        EXPECT_GT(acceptedCount, 0u);
        ASSERT_TRUE(results->waitTotal(acceptedCount, 5s));
        sink->take(); // What the sink held was resolved by awaitClosed.
        for (std::size_t p = 0; p < PRODUCERS; ++p)
        {
            for (std::size_t i = 0; i < PER_PRODUCER; ++i)
            {
                EXPECT_EQ(results->count(p * PER_PRODUCER + i), accepted[p][i] == 1 ? 1 : 0)
                    << "producer " << p << " op " << i;
            }
        }
        EXPECT_EQ(results->total(), acceptedCount);
        EXPECT_EQ(report.value.droppedClientClosed, acceptedCount) << "no sink resolution: every op was dropped";
        ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
        expectInvariants(stats("b", "racing"));
    }

    // shutdown() while the submit sits in the seam.
    {
        auto gate = std::make_shared<SeamGate>();
        hooks::setAfterAdmission(gate->hook());
        auto c = client("shutting", {spec});
        auto writer = c->writer("b");
        auto results = Results::create();
        auto accepted = std::make_shared<std::atomic<int>>(-1);
        AsyncCall producer([writer, results, accepted]
                           { *accepted = writer->submit(indexOp(id(0)), results->callback(0)).accepted ? 1 : 0; });
        ASSERT_TRUE(gate->waitHeld(5s));
        EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
        gate->release();
        ASSERT_TRUE(producer.wait(5s));
        EXPECT_EQ(*accepted, 1);
        ASSERT_TRUE(results->waitTotal(1, 3s)) << "the op admitted across the shutdown was never resolved";
        EXPECT_EQ(results->count(0), 1);
        EXPECT_EQ(results->result(0)->cause, ic::Cause::Shutdown);
        EXPECT_EQ(writer->submit(indexOp(id(1)), results->callback(1)).cause, ic::Cause::Shutdown);
        EXPECT_EQ(results->total(), 1u);
        expectInvariants(stats("b", "shutting"));
    }
}

// I63: requestClose() + awaitClosed() resolve the client's retained ops (pending and delivered to the sink)
// Dropped(ClientClosed) and report a callback still running as callbacksInFlight; shutdown() resolves another
// client's retained ops Dropped(Shutdown). Charge 0, and the sink's late resolutions lose.
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
        const auto report = c->awaitClosed(now() + 300ms);
        ASSERT_TRUE(report.ok());
        EXPECT_EQ(report.value.callbacksInFlight, 1u) << "the slow callback was still running";
        EXPECT_EQ(report.value.droppedClientClosed, 13u);
        EXPECT_EQ(report.value.droppedShutdown, 0u);
        EXPECT_EQ(stats("b").retained, 0u);
        gate->set_value();
        ASSERT_TRUE(results->waitTotal(13));
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 13u);
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

// I63: the sink holds a batch; shutdown() resolves each op of it (and the pending ones) Dropped(Shutdown) exactly
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

// I63: without replacing the sink, every op is Failed(Unavailable) (the E1 stub's answer) and the charge returns to 0.
TEST_F(WriteTest, DefaultSinkUnavailable)
{
    ASSERT_NO_FATAL_FAILURE(start());
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
        EXPECT_EQ(result.value.status, ic::Status::Failed);
        EXPECT_EQ(result.value.cause, ic::Cause::Unavailable);
    }
    ASSERT_TRUE(results->waitTotal(12));
    EXPECT_EQ(results->countWith(ic::Status::Failed, ic::Cause::Unavailable), 12u);
    EXPECT_GT(globalCharge(), 0u) << "the reserves of the ops without callback live in their tickets";
    tickets.clear();
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, 5s));
    auto s = stats("b");
    EXPECT_EQ(s.accepted, 25u);
    EXPECT_EQ(s.resolvedFailed, 25u);
    EXPECT_EQ(s.retained, 0u);
    expectInvariants(s);
}
