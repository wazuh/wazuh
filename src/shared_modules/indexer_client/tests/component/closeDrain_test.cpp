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

// Client close and runtime shutdown with one deadline (plan-E5b §Tests, I99; write/writer.hpp «Close» is the
// contract): requestClose() only closes the admission and the buckets keep draining (D43), awaitClosed(D) sweeps at
// drainEnd and returns with no callback starting afterwards, the callback cutoff and its counters, and the shutdown
// sequence of E7/E10 (beginShutdown → requestClose → awaitClosed(shutdownDeadline()) → shutdown()) from the owner
// thread. CloseDrainTest runs the production sink over the real transport against one fake node (bulkFixture.hpp);
// CloseDrainSinkTest drives the test sink (writeFixture.hpp) where only the pool's timing matters. Time bounds of the
// plan are scaled(). Every wait is bounded; every case ends with the charge and the retained ops at 0
// (TearDown).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bulkFixture.hpp"
#include "queryFixture.hpp"
#include "transport/transport.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::AsyncCall;
using component::eventually;
using indexer_client::testing::Rule;
using query_component::scaled;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;

    std::string id(std::uint64_t n)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "d%07llu", static_cast<unsigned long long>(n));
        return buffer;
    }

    ic::Deadline in(std::chrono::milliseconds span)
    {
        return now() + span;
    }

    long long millis(ic::TimePoint::duration d)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
    }

    const char* const THROTTLED_BODY =
        R"({"error":{"root_cause":[{"type":"es_rejected_execution_exception","reason":"rejected"}],)"
        R"("type":"es_rejected_execution_exception","reason":"rejected"},"status":429})";
    const char* const UNAVAILABLE_BODY =
        R"({"error":{"root_cause":[{"type":"cluster_manager_not_discovered_exception","reason":null}],)"
        R"("type":"cluster_manager_not_discovered_exception","reason":null},"status":503})";

    /// A bucket of `index`-only ops: `maxDocs` per batch and no age-based batch for an hour.
    ic::BucketSpec heldBack(std::string name,
                            std::size_t maxDocs,
                            std::size_t quota = 8u << 20,
                            ic::Overflow::Kind overflow = ic::Overflow::Kind::Reject)
    {
        return bucketSpec(std::move(name), quota, overflow, 0, maxDocs, ic::Duration {3600000});
    }

    /// Holds one CPU-pool worker in a task until release(), releaseAt(t) or 30 s (never a frozen suite).
    class PoolBlocker final
    {
    public:
        PoolBlocker()
            : m_state(std::make_shared<State>())
        {
        }

        ~PoolBlocker()
        {
            release();
        }

        PoolBlocker(const PoolBlocker&) = delete;
        PoolBlocker& operator=(const PoolBlocker&) = delete;

        bool post()
        {
            return ic::detail::testing::postToPool(
                [s = m_state]
                {
                    std::unique_lock<std::mutex> lock(s->mutex);
                    s->entered = true;
                    s->cv.notify_all();
                    const auto cap = now() + std::chrono::seconds(30);
                    while (!s->released && now() < cap)
                    {
                        if (s->until)
                        {
                            if (now() >= *s->until)
                            {
                                break;
                            }
                            s->cv.wait_until(lock, std::min(*s->until, cap));
                        }
                        else
                        {
                            s->cv.wait_until(lock, cap);
                        }
                    }
                    s->left = now();
                });
        }

        bool waitEntered(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_state->mutex);
            return m_state->cv.wait_for(lock, timeout, [this] { return m_state->entered; });
        }

        void releaseAt(ic::TimePoint at)
        {
            {
                std::lock_guard<std::mutex> lock(m_state->mutex);
                m_state->until = at;
            }
            m_state->cv.notify_all();
        }

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_state->mutex);
                m_state->released = true;
            }
            m_state->cv.notify_all();
        }

    private:
        struct State final
        {
            std::mutex mutex;
            std::condition_variable cv;
            bool entered {false};
            bool released {false};
            std::optional<ic::TimePoint> until;
            ic::TimePoint left {};
        };
        std::shared_ptr<State> m_state;
    };

    /// A seam hook that parks its first call until release() (or 5 s, never a frozen suite); later calls pass.
    class Park final
    {
    public:
        std::function<void()> hook()
        {
            return [s = m_state]
            {
                std::unique_lock<std::mutex> lock(s->mutex);
                if (s->used)
                {
                    return;
                }
                s->used = true;
                s->entered = true;
                s->cv.notify_all();
                s->cv.wait_for(lock, std::chrono::seconds(5), [&s] { return s->released; });
            };
        }

        bool waitEntered(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_state->mutex);
            return m_state->cv.wait_for(lock, timeout, [this] { return m_state->entered; });
        }

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_state->mutex);
                m_state->released = true;
            }
            m_state->cv.notify_all();
        }

    private:
        struct State final
        {
            std::mutex mutex;
            std::condition_variable cv;
            bool used {false};
            bool entered {false};
            bool released {false};
        };
        std::shared_ptr<State> m_state {std::make_shared<State>()};
    };

    /// When each callback of a set started.
    class StartLog final
    {
    public:
        void add(ic::TimePoint at)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_starts.push_back(at);
        }

        std::vector<ic::TimePoint> starts() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_starts;
        }

        std::size_t size() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_starts.size();
        }

        /// Starts at or after `at`.
        std::size_t notBefore(ic::TimePoint at) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return static_cast<std::size_t>(
                std::count_if(m_starts.begin(), m_starts.end(), [at](const ic::TimePoint t) { return t >= at; }));
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<ic::TimePoint> m_starts;
    };

    /// A callback that logs its start, then runs `inner` (a Results callback) and sleeps `sleep`.
    ic::Callback logged(std::shared_ptr<StartLog> log, ic::Callback inner, std::chrono::milliseconds sleep = {})
    {
        return [log, inner, sleep](const ic::OpResult& result)
        {
            log->add(now());
            if (inner)
            {
                inner(result);
            }
            if (sleep.count() > 0)
            {
                std::this_thread::sleep_for(sleep);
            }
        };
    }

    bool sameReport(const ic::CloseReport& a, const ic::CloseReport& b)
    {
        return a.callbacksInFlight == b.callbacksInFlight && a.droppedClientClosed == b.droppedClientClosed &&
               a.droppedShutdown == b.droppedShutdown && a.callbacksSkipped == b.callbacksSkipped &&
               a.callbackOverruns == b.callbackOverruns && a.drained == b.drained;
    }

    std::string describe(const ic::CloseReport& r)
    {
        return "inFlight " + std::to_string(r.callbacksInFlight) + " droppedClientClosed " +
               std::to_string(r.droppedClientClosed) + " droppedShutdown " + std::to_string(r.droppedShutdown) +
               " skipped " + std::to_string(r.callbacksSkipped) + " overruns " + std::to_string(r.callbackOverruns) +
               " drained " + std::to_string(r.drained);
    }

    std::uint64_t transportCancelled()
    {
        const auto transport = ic::detail::runtimeTransport();
        return transport ? transport->stats().cancelled : 0;
    }

    /// A `_bulk` rewrite: requests whose body mentions `index` are held until FakeIndexer::releaseHeld().
    std::function<void(const httplib::Request&, Rule&)> holdIndex(std::string index)
    {
        return [index = std::move(index)](const httplib::Request& request, Rule& reply)
        {
            if (request.body.find(index) != std::string::npos)
            {
                reply.hold = true;
            }
        };
    }
} // namespace

class CloseDrainTest : public BulkTest
{
};

class CloseDrainSinkTest : public WriteTest
{
};

// D43, CA-17: 205 ops with maxDocs 100 and maxAge 1 h (the last 5 under every threshold; the two full batches held by
// the fake), requestClose() and awaitClosed(now + 10 s): the 205 end Ok in < 2 s, all counted as drained; a submit
// afterwards is ClientClosed. Mutant: requestClose() neither moves flushSeq nor notifies (the 5 wait for maxAge).
TEST_F(CloseDrainTest, RequestCloseDrainsPending)
{
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {heldBack("b", 100)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 205; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(2, scaled(5000ms))) << "the two maxDocs batches never left";
    EXPECT_EQ(stats("b").retained, 205u);

    const auto t0 = now();
    c->requestClose();
    a.fake->releaseHeld();
    const auto report = c->awaitClosed(t0 + 10s);
    const auto took = now() - t0;
    ASSERT_TRUE(report.ok()) << ic::toString(report.cause);
    EXPECT_LT(took, scaled(2000ms)) << "the ops under the thresholds waited for maxAge (" << millis(took) << " ms)";
    ASSERT_TRUE(results->waitTotal(205, scaled(1000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 205u);
    EXPECT_EQ(report.value.drained, 205u) << describe(report.value);
    EXPECT_EQ(report.value.callbacksSkipped, 0u) << "a drained op lost its callback with D 10 s away";
    EXPECT_EQ(report.value.droppedClientClosed, 0u);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    EXPECT_EQ(a.bulk->opCount(), 205u);
    EXPECT_EQ(writer->submit(indexOp(id(999))).cause, ic::Cause::ClientClosed);
    expectInvariants(stats("b"));
}

// I99 obj. 1: with only the admission closed a requeue keeps retrying: the node answers 503 for 1 s after
// requestClose() and then 200; every op ends Ok after at least one retry and nothing is dropped. Mutant:
// closeAdmission() also closes the bucket (m_closed), so the first requeue hands the ops back as closed.
TEST_F(CloseDrainTest, CloseDrainRetriesDuringDrain)
{
    auto until = std::make_shared<std::atomic<ic::TimePoint::rep>>(std::numeric_limits<ic::TimePoint::rep>::min());
    const auto a = startNode(BulkScript::items(),
                             "green",
                             {},
                             [until](const httplib::Request&, Rule& reply)
                             {
                                 if (now().time_since_epoch().count() < until->load())
                                 {
                                     reply.status = 503;
                                     reply.body = UNAVAILABLE_BODY;
                                 }
                             });
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto spec = heldBack("b", 1000);
    spec.retry.maxAttempts.reset();
    spec.retry.maxDuration.reset();
    spec.retry.base = ic::Duration {100};
    spec.retry.cap = ic::Duration {200};
    spec.retry.jitter = 0.0;
    auto c = client("c", {spec});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 20; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    const auto retriesBefore = wr::senderStats().retries;

    const auto t0 = now();
    until->store((t0 + 1s).time_since_epoch().count());
    c->requestClose();
    const auto report = c->awaitClosed(t0 + 10s);
    const auto took = now() - t0;
    ASSERT_TRUE(report.ok()) << ic::toString(report.cause);
    ASSERT_TRUE(results->waitTotal(20, scaled(1000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 20u) << describe(report.value);
    EXPECT_GT(wr::senderStats().retries, retriesBefore) << "no retry during the drain";
    EXPECT_GE(took, 1s) << "nothing could succeed before the 503 window ended";
    EXPECT_EQ(report.value.droppedClientClosed, 0u);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    EXPECT_EQ(report.value.drained, 20u);
    expectInvariants(stats("b"));
}

// I99 obj. 2 (N2), CA-E6d-5: 50 pending ops (maxAge 1 h; node_window_max 1 and another bucket's batch held, so they
// cannot leave) and one submit racing requestClose() from another thread, with no seam: the racing op is either
// refused (ClientClosed, no callback) or accepted and then drained Ok like the 50 — never dropped, and never closing
// the bucket (the old sweep of E3a) — so drained + droppedClientClosed == 51 + accepted(50). A submit or post started
// after requestClose() returned is ClientClosed. The charge and the retained ops end at 0.
TEST_F(CloseDrainTest, SubmitRacesCloseKeepsDrain)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items().held()); // The first request (bucket x) holds the only window slot.
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"node_window_max", "1"}}));
    auto c = client("c", {heldBack("b", 1000), heldBack("x", 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(c->writer("x")->submit(indexOp(id(100)), results->callback(100)).accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(5000ms)));
    for (std::uint64_t k = 0; k < 50; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }

    auto go = std::make_shared<std::atomic<bool>>(false);
    auto racing = std::make_shared<ic::Submit>();
    {
        AsyncCall producer(
            [writer, results, racing, go]
            {
                while (!go->load())
                {
                    std::this_thread::yield();
                }
                *racing = writer->submit(indexOp(id(50)), results->callback(50));
            });
        go->store(true);
        c->requestClose();
        ASSERT_TRUE(producer.wait(5s));
    }
    const std::size_t accepted50 = racing->accepted ? 1 : 0;
    if (!racing->accepted)
    {
        EXPECT_EQ(racing->cause, ic::Cause::ClientClosed);
    }
    const auto late = writer->submit(indexOp(id(51)), results->callback(51));
    EXPECT_FALSE(late.accepted);
    EXPECT_EQ(late.cause, ic::Cause::ClientClosed) << "a submit started after requestClose() returned";
    const auto latePost = writer->post(indexOp(id(52)));
    EXPECT_FALSE(latePost.accepted);
    EXPECT_EQ(latePost.cause, ic::Cause::ClientClosed) << "a post started after requestClose() returned";
    EXPECT_EQ(stats("b").retained, 50 + accepted50) << "the pending ops left the bucket";

    a.fake->releaseHeld();
    const auto report = c->awaitClosed(in(10s));
    ASSERT_TRUE(report.ok());
    ASSERT_TRUE(results->waitTotal(51 + accepted50, scaled(2000ms)));
    for (std::uint64_t k = 0; k < 50; ++k)
    {
        EXPECT_EQ(results->count(k), 1) << k;
        EXPECT_EQ(results->result(k)->status, ic::Status::Ok) << k << " " << ic::toString(results->result(k)->cause);
    }
    EXPECT_EQ(results->result(100)->status, ic::Status::Ok);
    EXPECT_EQ(results->count(50), static_cast<int>(accepted50)) << "refused ⇒ no callback; accepted ⇒ one result";
    if (accepted50 == 1)
    {
        EXPECT_EQ(results->result(50)->status, ic::Status::Ok)
            << "the accepted racing op was not drained: " << ic::toString(results->result(50)->cause);
    }
    EXPECT_EQ(results->count(51), 0);
    EXPECT_EQ(report.value.drained + report.value.droppedClientClosed, 51 + accepted50) << describe(report.value);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    EXPECT_EQ(stats("b").retained, 0u);
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, scaled(5000ms)));
    expectInvariants(stats("b"));
}

// CA-E6d-3 (I122): 205 posted ops (the last 5 under every threshold, the two full batches held by the fake), then
// requestClose() + awaitClosed(): CloseReport::drained counts all 205 although no Ticket or callback ties them to the
// client, and the snapshot leaves none without a result (ok = 205, retained 0). Mutant m3: resolve finds no client
// for a post op (drained 0).
TEST_F(CloseDrainTest, PostDrainedOnClose)
{
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {heldBack("b", 100)});
    auto writer = c->writer("b");
    for (std::uint64_t k = 0; k < 205; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(2, scaled(5000ms))) << "the two maxDocs batches never left";
    EXPECT_EQ(stats("b").retained, 205u);

    c->requestClose();
    a.fake->releaseHeld();
    const auto report = c->awaitClosed(in(10s));
    ASSERT_TRUE(report.ok()) << ic::toString(report.cause);
    EXPECT_EQ(report.value.drained, 205u) << describe(report.value);
    EXPECT_EQ(report.value.droppedClientClosed, 0u);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    EXPECT_EQ(a.bulk->opCount(), 205u);
    const auto metrics = c->metrics();
    ASSERT_EQ(metrics.buckets.size(), 1u);
    EXPECT_EQ(metrics.buckets[0].accepted, 205u);
    EXPECT_EQ(metrics.buckets[0].ok, 205u);
    const auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, 205u);
    EXPECT_EQ(s.retained, 0u);
    expectInvariants(s);
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, scaled(5000ms)));
}

// I99 obj. 3: two Clients destroyed from callbacks (runtime threads) with 20 pending ops each, whose `_bulk` the fake
// would hold: every op is resolved at once (Dropped(ClientClosed), nothing sent), the charge returns to 0 and each
// destruction is a counted usage error. Mutant: ~Client on a runtime thread only closes the admission (the ops would
// drain into the held node and stay unresolved).
TEST_F(CloseDrainTest, RuntimeThreadDestroyResolvesAll)
{
    const auto a = startNode(BulkScript::items(), "green", {}, holdIndex("wazuh-held"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    constexpr int CLIENTS = 2;
    constexpr std::uint64_t PENDING = 20;
    const auto errorsBefore = ic::detail::testing::usageErrors();
    const auto bulkBefore = a.bulk->answered();
    auto results = Results::create();
    std::vector<std::future<void>> destroyed;
    for (int i = 0; i < CLIENTS; ++i)
    {
        auto owned = std::make_shared<std::shared_ptr<ic::Client>>(
            client("destroyed-" + std::to_string(i),
                   {bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1), heldBack("p", 1000)}));
        {
            auto pending = (*owned)->writer("p");
            for (std::uint64_t k = 0; k < PENDING; ++k)
            {
                const auto key = static_cast<std::uint64_t>(i) * 100 + k;
                ASSERT_TRUE(pending->submit(indexOp(id(key), 16, "wazuh-held"), results->callback(key)).accepted);
            }
        }
        auto done = std::make_shared<std::promise<void>>();
        destroyed.push_back(done->get_future());
        auto trigger = (*owned)->writer("t");
        ASSERT_TRUE(trigger
                        ->submit(indexOp(id(1000 + i)),
                                 [owned, done](const ic::OpResult&)
                                 {
                                     owned->reset(); // The last handle: ~Client on a pool thread.
                                     done->set_value();
                                 })
                        .accepted);
    }
    for (auto& future : destroyed)
    {
        ASSERT_EQ(future.wait_for(scaled(5000ms)), std::future_status::ready)
            << "a callback never destroyed its client";
    }
    const bool all = results->waitTotal(CLIENTS * PENDING, scaled(2000ms));
    EXPECT_TRUE(all) << "unresolved after the destruction: " << CLIENTS * PENDING - results->total();
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), CLIENTS * PENDING);
    EXPECT_EQ(a.fake->heldNow(), 0u) << "the pending ops were sent instead of resolved";
    EXPECT_EQ(a.bulk->answered(), bulkBefore + CLIENTS) << "only the two trigger ops";
    EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + CLIENTS);
    a.fake->releaseHeld(); // Only matters to a mutant.
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, scaled(5000ms))) << describe(m_path->stats());
}

// CA-17: callback_budget_ms 2000 and D = now + 6 s (drainEnd = D - 4 s); the node holds its only window slot with 4
// delivered ops and 50 more wait: awaitClosed returns in [drainEnd, drainEnd + 500 ms] with the 50
// Dropped(ClientClosed) and the 4 Dropped(Shutdown), their transfer cancelled; the late answer changes nothing. Mutant:
// the sweep at D.
TEST_F(CloseDrainTest, AwaitClosedSweepsAtDrainEnd)
{
    const auto a = startNode(BulkScript::items().held());
    ASSERT_NO_FATAL_FAILURE(
        startOn({a.url()}, std::chrono::hours(1), {{"node_window_max", "1"}, {"callback_budget_ms", "2000"}}));
    auto c = client("c", {heldBack("b", 4)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(5000ms)));
    for (std::uint64_t k = 4; k < 54; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    EXPECT_EQ(stats("b").retained, 54u);
    const auto cancelledBefore = transportCancelled();

    const auto t0 = now();
    const auto deadline = t0 + 6s;
    const auto drainEnd = deadline - 4s;
    const auto report = c->awaitClosed(deadline);
    const auto returned = now();
    ASSERT_TRUE(report.ok());
    EXPECT_GE(returned, drainEnd) << "swept before drainEnd";
    EXPECT_LT(returned - drainEnd, scaled(500ms)) << "returned " << millis(returned - t0) << " ms after the call";
    EXPECT_EQ(report.value.droppedClientClosed, 50u) << describe(report.value);
    EXPECT_EQ(report.value.droppedShutdown, 4u);
    EXPECT_EQ(report.value.drained, 0u);
    ASSERT_TRUE(results->waitTotal(54, scaled(1000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 50u);
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 4u);
    EXPECT_TRUE(eventually([&] { return transportCancelled() == cancelledBefore + 1; }, scaled(1000ms)))
        << "the held transfer was not cancelled: " << transportCancelled() - cancelledBefore;

    a.fake->releaseHeld(); // The late answer.
    EXPECT_FALSE(eventually([&] { return results->total() > 54; }, scaled(300ms)));
    for (std::uint64_t k = 0; k < 54; ++k)
    {
        EXPECT_EQ(results->count(k), 1) << k;
    }
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 4u) << "the late answer changed a result";
    EXPECT_EQ(a.bulk->answered(), 1u) << "nothing else was sent";
    ASSERT_TRUE(eventually([this] { return globalCharge() == 0; }, scaled(5000ms)));
    expectInvariants(stats("b"));
}

// I99 obj. 6 (CA-24): an op in the lane with notBefore = now + 10 s (a 429 with Retry-After: 10) and
// awaitClosed(now + 2 s): Dropped(ClientClosed) at drainEnd (1.6 s), not at 10 s, and never sent again before its
// backoff.
TEST_F(CloseDrainTest, CloseWithBackoffBeyondDrainEnd)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::throttled("10"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {heldBack("b", 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == 1; }, scaled(5000ms)));
    ASSERT_TRUE(eventually([this] { return stats("b").retained == 1; }, scaled(1000ms)));
    EXPECT_EQ(results->total(), 0u);

    const auto t0 = now();
    const auto report = c->awaitClosed(t0 + 2s);
    const auto took = now() - t0;
    ASSERT_TRUE(report.ok());
    EXPECT_GE(took, 1600ms) << "swept before drainEnd";
    EXPECT_LT(took, 1600ms + scaled(500ms)) << "the sweep waited for the backoff";
    ASSERT_TRUE(results->waitTotal(1, scaled(1000ms)));
    EXPECT_EQ(results->result(0)->status, ic::Status::Dropped);
    EXPECT_EQ(results->result(0)->cause, ic::Cause::ClientClosed);
    EXPECT_EQ(report.value.droppedClientClosed, 1u);
    EXPECT_EQ(a.bulk->answered(), 1u) << "sent again before its backoff";
    expectInvariants(stats("b"));
}

// T12: cpu_threads 1, a 429 storm on one bucket and, on another, a callback of 3 x callbackBudget that is running at
// the cutoff: awaitClosed returns by D with callbacksInFlight = 1; the storm's ops, swept at drainEnd and queued
// behind the slow callback, never start theirs (callbacksSkipped >= 1); every callback of the client started before
// awaitClosed returned. Mutant: no cutoff check (the cutoff decided without completionsMutex needs the seam:
// CutoffGateHoldsAwaitClosed).
TEST_F(CloseDrainTest, StormWithSlowCallbackAtDeadline)
{
    const auto budget = scaled(200ms);
    const auto a = startNode(BulkScript::items(),
                             "green",
                             {},
                             [](const httplib::Request& request, Rule& reply)
                             {
                                 if (request.body.find("wazuh-storm") != std::string::npos)
                                 {
                                     reply.status = 429;
                                     reply.body = THROTTLED_BODY;
                                 }
                                 else if (request.body.find("wazuh-slow") != std::string::npos)
                                 {
                                     reply.hold = true;
                                 }
                             });
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()},
                                    std::chrono::hours(1),
                                    {{"cpu_threads", "1"}, {"callback_budget_ms", std::to_string(budget.count())}}));
    auto c = client("c", {heldBack("slow", 1), heldBack("storm", 10)});
    auto results = Results::create();
    auto log = std::make_shared<StartLog>();
    ASSERT_TRUE(c->writer("slow")
                    ->submit(indexOp(id(0), 16, "wazuh-slow"), logged(log, results->callback(0), 3 * budget))
                    .accepted);
    ASSERT_TRUE(a.fake->waitHeld(1, scaled(5000ms)));
    auto storm = c->writer("storm");
    for (std::uint64_t k = 1; k <= 20; ++k)
    {
        ASSERT_TRUE(storm->submit(indexOp(id(k), 16, "wazuh-storm"), logged(log, results->callback(k))).accepted);
    }
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled >= 1; }, scaled(5000ms))) << "no storm";

    const auto t0 = now();
    const auto deadline = t0 + 5 * budget / 2; // drainEnd = t0 + budget / 2, cutoff = t0 + 1.5 x budget.
    const auto drainEnd = deadline - 2 * budget;
    const auto cutoff = deadline - budget;
    c->requestClose();
    a.fake->releaseHeld(); // The slow op completes: its callback starts now and outlives D.
    const auto report = c->awaitClosed(deadline);
    const auto returned = now();
    ASSERT_TRUE(report.ok());
    EXPECT_LT(returned - deadline, scaled(100ms)) << "returned after D";
    EXPECT_EQ(report.value.callbacksInFlight, 1u) << describe(report.value);
    const auto starts = log->starts();
    ASSERT_GE(starts.size(), 1u);
    EXPECT_LT(starts.front(), drainEnd) << "the slow callback started late: the sweep did not queue behind it";
    EXPECT_LT(starts.front(), cutoff);
    for (const auto& start : starts)
    {
        EXPECT_LT(start, returned) << "a callback started " << millis(start - returned) << " ms after awaitClosed";
    }

    ASSERT_TRUE(eventually([&] { return results->count(0) == 1; }, scaled(5000ms)));
    ASSERT_TRUE(eventually([&] { return stats("storm").retained == 0; }, scaled(1000ms)));
    const auto again = c->awaitClosed(in(scaled(2000ms))); // The counters, once the worker is free (N3).
    ASSERT_TRUE(again.ok());
    EXPECT_GE(again.value.callbacksSkipped, 1u) << describe(again.value);
    EXPECT_EQ(again.value.callbacksSkipped + log->size(), 21u) << "every completion is a start or a skip";
    EXPECT_EQ(log->notBefore(returned), 0u) << "a callback started after the first awaitClosed returned";
    EXPECT_EQ(again.value.callbacksInFlight, 0u);
    EXPECT_EQ(again.value.droppedClientClosed + again.value.droppedShutdown, 20u) << "queued or in flight at drainEnd";
}

// I99 obj. 7: D = now - 1 s with 10 completions queued behind a held worker (cpu_threads 1): awaitClosed returns in
// < 100 ms, and once the worker is free every Ticket is complete and the 10 callbacks were skipped.
TEST_F(CloseDrainSinkTest, AwaitClosedDeadlinePast)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 1));
    installSink(TestSink::Mode::ResolveOk);
    PoolBlocker blocker;
    ASSERT_TRUE(blocker.post());
    ASSERT_TRUE(blocker.waitEntered(5s));
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 10)});
    auto writer = c->writer("b");
    auto results = Results::create();
    std::vector<ic::Ticket> tickets;
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        auto submit = writer->submit(indexOp(id(k)), results->callback(k));
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(submit.ticket);
    }
    ASSERT_TRUE(eventually([] { return ic::detail::runtimePoolStats().postsPending >= 10; }, scaled(5000ms)));

    const auto t0 = now();
    const auto report = c->awaitClosed(t0 - 1s);
    const auto took = now() - t0;
    ASSERT_TRUE(report.ok());
    EXPECT_LT(took, scaled(100ms));
    EXPECT_EQ(report.value.callbacksInFlight, 0u);

    blocker.release();
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        const auto result = tickets[k].wait(in(scaled(5000ms)));
        ASSERT_TRUE(result.ok()) << k << " " << ic::toString(result.cause);
        EXPECT_EQ(result.value.status, ic::Status::Ok) << k;
    }
    ASSERT_TRUE(eventually([] { return ic::detail::runtimePoolStats().postsPending == 0; }, scaled(5000ms)));
    const auto again = c->awaitClosed(in(scaled(2000ms)));
    ASSERT_TRUE(again.ok());
    EXPECT_EQ(again.value.callbacksSkipped, 10u) << describe(again.value);
    EXPECT_EQ(results->total(), 0u) << "a callback ran past the cutoff";
}

// I99 obj. 7c: D - now = 100 ms with callbackBudget 200 ms (< 2 x budget): the sweep lands near now + 50 ms and the
// cutoff near now + 75 ms. Client x: its worker is free at + 55 ms, so its callback starts; client y: free at + 95 ms,
// so its callback is skipped. The Ticket without callback completes at the sweep.
TEST_F(CloseDrainSinkTest, ShortDeadlineHalves)
{
    const auto span = scaled(100ms);
    ASSERT_NO_FATAL_FAILURE(start(1, 1, {{"callback_budget_ms", std::to_string(scaled(200ms).count())}}));
    auto sink = installSink(TestSink::Mode::Hold, 0); // Nothing is dispatched: everything stays pending.

    struct Seen final
    {
        ic::TimePoint t0 {};
        ic::TimePoint swept {};
        ic::CloseReport report;
    };
    const auto run = [&](const std::string& name, std::chrono::milliseconds freeAt, StartLog& log) -> Seen
    {
        Seen seen;
        auto c = client(name, {heldBack("b", 1000)});
        auto writer = c->writer("b");
        auto plain = writer->submit(indexOp(id(0)));
        EXPECT_TRUE(plain.accepted);
        auto withCallback = writer->submit(indexOp(id(1)), [&log](const ic::OpResult&) { log.add(now()); });
        EXPECT_TRUE(withCallback.accepted);
        PoolBlocker blocker;
        EXPECT_TRUE(blocker.post());
        EXPECT_TRUE(blocker.waitEntered(5s));
        auto swept = std::make_shared<std::atomic<ic::TimePoint::rep>>(0);
        AsyncCall waiter(
            [ticket = plain.ticket, swept]
            {
                ticket.wait(now() + 5s);
                swept->store(now().time_since_epoch().count());
            });
        seen.t0 = now();
        blocker.releaseAt(seen.t0 + freeAt);
        const auto report = c->awaitClosed(seen.t0 + span);
        EXPECT_TRUE(report.ok());
        EXPECT_TRUE(waiter.wait(5s));
        seen.swept = ic::TimePoint(ic::TimePoint::duration(swept->load()));
        EXPECT_TRUE(withCallback.ticket.wait(now() + 5s).ok());
        const auto again = c->awaitClosed(now() + 1s);
        EXPECT_TRUE(again.ok());
        seen.report = again.value;
        return seen;
    };

    StartLog xLog;
    const auto x = run("x", span * 55 / 100, xLog);
    EXPECT_GE(x.swept - x.t0, span / 2) << "swept before now + left / 2";
    EXPECT_LT(x.swept - x.t0, span / 2 + scaled(20ms)) << "swept " << millis(x.swept - x.t0) << " ms after the call";
    ASSERT_EQ(xLog.size(), 1u) << "the callback freed before the cutoff did not start: " << describe(x.report);
    EXPECT_LT(xLog.starts().front() - x.t0, span * 3 / 4) << "started past the cutoff";
    EXPECT_EQ(x.report.callbacksSkipped, 0u);
    EXPECT_EQ(x.report.droppedClientClosed, 2u);

    StartLog yLog;
    const auto y = run("y", span * 95 / 100, yLog);
    EXPECT_GE(y.swept - y.t0, span / 2);
    EXPECT_LT(y.swept - y.t0, span / 2 + scaled(20ms));
    EXPECT_EQ(yLog.size(), 0u) << "a callback freed after now + 3 x left / 4 started";
    EXPECT_EQ(y.report.callbacksSkipped, 1u) << describe(y.report);
    EXPECT_EQ(sink->dispatched(), 0u);
}

// k4-1: a callback of 2 x callbackBudget counts one overrun; one of 0.5 x does not.
TEST_F(CloseDrainSinkTest, CallbackOverrunCounted)
{
    const auto budget = scaled(200ms);
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"callback_budget_ms", std::to_string(budget.count())}}));
    installSink(TestSink::Mode::ResolveOk);
    const auto spec = bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1);

    auto results = Results::create();
    auto shortOnly = client("short", {spec});
    ASSERT_TRUE(shortOnly->writer("b")
                    ->submit(indexOp(id(0)), logged(std::make_shared<StartLog>(), results->callback(0), budget / 2))
                    .accepted);
    ASSERT_TRUE(results->waitTotal(1, scaled(5000ms)));
    const auto shortReport = shortOnly->awaitClosed(in(scaled(5000ms)));
    ASSERT_TRUE(shortReport.ok());
    EXPECT_EQ(shortReport.value.callbackOverruns, 0u) << describe(shortReport.value);

    auto both = client("both", {spec});
    auto writer = both->writer("b");
    ASSERT_TRUE(writer->submit(indexOp(id(1)), logged(std::make_shared<StartLog>(), results->callback(1), budget / 2))
                    .accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(2)), logged(std::make_shared<StartLog>(), results->callback(2), 2 * budget))
                    .accepted);
    ASSERT_TRUE(results->waitTotal(3, scaled(5000ms)));
    const auto report = both->awaitClosed(in(scaled(5000ms)));
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.callbacksInFlight, 0u);
    EXPECT_EQ(report.value.callbackOverruns, 1u) << describe(report.value);
}

// G-diff E5b obj. 1: a resolution is outstanding before it stops being retained. Ops A and B of one client are held by
// the sink; after requestClose() A is resolved on another thread and parked right after its payload was released
// (seam afterPayloadReleased), then B is resolved: Σ retained is 0 and the drain predicate holds while A is parked.
// awaitClosed(now + 10 s) must still wait for A's completion: it does not return while A is parked, both callbacks
// run and nothing is skipped. Mutant: the client accounting after releasePayload (the old order).
TEST_F(CloseDrainSinkTest, ResolutionOutstandingBeforeReleased)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2));
    auto sink = installSink(TestSink::Mode::Hold);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();
    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(sink->waitDispatched(2));
    std::vector<std::shared_ptr<wr::OpState>> ops;
    for (const auto& batch : sink->take())
    {
        ops.insert(ops.end(), batch.ops.begin(), batch.ops.end());
    }
    ASSERT_EQ(ops.size(), 2u);

    c->requestClose();
    Park park;
    hooks::setAfterPayloadReleased(park.hook());
    AsyncCall resolveA([path = m_path, op = ops[0]] { path->resolve(op, TestSink::ok()); });
    ASSERT_TRUE(park.waitEntered(5s));
    auto report = std::make_shared<ic::Outcome<ic::CloseReport>>();
    AsyncCall closer([c, report] { *report = c->awaitClosed(now() + 10s); });
    ASSERT_TRUE(m_path->resolve(ops[1], TestSink::ok())); // Σ retained = 0 from here on.
    const bool returnedWhileParked = closer.wait(scaled(300ms));
    park.release();
    ASSERT_TRUE(resolveA.wait(5s));
    ASSERT_TRUE(closer.wait(5s));
    hooks::setAfterPayloadReleased({});

    EXPECT_FALSE(returnedWhileParked) << "awaitClosed returned with A's completion not yet outstanding";
    ASSERT_TRUE(report->ok());
    ASSERT_TRUE(results->waitTotal(2, scaled(5000ms)));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    EXPECT_EQ(report->value.callbacksSkipped, 0u) << describe(report->value);
    EXPECT_EQ(report->value.drained, 2u) << describe(report->value);
}

// G-diff E5b obj. 4: the cutoff gate decides and marks under completionsMutex. One completion is parked inside the
// gate (seam inCallbackGate, after the comparison with the cutoff still open, before the mark) and its callback blocks
// once started; awaitClosed(now - 1 s) from the owner thread must not return while the gate is open, and when it
// returns the callback is counted as started (callbacksInFlight 1, nothing skipped). Mutant: the cutoff decided
// without completionsMutex (awaitClosed returns at once with callbacksInFlight 0 and the callback starts after it).
TEST_F(CloseDrainSinkTest, CutoffGateHoldsAwaitClosed)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2));
    installSink(TestSink::Mode::ResolveOk);
    Park gate;
    hooks::setInCallbackGate(gate.hook());
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto started = std::make_shared<std::atomic<ic::TimePoint::rep>>(0);
    auto results = Results::create();
    const auto inner = results->callback(0);
    ASSERT_TRUE(c->writer("b")
                    ->submit(indexOp(id(0)),
                             [started, inner](const ic::OpResult& result)
                             {
                                 started->store(now().time_since_epoch().count());
                                 std::this_thread::sleep_for(scaled(300ms)); // Still running when awaitClosed reads.
                                 inner(result);
                             })
                    .accepted);
    ASSERT_TRUE(gate.waitEntered(5s));

    auto report = std::make_shared<ic::Outcome<ic::CloseReport>>();
    AsyncCall closer([c, report] { *report = c->awaitClosed(now() - 1s); });
    const bool returnedWhileOpen = closer.wait(scaled(300ms));
    gate.release();
    ASSERT_TRUE(closer.wait(5s));
    ASSERT_TRUE(results->waitTotal(1, scaled(5000ms)));
    hooks::setInCallbackGate({});

    EXPECT_FALSE(returnedWhileOpen) << "awaitClosed returned while a completion was inside the gate";
    ASSERT_TRUE(report->ok());
    EXPECT_EQ(report->value.callbacksInFlight, 1u) << describe(report->value);
    EXPECT_EQ(report->value.callbacksSkipped, 0u) << describe(report->value);
    EXPECT_NE(started->load(), 0) << "the callback never ran";
}

// T8, CA-17: three healthy consumers with N = (rate measured over 2 s) x 0.5 x the 5 s budget ops in total;
// beginShutdown(now + 5 s), requestClose() on the three, awaitClosed(shutdownDeadline()) on each and shutdown():
// every op Ok, nothing dropped, all within 5 s. Mutant: awaitClosed does not wait for the drain.
TEST_F(CloseDrainTest, OneBeginShutdownThreeConsumersHealthy)
{
    auto script = BulkScript::items();
    script.latency = 10ms; // Bounds the node's rate (window 4 x 50 docs per 10 ms).
    const auto a = startNode(script);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    const auto budget = scaled(5000ms);

    // The rate: one producer blocking on a 1 MiB quota for 2 s.
    std::uint64_t rate = 0;
    {
        auto measure = client("measure", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Block, 0, 50, 50ms)});
        auto writer = measure->writer("b");
        auto ok = std::make_shared<std::atomic<std::uint64_t>>(0);
        std::atomic<bool> stop {false};
        std::thread producer(
            [&]
            {
                for (std::uint64_t k = 0; !stop.load(); ++k)
                {
                    writer->submit(indexOp(id(k)),
                                   [ok](const ic::OpResult& r)
                                   {
                                       if (r.status == ic::Status::Ok)
                                       {
                                           ok->fetch_add(1);
                                       }
                                   });
                }
            });
        std::this_thread::sleep_for(500ms); // Warm-up (window and connections).
        const auto from = ok->load();
        std::this_thread::sleep_for(2s);
        rate = (ok->load() - from) / 2;
        stop = true;
        producer.join();
        ASSERT_TRUE(measure->awaitClosed(in(scaled(10000ms))).ok());
    }
    ASSERT_GT(rate, 0u);
    const std::uint64_t total = rate * budget.count() / 1000 / 2;
    const std::uint64_t perClient = std::max<std::uint64_t>(1, total / 3);

    std::vector<std::shared_ptr<ic::Client>> clients;
    auto ok = std::make_shared<std::atomic<std::uint64_t>>(0);
    auto other = std::make_shared<std::atomic<std::uint64_t>>(0);
    const auto count = [ok, other](const ic::OpResult& r)
    {
        (r.status == ic::Status::Ok ? ok : other)->fetch_add(1);
    };
    for (int i = 0; i < 3; ++i)
    {
        clients.push_back(
            client("c" + std::to_string(i), {bucketSpec("b", 256u << 20, ic::Overflow::Kind::Reject, 0, 50, 50ms)}));
        auto writer = clients.back()->writer("b");
        for (std::uint64_t k = 0; k < perClient; ++k)
        {
            ASSERT_TRUE(writer->submit(indexOp(id(k)), count).accepted)
                << "rate " << rate << " per client " << perClient;
        }
    }

    const auto t0 = now();
    ASSERT_EQ(ic::RuntimeOwner::beginShutdown(t0 + budget), ic::Cause::None);
    const auto deadline = m_ref.shutdownDeadline();
    ASSERT_TRUE(deadline.has_value());
    for (auto& c : clients)
    {
        c->requestClose();
    }
    std::vector<ic::CloseReport> reports;
    for (auto& c : clients)
    {
        const auto report = c->awaitClosed(*deadline);
        ASSERT_TRUE(report.ok());
        reports.push_back(report.value);
    }
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto took = now() - t0;
    // On a failure: skipped > 0 with nothing dropped is a lost callback (G-diff obj. 1); dropped > 0 is a drain that
    // did not fit the budget (the calibration).
    std::string seen;
    for (const auto& report : reports)
    {
        seen += " [" + describe(report) + "]";
    }
    EXPECT_LT(took, budget) << "rate " << rate << "/s, " << 3 * perClient << " ops;" << seen;
    EXPECT_EQ(ok->load(), 3 * perClient) << "rate " << rate << "/s; others " << other->load() << ";" << seen;
    EXPECT_EQ(other->load(), 0u);
    for (const auto& report : reports)
    {
        EXPECT_EQ(report.droppedClientClosed, 0u) << describe(report);
        EXPECT_EQ(report.droppedShutdown, 0u) << describe(report);
    }
    std::printf("[ info ] rate %llu ops/s, %llu ops in total, shutdown sequence %lld ms\n",
                static_cast<unsigned long long>(rate),
                static_cast<unsigned long long>(3 * perClient),
                millis(took));
}

// T8, CA-17: the node is down (it holds every `_bulk`) and callbacks are running (one of them 1 s long): with
// beginShutdown(now + 2 s), requestClose() x 3, awaitClosed(D) x 3 and shutdown(), every op has a result, shutdown()
// returns before D + margin and no callback started past its client's cutoff. The awaitClosed calls are sequential
// with one D, so each later one has less left: its cutoff is D - callbackBudget only while D - call >= 2 x budget,
// else call + 3 x (D - call) / 4 (writer.hpp «Close»); every start is also before D.
TEST_F(CloseDrainTest, OneBeginShutdownThreeConsumersDown)
{
    auto down = std::make_shared<std::atomic<bool>>(false);
    const auto a = startNode(BulkScript::items(),
                             "green",
                             {},
                             [down](const httplib::Request&, Rule& reply)
                             {
                                 if (down->load())
                                 {
                                     reply.hold = true;
                                 }
                             });
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    const ic::Duration callbackBudget = ic::RuntimeConfig {}.callbackBudget;

    std::vector<std::shared_ptr<ic::Client>> clients;
    for (int i = 0; i < 3; ++i)
    {
        clients.push_back(client("c" + std::to_string(i), {heldBack("p", 5), heldBack("s", 1)}));
    }
    std::vector<std::shared_ptr<StartLog>> logs;
    for (std::size_t i = 0; i < clients.size(); ++i)
    {
        logs.push_back(std::make_shared<StartLog>());
    }
    auto results = Results::create();
    auto slowStarted = std::make_shared<std::promise<void>>();
    auto slowFuture = slowStarted->get_future();
    ASSERT_TRUE(clients[0]
                    ->writer("s")
                    ->submit(indexOp(id(900)),
                             [slowStarted, results](const ic::OpResult& r)
                             {
                                 slowStarted->set_value();
                                 results->callback(900)(r);
                                 std::this_thread::sleep_for(1s); // The delayed callback.
                             })
                    .accepted);
    ASSERT_EQ(slowFuture.wait_for(scaled(5000ms)), std::future_status::ready);
    down->store(true);

    std::vector<ic::Ticket> tickets;
    for (std::size_t i = 0; i < clients.size(); ++i)
    {
        auto writer = clients[i]->writer("p");
        for (std::uint64_t k = 0; k < 12; ++k)
        {
            const auto key = i * 100 + k;
            auto submit = writer->submit(indexOp(id(key)), logged(logs[i], results->callback(key)));
            ASSERT_TRUE(submit.accepted);
            tickets.push_back(submit.ticket);
        }
    }
    ASSERT_TRUE(a.fake->waitHeld(4, scaled(5000ms))) << "the node window never filled";

    const auto t0 = now();
    const auto deadline = t0 + 2s;
    ASSERT_EQ(ic::RuntimeOwner::beginShutdown(deadline), ic::Cause::None);
    for (auto& c : clients)
    {
        c->requestClose();
    }
    std::vector<ic::TimePoint> cutoffs;
    for (auto& c : clients)
    {
        const auto call = now();
        const auto left = deadline - call;
        cutoffs.push_back(left >= 2 * callbackBudget ? deadline - callbackBudget : call + 3 * left / 4);
        const auto report = c->awaitClosed(deadline);
        EXPECT_TRUE(report.ok());
    }
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto returned = now();
    EXPECT_LT(returned, deadline + scaled(1000ms)) << "shutdown() took " << millis(returned - t0) << " ms";
    for (std::size_t i = 0; i < tickets.size(); ++i)
    {
        ASSERT_TRUE(tickets[i].ready()) << i;
        EXPECT_EQ(tickets[i].wait(in(1s)).value.status, ic::Status::Dropped) << i;
    }
    std::size_t started = 0;
    for (std::size_t i = 0; i < clients.size(); ++i)
    {
        EXPECT_EQ(logs[i]->notBefore(cutoffs[i]), 0u)
            << "client " << i << ": a callback started past its cutoff (+" << millis(cutoffs[i] - t0) << " ms)";
        EXPECT_EQ(logs[i]->notBefore(deadline), 0u);
        started += logs[i]->size();
    }
    std::size_t skipped = 0;
    for (auto& c : clients)
    {
        const auto report = c->awaitClosed(in(100ms));
        ASSERT_TRUE(report.ok());
        skipped += report.value.callbacksSkipped;
        EXPECT_EQ(report.value.callbacksInFlight, 0u);
    }
    EXPECT_EQ(started + skipped, tickets.size()) << "every op: a callback or a skip";
    EXPECT_EQ(results->count(900), 1);
    a.fake->releaseHeld();
}

namespace
{
    std::atomic<int> g_signalled {0};
    std::atomic<int> g_signalFd {-1};
    std::atomic<pid_t> g_handlerTid {0};

    void onSigusr1(int)
    {
        g_signalled.store(1);
        g_handlerTid.store(static_cast<pid_t>(::syscall(SYS_gettid)));
        const std::uint64_t one = 1;
        const auto written = ::write(g_signalFd.load(), &one, sizeof(one));
        (void)written;
    }
} // namespace

// T8: SIGUSR1 blocked on the test (owner) thread before the fake, the runtime and the load exist, so only the owner
// can take it; its handler only sets a flag and writes an eventfd; kill(getpid()) during the load. The owner thread,
// waiting on the eventfd, runs beginShutdown / requestClose / awaitClosed / shutdown(): it is not a runtime thread
// (seams' tid registry) and shutdown() is None.
TEST_F(CloseDrainTest, SignalDuringActivityOwnerThread)
{
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigset_t previousMask;
    ASSERT_EQ(::pthread_sigmask(SIG_BLOCK, &usr1, &previousMask), 0);
    const int efd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(efd, 0);
    g_signalFd.store(efd);
    g_signalled.store(0);
    g_handlerTid.store(0);
    struct sigaction action
    {
    };
    action.sa_handler = onSigusr1;
    sigemptyset(&action.sa_mask);
    struct sigaction previousAction
    {
    };
    ASSERT_EQ(::sigaction(SIGUSR1, &action, &previousAction), 0);

    const auto a = startNode();
    hooks::clearRuntimeThreads();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {bucketSpec("b", 4u << 20, ic::Overflow::Kind::Block, 0, 20, 50ms)});
    auto writer = c->writer("b");
    std::atomic<std::uint64_t> accepted {0};
    std::atomic<int> endCause {-1};
    auto results = Results::create();
    std::thread load(
        [&]
        {
            for (std::uint64_t k = 0;; ++k)
            {
                const auto submit = writer->submit(indexOp(id(k)), results->callback(k));
                if (!submit.accepted)
                {
                    endCause = static_cast<int>(submit.cause);
                    return;
                }
                ++accepted;
            }
        });
    std::thread killer(
        [&]
        {
            eventually([&] { return accepted.load() >= 2000; }, 5s);
            ::kill(::getpid(), SIGUSR1);
        });

    const pid_t owner = static_cast<pid_t>(::syscall(SYS_gettid));
    sigset_t waitMask = previousMask;
    sigdelset(&waitMask, SIGUSR1);
    pollfd pfd {efd, POLLIN, 0};
    const auto limit = now() + scaled(10000ms);
    bool woke = false;
    while (!woke && now() < limit)
    {
        timespec slice {0, 100 * 1000 * 1000};
        const int n = ::ppoll(&pfd, 1, &slice, &waitMask);
        std::uint64_t value = 0;
        woke = (n > 0 || g_signalled.load() != 0) && ::read(efd, &value, sizeof(value)) == sizeof(value);
    }
    killer.join();
    EXPECT_TRUE(woke) << "the signal never reached the owner";
    EXPECT_EQ(g_signalled.load(), 1);
    EXPECT_GT(accepted.load(), 0u) << "no activity when the signal came";

    const auto deadline = now() + scaled(3000ms);
    EXPECT_EQ(ic::RuntimeOwner::beginShutdown(deadline), ic::Cause::None);
    c->requestClose();
    const auto report = c->awaitClosed(deadline);
    EXPECT_TRUE(report.ok());
    load.join();
    EXPECT_EQ(endCause.load(), static_cast<int>(ic::Cause::ClientClosed));
    const auto runtimeTids = hooks::runtimeThreads();
    EXPECT_FALSE(runtimeTids.empty());
    EXPECT_EQ(std::find(runtimeTids.begin(), runtimeTids.end(), owner), runtimeTids.end())
        << "the shutdown sequence ran on a runtime thread";
    EXPECT_EQ(std::find(runtimeTids.begin(), runtimeTids.end(), g_handlerTid.load()), runtimeTids.end())
        << "a runtime thread took the signal";
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    EXPECT_TRUE(results->waitTotal(accepted.load(), scaled(2000ms)));

    ::sigaction(SIGUSR1, &previousAction, nullptr);
    ::pthread_sigmask(SIG_SETMASK, &previousMask, nullptr);
    g_signalFd.store(-1);
    ::close(efd);
}

// CA-17: a producer blocked on a full quota (Overflow::Block) and a query in its backoff after a 503: requestClose()
// from the test thread wakes both with ClientClosed in < 500 ms.
TEST_F(CloseDrainTest, BlockedProducerAndQueryUnblock)
{
    const auto a = startNode();
    Rule busy;
    busy.method = "POST";
    busy.pathRegex = "/busy/_search";
    busy.status = 503;
    busy.body = UNAVAILABLE_BODY;
    a.fake->addRule(busy);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    const std::uint64_t charge = wireSize(indexOp(id(0))) + R;
    auto c = client("c", {heldBack("b", 1000, 2 * charge, ic::Overflow::Kind::Block)});
    auto writer = c->writer("b");
    ASSERT_TRUE(writer->submit(indexOp(id(0))).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(1))).accepted);

    auto query = c->query();
    ic::QueryOptions options;
    options.retry.base = ic::Duration {10000};
    options.retry.cap = ic::Duration {10000};
    options.retry.jitter = 0.0;
    auto searched = std::make_shared<ic::Outcome<nlohmann::json>>();
    auto blocked = std::make_shared<ic::Submit>();
    const auto searches = [&]
    {
        std::size_t n = 0;
        for (const auto& request : a.fake->requests())
        {
            n += request.path == "/busy/_search" ? 1 : 0;
        }
        return n;
    };
    {
        AsyncCall search(
            [query, options, searched] {
                *searched =
                    query->search("busy", nlohmann::json::parse(R"({"query":{"match_all":{}}})"), options, now() + 30s);
            });
        AsyncCall producer([writer, blocked] { *blocked = writer->submit(indexOp(id(2))); });
        ASSERT_TRUE(eventually([&] { return searches() == 1; }, scaled(5000ms))) << "the search never reached the fake";
        std::this_thread::sleep_for(scaled(100ms)); // The query in its backoff, the producer on the quota.
        ASSERT_FALSE(search.done());
        ASSERT_FALSE(producer.done()) << ic::toString(blocked->cause);
        const auto t0 = now();
        c->requestClose();
        EXPECT_TRUE(search.wait(scaled(500ms))) << "the query backoff was not woken";
        EXPECT_TRUE(producer.wait(scaled(500ms))) << "the blocked producer was not woken";
        EXPECT_LT(now() - t0, scaled(500ms));
    }
    EXPECT_EQ(searched->cause, ic::Cause::ClientClosed) << searched->reason;
    EXPECT_FALSE(blocked->accepted);
    EXPECT_EQ(blocked->cause, ic::Cause::ClientClosed);
    const auto report = c->awaitClosed(in(5s));
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.drained, 2u) << "the two queued ops drain";
    EXPECT_EQ(searches(), 1u);
}

// T18, I99 obj. 12: K = 1. A callback calls requestClose() on its own client (returns at once; its pending ops
// drain); another destroys the last handle of its Client (a counted usage error, no deadlock, no self-join); a third
// waits on a Ticket (Reentrancy at once). Two concurrent awaitClosed() on one client return the same CloseReport.
TEST_F(CloseDrainTest, CallbackCloseAndDestroyK1)
{
    const auto a = startNode(BulkScript::items(), "green", {}, holdIndex("wazuh-twice"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"network_threads", "1"}}));
    const auto trigger = bucketSpec("t", 4u << 20, ic::Overflow::Kind::Reject, 0, 1);

    // requestClose() from a callback.
    {
        auto closing = client("closing", {trigger, heldBack("p", 1000)});
        auto results = Results::create();
        for (std::uint64_t k = 0; k < 3; ++k)
        {
            ASSERT_TRUE(closing->writer("p")->submit(indexOp(id(k)), results->callback(k)).accepted);
        }
        auto took = std::make_shared<std::promise<std::chrono::nanoseconds>>();
        auto tookFuture = took->get_future();
        ic::Client* self = closing.get();
        ASSERT_TRUE(closing->writer("t")
                        ->submit(indexOp(id(10)),
                                 [took, self](const ic::OpResult&)
                                 {
                                     const auto t0 = now();
                                     self->requestClose();
                                     took->set_value(now() - t0);
                                 })
                        .accepted);
        ASSERT_EQ(tookFuture.wait_for(scaled(5000ms)), std::future_status::ready) << "requestClose() hung";
        EXPECT_LT(tookFuture.get(), scaled(100ms));
        ASSERT_TRUE(results->waitTotal(3, scaled(5000ms)));
        EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
        const auto report = closing->awaitClosed(in(5s));
        ASSERT_TRUE(report.ok());
        EXPECT_EQ(report.value.drained, 3u) << describe(report.value);
    }

    // The last handle destroyed in a callback.
    {
        const auto errorsBefore = ic::detail::testing::usageErrors();
        auto owned = std::make_shared<std::shared_ptr<ic::Client>>(client("destroyed", {trigger}));
        auto took = std::make_shared<std::promise<std::chrono::nanoseconds>>();
        auto tookFuture = took->get_future();
        ASSERT_TRUE((*owned)
                        ->writer("t")
                        ->submit(indexOp(id(20)),
                                 [owned, took](const ic::OpResult&)
                                 {
                                     const auto t0 = now();
                                     owned->reset();
                                     took->set_value(now() - t0);
                                 })
                        .accepted);
        ASSERT_EQ(tookFuture.wait_for(scaled(5000ms)), std::future_status::ready) << "~Client in a callback hung";
        EXPECT_LT(tookFuture.get(), scaled(100ms)) << "~Client waited on a runtime thread";
        EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + 1);
    }

    // Ticket::wait in a callback.
    {
        auto waiting = client("waiting", {trigger, heldBack("p", 1000)});
        const auto outside = waiting->writer("p")->submit(indexOp(id(30)));
        ASSERT_TRUE(outside.accepted);
        auto waited = std::make_shared<std::promise<std::pair<ic::Cause, std::chrono::nanoseconds>>>();
        auto waitedFuture = waited->get_future();
        ASSERT_TRUE(waiting->writer("t")
                        ->submit(indexOp(id(31)),
                                 [waited, ticket = outside.ticket](const ic::OpResult&)
                                 {
                                     const auto t0 = now();
                                     const auto cause = ticket.wait(now() + 2s).cause;
                                     waited->set_value({cause, now() - t0});
                                 })
                        .accepted);
        ASSERT_EQ(waitedFuture.wait_for(scaled(5000ms)), std::future_status::ready);
        const auto [cause, took] = waitedFuture.get();
        EXPECT_EQ(cause, ic::Cause::Reentrancy) << ic::toString(cause);
        EXPECT_LT(took, scaled(100ms));
        ASSERT_TRUE(waiting->awaitClosed(in(5s)).ok());
        EXPECT_EQ(outside.ticket.wait(in(1s)).value.status, ic::Status::Ok);
    }

    // Two concurrent awaitClosed().
    {
        auto twice = client("twice", {heldBack("p", 3)});
        auto results = Results::create();
        for (std::uint64_t k = 0; k < 3; ++k)
        {
            ASSERT_TRUE(
                twice->writer("p")->submit(indexOp(id(40 + k), 16, "wazuh-twice"), results->callback(k)).accepted);
        }
        ASSERT_TRUE(a.fake->waitHeld(1, scaled(5000ms)));
        auto first = std::make_shared<ic::Outcome<ic::CloseReport>>();
        auto second = std::make_shared<ic::Outcome<ic::CloseReport>>();
        const auto deadline = in(scaled(1000ms));
        {
            AsyncCall one([twice, first, deadline] { *first = twice->awaitClosed(deadline); });
            AsyncCall two([twice, second, deadline] { *second = twice->awaitClosed(deadline); });
            EXPECT_TRUE(one.wait(scaled(5000ms)));
            EXPECT_TRUE(two.wait(scaled(5000ms)));
        }
        ASSERT_TRUE(first->ok());
        ASSERT_TRUE(second->ok());
        EXPECT_TRUE(sameReport(first->value, second->value))
            << describe(first->value) << " vs " << describe(second->value);
        EXPECT_EQ(first->value.droppedShutdown, 3u) << describe(first->value);
        EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 3u);
        a.fake->releaseHeld();
    }
}

// I99: cpu_threads 1 with the worker held until past the runtime cutoff, 1 000 completions of a live client queued
// behind it, and shutdown() with a short deadline: it returns before deadline + margin, the callbacks past
// stopDeadline - callbackBudget are skipped and every Ticket is complete. Mutant: stop() sets no callbackCutoff.
TEST_F(CloseDrainSinkTest, ShutdownCutsCallbacksOfLiveClients)
{
    constexpr std::uint64_t OPS = 1000;
    ASSERT_NO_FATAL_FAILURE(start(1, 1, {{"callback_budget_ms", std::to_string(scaled(200ms).count())}}));
    installSink(TestSink::Mode::ResolveOk);
    PoolBlocker blocker;
    ASSERT_TRUE(blocker.post());
    ASSERT_TRUE(blocker.waitEntered(5s));
    auto c = client("c", {bucketSpec("b", 16u << 20, ic::Overflow::Kind::Reject, 0, 100)});
    auto writer = c->writer("b");
    auto results = Results::create();
    auto log = std::make_shared<StartLog>();
    std::vector<ic::Ticket> tickets;
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        auto submit = writer->submit(indexOp(id(k)), logged(log, results->callback(k), 2ms));
        ASSERT_TRUE(submit.accepted);
        tickets.push_back(submit.ticket);
    }
    ASSERT_TRUE(eventually([] { return ic::detail::runtimePoolStats().postsPending >= OPS; }, scaled(5000ms)));

    const auto t0 = now();
    const auto deadline = t0 + scaled(500ms);
    const auto cutoff = deadline - scaled(200ms);
    blocker.releaseAt(t0 + scaled(350ms)); // Past the cutoff.
    ASSERT_EQ(ic::RuntimeOwner::beginShutdown(deadline), ic::Cause::None);
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto returned = now();
    EXPECT_LT(returned, deadline + scaled(500ms)) << "shutdown() took " << millis(returned - t0) << " ms";
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(tickets[k].ready()) << k;
        EXPECT_EQ(tickets[k].wait(in(1s)).value.status, ic::Status::Ok) << k;
    }
    EXPECT_EQ(log->notBefore(cutoff), 0u) << "callbacks started past the runtime cutoff";
    const auto report = c->awaitClosed(in(100ms));
    ASSERT_TRUE(report.ok());
    EXPECT_GT(report.value.callbacksSkipped, 0u) << describe(report.value);
    EXPECT_EQ(report.value.callbacksSkipped + log->size(), OPS);
}
