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

// Admission against stop, and stop against itself (plan-E2a-1 §Tests, lot A: D26 H7 and H7b).

#include <dlfcn.h>

#include <atomic>

#include <curl/curl.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "testTimeScale.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;
using indexer_client::testing::scaled;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    /// Every curl_multi_cleanup of the process (a multi is cleaned up once per loop when the transport stops).
    std::atomic<std::uint64_t> g_multiCleanups {0};
    std::atomic<std::uint64_t> g_nullMultiCleanups {0};
} // namespace

// Interposed (the component executable is linked with -rdynamic and the library objects call curl through it): counts
// and forwards to libcurl inside wazuhext. A cleanup of an already cleaned (null) multi is a second teardown.
extern "C" CURLMcode curl_multi_cleanup(CURLM* multi)
{
    using Real = CURLMcode (*)(CURLM*);
    static const auto real = reinterpret_cast<Real>(dlsym(RTLD_NEXT, "curl_multi_cleanup"));
    g_multiCleanups.fetch_add(1);
    if (multi == nullptr)
    {
        g_nullMultiCleanups.fetch_add(1);
        ADD_FAILURE() << "curl_multi_cleanup ran again on a loop already torn down (double join)";
    }
    return real(multi);
}

// D26 (H7): submit ∥ stop. Four submitters are held in afterAdmissionCheck (registered, not yet posted) while the
// runtime shuts down; four more keep submitting through the stop. Every admitted id gets exactly one result, every
// refused one none; the race is proven by the held submitters' posts being refused by the closed loops.
TEST_F(TransportTest, ExactlyOncePerAdmittedId)
{
    constexpr std::size_t HELD = 4;
    constexpr std::size_t LATE = 4;
    FakeIndexerOptions options;
    options.threads = 32;
    FakeIndexer fake(options);
    fake.start();
    auto transport = startRuntime(2, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto url = fake.baseUrl() + "/admission";

    struct Barrier final
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool armed {false};
        std::size_t inHook {0};
        bool released {false};
    };
    auto barrier = std::make_shared<Barrier>();
    hooks::setAfterAdmissionCheck(
        [barrier]()
        {
            std::unique_lock<std::mutex> lock(barrier->mutex);
            if (!barrier->armed || barrier->inHook >= HELD)
            {
                return;
            }
            ++barrier->inHook;
            barrier->cv.notify_all();
            barrier->cv.wait_for(lock, 20s, [&] { return barrier->released; });
        });

    struct Record final
    {
        std::mutex mutex;
        std::vector<Submitted> all;
    };
    auto record = std::make_shared<Record>();
    const auto keep = [record](const Submitted& submitted)
    {
        std::lock_guard<std::mutex> lock(record->mutex);
        record->all.push_back(submitted);
    };

    // Warm-up: the loops are serving.
    for (int i = 0; i < 8; ++i)
    {
        keep(submitTo(*transport, collector, request(HttpMethod::Get, url)));
    }
    ASSERT_TRUE(collector->waitTotal(8, 10s));

    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        barrier->armed = true;
    }
    std::vector<std::unique_ptr<AsyncCall>> held;
    for (std::size_t i = 0; i < HELD; ++i)
    {
        held.push_back(
            std::make_unique<AsyncCall>([transport, collector, url, keep]()
                                        { keep(submitTo(*transport, collector, request(HttpMethod::Get, url))); }));
    }
    {
        std::unique_lock<std::mutex> lock(barrier->mutex);
        ASSERT_TRUE(barrier->cv.wait_for(lock, 10s, [&] { return barrier->inHook == HELD; }));
    }

    auto lateRefused = std::make_shared<std::atomic<std::size_t>>(0);
    std::vector<std::unique_ptr<AsyncCall>> late;
    for (std::size_t i = 0; i < LATE; ++i)
    {
        late.push_back(std::make_unique<AsyncCall>(
            [transport, collector, url, keep, lateRefused]()
            {
                const auto until = std::chrono::steady_clock::now() + 20s;
                while (std::chrono::steady_clock::now() < until)
                {
                    const auto submitted = submitTo(*transport, collector, request(HttpMethod::Get, url));
                    keep(submitted);
                    if (!submitted.admission.admitted)
                    {
                        if (submitted.admission.cause == indexer_client::Cause::Shutdown)
                        {
                            lateRefused->fetch_add(1);
                        }
                        return;
                    }
                    std::this_thread::yield();
                }
            }));
    }

    const auto rejectedBefore = hooks::postsRejected();
    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    {
        std::lock_guard<std::mutex> lock(barrier->mutex);
        barrier->released = true;
    }
    barrier->cv.notify_all();
    for (auto& call : held)
    {
        ASSERT_TRUE(call->wait(10s));
    }
    for (auto& call : late)
    {
        ASSERT_TRUE(call->wait(30s));
    }

    // Race exercised: the held submitters were admitted before the stop and posted after it.
    EXPECT_GE(hooks::postsRejected() - rejectedBefore, HELD) << "the held posts must meet closed loops";
    EXPECT_EQ(lateRefused->load(), LATE) << "every late submitter ends refused with Shutdown";

    std::size_t admitted = 0;
    std::size_t refused = 0;
    std::lock_guard<std::mutex> lock(record->mutex);
    for (const auto& submitted : record->all)
    {
        if (submitted.admission.admitted)
        {
            ++admitted;
            EXPECT_GT(submitted.admission.id, 0u);
            EXPECT_EQ(collector->count(submitted.key), 1) << "admitted id " << submitted.admission.id;
        }
        else
        {
            ++refused;
            EXPECT_EQ(collector->count(submitted.key), 0) << "refused submission " << submitted.key;
        }
    }
    EXPECT_EQ(refused, LATE);
    EXPECT_EQ(collector->total(), admitted);
    std::set<std::uint64_t> ids;
    for (const auto& submitted : record->all)
    {
        if (submitted.admission.admitted)
        {
            EXPECT_TRUE(ids.insert(submitted.admission.id).second) << "id " << submitted.admission.id << " reused";
        }
    }
}

// D26 (H7b): two concurrent stop() calls while loop 0 is pinned by a task: neither returns before the loop is free,
// both return true, the loops are torn down once (one curl_multi_cleanup per loop) and the transfers in flight are
// resolved once each as Shutdown. RuntimeOwner::shutdown() afterwards is a third, idempotent stop.
TEST_F(TransportTest, ConcurrentStopsJoinOnce)
{
    constexpr std::uint32_t K = 2;
    constexpr std::size_t IN_FLIGHT = 4;
    FakeIndexerOptions options;
    options.threads = 32;
    FakeIndexer fake(options);
    Rule hold;
    hold.hold = true;
    fake.addRule(hold);
    fake.start();
    auto transport = startRuntime(K, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    std::vector<Submitted> submitted;
    for (std::size_t i = 0; i < IN_FLIGHT; ++i)
    {
        submitted.push_back(submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/stop")));
        ASSERT_TRUE(submitted.back().admission.admitted);
    }
    ASSERT_TRUE(fake.waitHeld(IN_FLIGHT, 10s));

    auto blocker = Blocker::create();
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(blocker->task(), 0));
    ASSERT_TRUE(blocker->waitStarted(1, 5s));

    const auto cleanupsBefore = g_multiCleanups.load();
    struct Calls final
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::size_t entered {0};
        std::size_t returned {0};
        std::vector<bool> results;
        std::vector<std::chrono::steady_clock::time_point> returnedAt;
    };
    auto calls = std::make_shared<Calls>();
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    const auto stopper = [transport, calls, deadline]()
    {
        {
            std::lock_guard<std::mutex> lock(calls->mutex);
            ++calls->entered;
        }
        calls->cv.notify_all();
        const bool result = transport->stop(deadline);
        {
            std::lock_guard<std::mutex> lock(calls->mutex);
            ++calls->returned;
            calls->results.push_back(result);
            calls->returnedAt.push_back(std::chrono::steady_clock::now());
        }
        calls->cv.notify_all();
    };
    AsyncCall first(stopper);
    AsyncCall second(stopper);
    ReleaseOnExit releaseBlocker(blocker);
    {
        std::unique_lock<std::mutex> lock(calls->mutex);
        ASSERT_TRUE(calls->cv.wait_for(lock, 5s, [&] { return calls->entered == 2; }));
    }
    // Observation window (measured, scaled()): both callers are inside stop() and neither may come back while loop 0
    // cannot tear down.
    std::this_thread::sleep_for(scaled(150ms));
    {
        std::lock_guard<std::mutex> lock(calls->mutex);
        EXPECT_EQ(calls->returned, 0u) << "a stop() returned before every loop was torn down";
    }
    const auto releasedAt = std::chrono::steady_clock::now();
    blocker->release();
    ASSERT_TRUE(first.wait(10s));
    ASSERT_TRUE(second.wait(10s));
    {
        std::lock_guard<std::mutex> lock(calls->mutex);
        ASSERT_EQ(calls->results.size(), 2u);
        EXPECT_TRUE(calls->results[0]);
        EXPECT_TRUE(calls->results[1]);
        for (const auto at : calls->returnedAt)
        {
            EXPECT_GE(at, releasedAt) << "both callers wait for the single teardown";
        }
    }
    EXPECT_EQ(g_multiCleanups.load() - cleanupsBefore, K) << "one curl_multi_cleanup per loop";
    EXPECT_EQ(g_nullMultiCleanups.load(), 0u);
    EXPECT_FALSE(blocker->expired());

    ASSERT_TRUE(collector->waitTotal(IN_FLIGHT, 10s));
    for (const auto& one : submitted)
    {
        EXPECT_EQ(collector->count(one.key), 1);
        EXPECT_EQ(collector->result(one.key)->cause, TransportCause::Shutdown);
        // The contract fills the timings also for Shutdown: each request reached the fake over a real connection.
        EXPECT_GT(collector->result(one.key)->timings.connect.count(), 0);
        EXPECT_GT(collector->result(one.key)->timings.total.count(), 0);
    }
    EXPECT_EQ(transport->stats().shutdown, IN_FLIGHT);

    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    EXPECT_EQ(g_multiCleanups.load() - cleanupsBefore, K) << "the owner's stop is idempotent";
    EXPECT_TRUE(transport->stop(deadline));
}
