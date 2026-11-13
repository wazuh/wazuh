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

// The ordered shutdown.

#include <dlfcn.h>
#include <netdb.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <iostream>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;
namespace hooks = indexer_client::testing_hooks;

namespace
{
    constexpr const char* HUNG_HOST = "slow.invalid";

    /// The interposed resolver's state. Never destroyed: a resolver thread curl abandoned may still be inside
    /// getaddrinfo when the process exits.
    struct HungResolver final
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::size_t entered {0};
        bool released {true};
    };

    HungResolver& hungResolver()
    {
        static auto* resolver = new HungResolver();
        return *resolver;
    }

    void armResolver()
    {
        auto& resolver = hungResolver();
        std::lock_guard<std::mutex> lock(resolver.mutex);
        resolver.entered = 0;
        resolver.released = false;
    }

    void releaseResolver()
    {
        auto& resolver = hungResolver();
        {
            std::lock_guard<std::mutex> lock(resolver.mutex);
            resolver.released = true;
        }
        resolver.cv.notify_all();
    }
} // namespace

// Interposed (-rdynamic): hangs only HUNG_HOST, until the test releases it, after confirming the entry; every other
// name goes to the real getaddrinfo.
extern "C" int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
{
    using Real = int (*)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
    static const auto real = reinterpret_cast<Real>(dlsym(RTLD_NEXT, "getaddrinfo"));
    if (node != nullptr && std::strcmp(node, HUNG_HOST) == 0)
    {
        auto& resolver = hungResolver();
        std::unique_lock<std::mutex> lock(resolver.mutex);
        ++resolver.entered;
        resolver.cv.notify_all();
        resolver.cv.wait(lock, [&] { return resolver.released; });
        return EAI_NONAME;
    }
    return real(node, service, hints, res);
}

// 10 000 results queued in a blocked CPU pool and transfers still in flight when the shutdown starts. The
// transport stops within its 2 s deadline (it never waits for the pool), the pool is drained afterwards, and every
// id is delivered exactly once, the in-flight ones as Shutdown.
TEST_F(TransportTest, ShutdownWithInternalBacklog)
{
    constexpr std::uint32_t M = 2;
    constexpr std::size_t BACKLOG = 10000;
    constexpr std::size_t IN_FLIGHT = 4;
    FakeIndexerOptions options;
    options.threads = 32;
    FakeIndexer fake(options);
    Rule hold;
    hold.hold = true;
    fake.addRule(hold);
    fake.start();
    auto transport = startRuntime(2, M);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    std::vector<Submitted> held;
    for (std::size_t i = 0; i < IN_FLIGHT; ++i)
    {
        held.push_back(submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/inflight")));
        ASSERT_TRUE(held.back().admission.admitted);
    }
    ASSERT_TRUE(fake.waitHeld(IN_FLIGHT, 10s));

    auto pool = Blocker::create(20s);
    ReleaseOnExit releasePool(pool);
    for (std::uint32_t i = 0; i < M; ++i)
    {
        ASSERT_TRUE(indexer_client::detail::testing::postToPool(pool->task()));
    }
    ASSERT_TRUE(pool->waitStarted(M, 5s)) << "every pool worker is blocked";

    const auto refused = "http://127.0.0.1:" + std::to_string(closedPort()) + "/backlog";
    std::vector<Submitted> backlog;
    backlog.reserve(BACKLOG);
    for (std::size_t i = 0; i < BACKLOG; ++i)
    {
        backlog.push_back(submitTo(*transport, collector, request(HttpMethod::Get, refused)));
        ASSERT_TRUE(backlog.back().admission.admitted);
    }
    ASSERT_TRUE(eventually([&] { return transport->stats().completed >= BACKLOG; }, 60s))
        << transport->stats().completed << " of " << BACKLOG << " completed";
    EXPECT_EQ(collector->total(), 0u) << "the pool is blocked: every result is queued";

    // The pool is let go only once the transport has resolved the transfers in flight (or after 5 s, so that a
    // wrong shutdown order fails instead of hanging).
    auto releasedByTimeout = std::make_shared<std::atomic<bool>>(false);
    AsyncCall releaser(
        [transport, pool, releasedByTimeout]()
        {
            if (!eventually([&] { return transport->stats().shutdown >= IN_FLIGHT; }, 5s))
            {
                releasedByTimeout->store(true);
            }
            pool->release();
        });

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    ASSERT_EQ(indexer_client::RuntimeOwner::beginShutdown(deadline), indexer_client::Cause::None);
    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    ASSERT_TRUE(releaser.wait(10s));
    EXPECT_FALSE(releasedByTimeout->load()) << "the transport did not stop while the pool was busy";
    EXPECT_TRUE(transport->stop(deadline)) << "stop() = true: finished within the 2 s deadline";

    EXPECT_EQ(collector->total(), BACKLOG + IN_FLIGHT);
    for (const auto& one : held)
    {
        ASSERT_EQ(collector->count(one.key), 1) << "in-flight key " << one.key;
        EXPECT_EQ(collector->result(one.key)->cause, TransportCause::Shutdown);
    }
    std::size_t wrong = 0;
    for (const auto& one : backlog)
    {
        if (collector->count(one.key) != 1)
        {
            ++wrong;
        }
    }
    EXPECT_EQ(wrong, 0u) << "backlog ids not delivered exactly once";
    EXPECT_EQ(collector->result(backlog.front().key)->cause, TransportCause::Connect);
    EXPECT_EQ(transport->stats().undelivered, 0u) << "a result the pool refused: its callback never ran";
}

// Eight threads keep submitting while the runtime shuts down. Every admitted id gets exactly one result, every
// refusal none, and each submitter, still running when the shutdown begins, ends refused with Shutdown. (ASAN clean
// in the sanitizer sibling.)
TEST_F(TransportTest, ShutdownWithConcurrentSubmitters)
{
    constexpr std::size_t SUBMITTERS = 8;
    constexpr std::size_t WINDOW = 2048; // Unresolved submissions per submitter: bounds memory, never the race.
    FakeIndexerOptions options;
    options.threads = 32;
    FakeIndexer fake(options);
    Rule slow; // Slow enough that the stop finds transfers in flight and queued inside curl.
    slow.latency = 2ms;
    fake.addRule(slow);
    fake.start();
    auto transport = startRuntime(2, 2);
    ASSERT_NE(transport, nullptr);
    const auto url = fake.baseUrl() + "/concurrent";

    /// One per submitter: its own collector (so its unresolved count is O(1)) and what it submitted.
    struct Submitter final
    {
        std::shared_ptr<Collector> collector {Collector::create()};
        std::vector<Submitted> all;
        std::size_t admitted {0};
        bool endedRefused {false};
    };
    std::vector<std::shared_ptr<Submitter>> states;
    auto admittedTotal = std::make_shared<std::atomic<std::size_t>>(0);
    std::vector<std::unique_ptr<AsyncCall>> submitters;
    for (std::size_t t = 0; t < SUBMITTERS; ++t)
    {
        auto state = std::make_shared<Submitter>();
        states.push_back(state);
        submitters.push_back(std::make_unique<AsyncCall>(
            [transport, state, url, admittedTotal]()
            {
                const auto until = std::chrono::steady_clock::now() + 30s;
                while (std::chrono::steady_clock::now() < until)
                {
                    if (state->admitted - state->collector->total() >= WINDOW)
                    {
                        state->collector->waitFor([&] { return state->admitted - state->collector->total() < WINDOW; },
                                                  10s);
                    }
                    const auto submitted = submitTo(*transport, state->collector, request(HttpMethod::Get, url));
                    state->all.push_back(submitted);
                    if (!submitted.admission.admitted)
                    {
                        state->endedRefused = submitted.admission.cause == indexer_client::Cause::Shutdown;
                        return;
                    }
                    ++state->admitted;
                    admittedTotal->fetch_add(1);
                }
            }));
    }
    ASSERT_TRUE(eventually([&] { return admittedTotal->load() >= 1000; }, 30s)) << "submitters are running";

    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    for (auto& submitter : submitters)
    {
        ASSERT_TRUE(submitter->wait(20s));
    }

    std::size_t admitted = 0;
    std::size_t lost = 0;
    std::size_t duplicated = 0;
    std::size_t refusedCalledBack = 0;
    std::size_t shutdownResults = 0;
    for (const auto& state : states)
    {
        EXPECT_TRUE(state->endedRefused) << "every submitter ends refused with Shutdown";
        for (const auto& one : state->all)
        {
            const auto count = state->collector->count(one.key);
            if (one.admission.admitted)
            {
                ++admitted;
                lost += count == 0 ? 1 : 0;
                duplicated += count > 1 ? 1 : 0;
                if (count == 1 && state->collector->result(one.key)->cause == TransportCause::Shutdown)
                {
                    ++shutdownResults;
                }
            }
            else
            {
                refusedCalledBack += count != 0 ? 1 : 0;
            }
        }
        EXPECT_EQ(state->collector->total(), state->admitted);
    }
    EXPECT_EQ(lost, 0u) << "admitted ids without a result (of " << admitted << ")";
    EXPECT_EQ(duplicated, 0u);
    EXPECT_EQ(refusedCalledBack, 0u);
    EXPECT_GT(shutdownResults, 0u) << "the stop found no submission in flight: the race was not exercised";
    EXPECT_EQ(transport->stats().undelivered, 0u) << "a result the pool refused: its callback never ran";
    std::cout << "[ INFO     ] admitted " << admitted << ", resolved by the stop " << shutdownResults << std::endl;
}

// A transfer stuck in name resolution (getaddrinfo hung for this one name) does not hold the shutdown:
// the multi is cleaned up with CURLMOPT_QUICK_EXIT, so curl does not join its resolver thread.
TEST_F(TransportTest, ShutdownWithHungResolver)
{
    armResolver();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one =
        submitTo(*transport, collector, request(HttpMethod::Get, std::string("http://") + HUNG_HOST + ":9200/"));
    ASSERT_TRUE(one.admission.admitted);
    {
        auto& resolver = hungResolver();
        std::unique_lock<std::mutex> lock(resolver.mutex);
        ASSERT_TRUE(resolver.cv.wait_for(lock, 10s, [&] { return resolver.entered >= 1; }))
            << "curl never called getaddrinfo for " << HUNG_HOST;
    }

    // Bound: if the shutdown waits for the resolver, it is let go after 5 s and the measure fails.
    AsyncCall watchdog(
        []()
        {
            auto& resolver = hungResolver();
            std::unique_lock<std::mutex> lock(resolver.mutex);
            if (!resolver.cv.wait_for(lock, 5s, [&] { return resolver.released; }))
            {
                lock.unlock();
                releaseResolver();
            }
        });
    const auto startedAt = std::chrono::steady_clock::now();
    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    const auto elapsed = std::chrono::steady_clock::now() - startedAt;
    {
        auto& resolver = hungResolver();
        std::lock_guard<std::mutex> lock(resolver.mutex);
        EXPECT_FALSE(resolver.released) << "the shutdown only finished once the resolver was let go";
    }
    releaseResolver();
    ASSERT_TRUE(watchdog.wait(10s));

    EXPECT_LT(elapsed, 2s) << "RuntimeOwner::shutdown() took "
                           << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
    ASSERT_EQ(collector->count(one.key), 1);
    EXPECT_EQ(collector->result(one.key)->cause, TransportCause::Shutdown);
}
