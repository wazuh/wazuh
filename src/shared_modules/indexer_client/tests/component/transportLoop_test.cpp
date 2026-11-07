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

// The network loop's own contracts (plan-E2a-1 §Tests, lot A: D27, D28): where callbacks run, the timer generation,
// a start that throws.

#include <dlfcn.h>

#include <atomic>
#include <iostream>
#include <stdexcept>

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
    // Timer handlers as the onTimerHandler seam reports them, and the timeout actions that follow them. Every
    // socket_action(CURL_SOCKET_TIMEOUT) of the loop comes from its timer handler, right after the seam, on the same
    // thread: a stale handler followed by one is a stale handler that reached curl.
    thread_local bool t_afterTimerHandler = false;
    thread_local bool t_lastHandlerStale = false;
    std::atomic<std::uint64_t> g_staleReachedCurl {0};
} // namespace

// Interposed (-rdynamic): watches which timer handlers call curl, then forwards to libcurl inside wazuhext.
extern "C" CURLMcode curl_multi_socket_action(CURLM* multi, curl_socket_t s, int evBitmask, int* runningHandles)
{
    using Real = CURLMcode (*)(CURLM*, curl_socket_t, int, int*);
    static const auto real = reinterpret_cast<Real>(dlsym(RTLD_NEXT, "curl_multi_socket_action"));
    if (s == CURL_SOCKET_TIMEOUT && t_afterTimerHandler && t_lastHandlerStale)
    {
        g_staleReachedCurl.fetch_add(1);
    }
    t_afterTimerHandler = false;
    return real(multi, s, evBitmask, runningHandles);
}

// D27: every result, whatever produced it, is delivered on a CPU-pool thread: a response, a refused connection, a
// cancellation, a start failure, a multi error and the stop's Shutdown.
TEST_F(TransportTest, CallbacksRunOnPoolThreads)
{
    FakeIndexerOptions options;
    options.threads = 32;
    FakeIndexer fake(options);
    Rule hold;
    hold.pathRegex = "/held.*";
    hold.hold = true;
    fake.addRule(hold);
    fake.start();
    auto transport = startRuntime(2, 3);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    std::vector<Submitted> all;
    const auto send = [&](HttpMethod method, const std::string& url)
    {
        all.push_back(submitTo(*transport, collector, request(method, url)));
        EXPECT_TRUE(all.back().admission.admitted);
        return all.back();
    };

    for (int i = 0; i < 6; ++i)
    {
        send(HttpMethod::Get, fake.baseUrl() + "/ok");
        send(HttpMethod::Post, fake.baseUrl() + "/ok");
    }
    send(HttpMethod::Get, "http://127.0.0.1:" + std::to_string(closedPort()) + "/refused");
    ASSERT_TRUE(collector->waitTotal(all.size(), 10s));

    const auto toCancel = send(HttpMethod::Get, fake.baseUrl() + "/held-cancel");
    ASSERT_TRUE(fake.waitHeld(1, 10s));
    ASSERT_TRUE(transport->cancel(toCancel.admission.id));
    ASSERT_TRUE(collector->waitKey(toCancel.key, 10s));

    auto throwOnce = std::make_shared<std::atomic<bool>>(true);
    hooks::setThrowOnAdd(
        [throwOnce]()
        {
            if (throwOnce->exchange(false))
            {
                throw std::runtime_error("injected");
            }
        });
    const auto failedStart = send(HttpMethod::Get, fake.baseUrl() + "/ok");
    ASSERT_TRUE(collector->waitKey(failedStart.key, 10s));

    auto failOnce = std::make_shared<std::atomic<bool>>(true);
    hooks::setInjectMultiError([failOnce](int rc) { return failOnce->exchange(false) ? CURLM_INTERNAL_ERROR : rc; });
    const auto multiError = send(HttpMethod::Get, fake.baseUrl() + "/ok");
    ASSERT_TRUE(collector->waitKey(multiError.key, 10s));

    const auto atShutdown = send(HttpMethod::Get, fake.baseUrl() + "/held-shutdown");
    ASSERT_TRUE(fake.waitHeld(2, 10s)); // The cancelled one is still held server-side.
    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);

    std::set<TransportCause> causes;
    const auto threads = collector->threads();
    for (const auto& one : all)
    {
        ASSERT_EQ(collector->count(one.key), 1) << "key " << one.key;
        const auto& name = threads.at(one.key);
        EXPECT_EQ(name.rfind("ic-cpu-", 0), 0u)
            << "callback of key " << one.key << " ("
            << indexer_client::detail::toString(collector->result(one.key)->cause) << ") ran on '" << name << "'";
        causes.insert(collector->result(one.key)->cause);
    }
    EXPECT_EQ(collector->result(failedStart.key)->cause, TransportCause::LocalError);
    EXPECT_EQ(collector->result(multiError.key)->cause, TransportCause::LocalError);
    EXPECT_EQ(collector->result(atShutdown.key)->cause, TransportCause::Shutdown);
    EXPECT_EQ(causes,
              (std::set<TransportCause> {TransportCause::None,
                                         TransportCause::Connect,
                                         TransportCause::Cancelled,
                                         TransportCause::LocalError,
                                         TransportCause::Shutdown}))
        << "every kind of result was delivered";
}

// D27, D28: a timer handler whose wait had already completed when curl changed its timeout (an older generation) must
// not call curl. Forced: a transfer with a short timeout is held by the server; the loop is kept busy past that
// timeout, so the timer's completion is already queued when a cancel (queued behind it in the same busy spell) makes
// curl drop the timeout. The seam counts the stale handlers; the interposed socket_action proves none reached curl.
TEST_F(TransportTest, StaleTimerNeverReachesCurl)
{
    FakeIndexer fake;
    Rule hold;
    hold.hold = true;
    fake.addRule(hold);
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    struct Timers final
    {
        std::atomic<std::uint64_t> handlers {0};
        std::atomic<std::uint64_t> stale {0};
    };
    auto timers = std::make_shared<Timers>();
    hooks::setOnTimerHandler(
        [timers](std::uint64_t generation, std::uint64_t current)
        {
            timers->handlers.fetch_add(1);
            const bool stale = generation != current;
            if (stale)
            {
                timers->stale.fetch_add(1);
            }
            t_afterTimerHandler = true;
            t_lastHandlerStale = stale;
        });
    const auto reachedBefore = g_staleReachedCurl.load();

    constexpr int ROUNDS = 5;
    for (int round = 0; round < ROUNDS; ++round)
    {
        SCOPED_TRACE("round " + std::to_string(round));
        fake.rearmHold();
        const auto one =
            submitTo(*transport,
                     collector,
                     request(HttpMethod::Get, fake.baseUrl() + "/stale", nullptr, indexer_client::Duration {200}));
        ASSERT_TRUE(one.admission.admitted);
        ASSERT_TRUE(fake.waitHeld(1, 10s));

        auto blocker = Blocker::create();
        ReleaseOnExit releaseBlocker(blocker);
        ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(blocker->task(), 0));
        ASSERT_TRUE(blocker->waitStarted(1, 5s));
        // Measured (scaled(): longer only widens the margin): the 200 ms timeout expires while the loop is busy.
        std::this_thread::sleep_for(scaled(400ms));
        ASSERT_TRUE(transport->cancel(one.admission.id));
        blocker->release();

        ASSERT_TRUE(collector->waitKey(one.key, 10s));
        EXPECT_EQ(collector->result(one.key)->cause, TransportCause::Cancelled);
        fake.releaseHeld();
        ASSERT_TRUE(eventually([&] { return fake.heldNow() == 0; }, 5s));
    }

    EXPECT_GT(timers->stale.load(), 0u) << "no stale timer handler: the race was not exercised (" << timers->handlers
                                        << " handlers)";
    EXPECT_EQ(g_staleReachedCurl.load() - reachedBefore, 0u) << "a stale timer handler called curl";
    std::cout << "[ INFO     ] timer handlers " << timers->handlers.load() << ", stale " << timers->stale.load()
              << std::endl;

    // The loop still runs its timers: a real timeout fires.
    fake.rearmHold();
    const auto late =
        submitTo(*transport,
                 collector,
                 request(HttpMethod::Get, fake.baseUrl() + "/slow", nullptr, indexer_client::Duration {150}));
    ASSERT_TRUE(collector->waitKey(late.key, 10s));
    EXPECT_EQ(collector->result(late.key)->cause, TransportCause::Timeout);
    fake.releaseHeld();
}

// D27: an exception thrown while starting (here, before curl_multi_add_handle) is not swallowed: the request gets
// its single result, LocalError with curl code 2, and the loop keeps working.
TEST_F(TransportTest, StartExceptionDeliversFailedInit)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    auto throwOnce = std::make_shared<std::atomic<bool>>(true);
    hooks::setThrowOnAdd(
        [throwOnce]()
        {
            if (throwOnce->exchange(false))
            {
                throw std::runtime_error("injected start failure");
            }
        });
    const auto failed = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/start"));
    ASSERT_TRUE(failed.admission.admitted);
    ASSERT_TRUE(collector->waitKey(failed.key, 10s)) << "the start failure was swallowed: no result";
    const auto result = collector->result(failed.key);
    EXPECT_EQ(result->cause, TransportCause::LocalError);
    EXPECT_EQ(result->curlCode, CURLE_FAILED_INIT);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_FALSE(result->mayHaveSent);
    EXPECT_EQ(sumOf(transport->stats().inFlightPerLoop), 0u);
    EXPECT_FALSE(fake.waitForRequests(1, 200ms)) << "the failed start sent nothing";

    const auto next = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/next"));
    ASSERT_TRUE(collector->waitKey(next.key, 10s));
    EXPECT_EQ(collector->result(next.key)->status, 200);
    EXPECT_EQ(collector->count(failed.key), 1);
}
