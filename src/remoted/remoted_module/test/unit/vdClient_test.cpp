/*
 * Wazuh remoted module - VdClient unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/vdClient.hpp"
#include "fakeVdServer.hpp"
#include "vdHttpClient.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using remoted::common::VdClient;
using remoted::test::FakeVdServer;
using remoted::test::makeUniqueVdSocketPath;
using remoted::test::makeVdHttpClient;

namespace
{
    // Generously wide relative to a single local UDS round trip (single-digit ms), to stay clear
    // of scheduling jitter on a loaded machine while still keeping the suite fast. Cache TTL is
    // deliberately longer than the failure-retry interval, same as production (30s vs 5s), so
    // FailedAttemptGatesRetriesToFailureIntervalThenRecovers can actually distinguish "gated by
    // the short failure interval" from "gated by the long normal TTL" after recovery.
    constexpr auto TEST_CACHE_TTL = 400ms;
    constexpr auto TEST_FAILURE_RETRY_INTERVAL = 120ms;
} // namespace

TEST(VdClientTest, FreshInstanceQueriesVdOnFirstCall)
{
    const auto socketPath = makeUniqueVdSocketPath("fresh");
    FakeVdServer server(socketPath);
    server.setOffset(12345);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_EQ(client.getOffset(), 12345u);
    EXPECT_EQ(server.offsetRequestCount(), 1u);
}

TEST(VdClientTest, CachedValueServedWithoutRequeryingWithinTtl)
{
    const auto socketPath = makeUniqueVdSocketPath("cachehit");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_EQ(client.getOffset(), 100u);
    ASSERT_EQ(server.offsetRequestCount(), 1u);

    // Change what the server would return; a cached call must not observe it yet.
    server.setOffset(999);
    EXPECT_EQ(client.getOffset(), 100u);
    EXPECT_EQ(server.offsetRequestCount(), 1u) << "cache hit must not re-query VD";
}

TEST(VdClientTest, CacheExpiresAfterTtlAndRequeries)
{
    const auto socketPath = makeUniqueVdSocketPath("expiry");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_EQ(client.getOffset(), 100u);
    ASSERT_EQ(server.offsetRequestCount(), 1u);

    server.setOffset(200);
    std::this_thread::sleep_for(TEST_CACHE_TTL + 20ms);

    EXPECT_EQ(client.getOffset(), 200u);
    EXPECT_EQ(server.offsetRequestCount(), 2u) << "expired cache must trigger a fresh query";
}

TEST(VdClientTest, FailedQueryWithNoPriorValueReturnsZero)
{
    // Nothing is listening on this path.
    const auto socketPath = makeUniqueVdSocketPath("nolistener");
    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_EQ(client.getOffset(), 0u);
}

TEST(VdClientTest, FailedQueryFallsBackToLastKnownGoodOffset)
{
    const auto socketPath = makeUniqueVdSocketPath("staleok");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);
    EXPECT_EQ(client.getOffset(), 100u);

    server.setOffsetFailure(500);
    std::this_thread::sleep_for(TEST_CACHE_TTL + 20ms);

    EXPECT_EQ(client.getOffset(), 100u) << "a transient failure must not discard the last known-good offset";
}

TEST(VdClientTest, FailedAttemptGatesRetriesToFailureIntervalThenRecovers)
{
    const auto socketPath = makeUniqueVdSocketPath("gating");
    FakeVdServer server(socketPath);
    server.setOffsetFailure(500);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_EQ(client.getOffset(), 0u);
    ASSERT_EQ(server.offsetRequestCount(), 1u);

    // Well within the failure-retry interval: must NOT attempt another query.
    std::this_thread::sleep_for(TEST_FAILURE_RETRY_INTERVAL / 4);
    EXPECT_EQ(client.getOffset(), 0u);
    EXPECT_EQ(server.offsetRequestCount(), 1u) << "must not retry more often than failureRetryInterval";

    // Past the failure-retry interval, and VD is healthy again: must retry and recover.
    server.setOffset(555);
    std::this_thread::sleep_for(TEST_FAILURE_RETRY_INTERVAL + 50ms);

    EXPECT_EQ(client.getOffset(), 555u);
    EXPECT_EQ(server.offsetRequestCount(), 2u);

    // Recovery must also clear the failure state: the next TTL window is the normal (longer)
    // cache TTL again, not the short failure-retry interval.
    std::this_thread::sleep_for(TEST_FAILURE_RETRY_INTERVAL + 50ms);
    EXPECT_EQ(client.getOffset(), 555u);
    EXPECT_EQ(server.offsetRequestCount(), 2u)
        << "after recovery, caching must follow cacheTtl again, not the short failure interval";
}

TEST(VdClientTest, AnswerWithoutEnabledFieldIsEnabled)
{
    const auto socketPath = makeUniqueVdSocketPath("enabledabsent");
    FakeVdServer server(socketPath);
    server.setOffset(42);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    const auto state = client.getFeedState();
    EXPECT_EQ(state.offset, 42u);
    EXPECT_TRUE(state.enabled);
}

TEST(VdClientTest, DisabledVdIsReportedAndCached)
{
    const auto socketPath = makeUniqueVdSocketPath("disabled");
    FakeVdServer server(socketPath);
    server.setOffsetHandler([](const httplib::Request&, httplib::Response& res)
                            { res.set_content(R"({"offset":0,"enabled":false})", "application/json"); });

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    EXPECT_FALSE(client.getFeedState().enabled);
    // Served from the cache: the enablement is part of the cached answer, not re-queried.
    EXPECT_FALSE(client.getFeedState().enabled);
    EXPECT_EQ(server.offsetRequestCount(), 1u);
}

TEST(VdClientTest, FailedQueryKeepsLastKnownEnablement)
{
    const auto socketPath = makeUniqueVdSocketPath("disabledstale");
    FakeVdServer server(socketPath);
    server.setOffsetHandler([](const httplib::Request&, httplib::Response& res)
                            { res.set_content(R"({"offset":0,"enabled":false})", "application/json"); });

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);
    EXPECT_FALSE(client.getFeedState().enabled);

    server.setOffsetFailure(500);
    std::this_thread::sleep_for(TEST_CACHE_TTL + 20ms);

    EXPECT_FALSE(client.getFeedState().enabled) << "a transient failure must not re-enable a disabled VD";
}

TEST(VdClientTest, NeverAnsweredVdIsNotReportedDisabled)
{
    const auto socketPath = makeUniqueVdSocketPath("neveranswered");
    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    const auto state = client.getFeedState();
    EXPECT_EQ(state.offset, 0u);
    EXPECT_TRUE(state.enabled);
}

TEST(VdClientTest, NonBooleanEnabledFieldIsEnabled)
{
    const auto socketPath = makeUniqueVdSocketPath("enabledbadtype");
    FakeVdServer server(socketPath);
    server.setOffsetHandler([](const httplib::Request&, httplib::Response& res)
                            { res.set_content(R"({"offset":7,"enabled":"no"})", "application/json"); });

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    const auto state = client.getFeedState();
    EXPECT_EQ(state.offset, 7u);
    EXPECT_TRUE(state.enabled);
}

TEST(VdClientTest, ConcurrentCallerDuringInFlightRefreshIsNeverBlocked)
{
    const auto socketPath = makeUniqueVdSocketPath("singleflight");
    FakeVdServer server(socketPath);

    constexpr auto SERVER_DELAY = 300ms;
    server.setOffsetHandler(
        [SERVER_DELAY](const httplib::Request&, httplib::Response& res)
        {
            std::this_thread::sleep_for(SERVER_DELAY);
            res.set_content(R"({"offset":777})", "application/json");
        });

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);

    // Thread A: fresh client, cache is empty, so this call becomes the in-flight refresher and
    // blocks in the (slow) network call for SERVER_DELAY.
    std::thread refresher([&client] { client.getOffset(); });

    // Give A a head start so it wins the single-flight race before B calls in.
    std::this_thread::sleep_for(50ms);

    const auto start = std::chrono::steady_clock::now();
    const auto piggybackResult = client.getOffset();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    refresher.join();

    EXPECT_LT(elapsed, SERVER_DELAY / 2)
        << "a concurrent caller must never block behind an in-flight refresh -- it should get the "
           "current best-known value immediately instead of queuing behind the network call";
    EXPECT_EQ(piggybackResult, 0u) << "no value was ever successfully obtained yet, so the piggyback call falls "
                                      "back to 0, exactly like a solo failed/pending call would";
    EXPECT_EQ(server.offsetRequestCount(), 1u)
        << "only the winning caller should have actually queried VD -- no duplicate network calls";

    // After the refresher completes, the value is cached and visible to everyone.
    EXPECT_EQ(client.getOffset(), 777u);
}

TEST(VdClientTest, RejectsANullHttpClient)
{
    EXPECT_THROW(VdClient(nullptr, makeUniqueVdSocketPath("null")), std::invalid_argument);
}

TEST(VdClientTest, AnOversizedOffsetAnswerIsAFailedQuery)
{
    const auto socketPath = makeUniqueVdSocketPath("oversized");
    FakeVdServer server(socketPath);
    server.setOffset(100);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);
    ASSERT_EQ(client.getOffset(), 100u);

    // Valid JSON carrying a different offset, but past the response cap: had it been read, the offset
    // would now be 200.
    const std::string padding(VdClient::MAX_RESPONSE_BODY_BYTES, 'x');
    server.setOffsetHandler(
        [&padding](const httplib::Request&, httplib::Response& res)
        { res.set_content(R"({"offset":200,"padding":")" + padding + R"("})", "application/json"); });
    std::this_thread::sleep_for(TEST_CACHE_TTL + 20ms);

    EXPECT_EQ(client.getOffset(), 100u) << "an answer over the cap must fail the query and keep the last offset";
    EXPECT_EQ(server.offsetRequestCount(), 2u);
}

TEST(VdClientTest, AMissingSocketKeepsTheLastKnownOffset)
{
    const auto socketPath = makeUniqueVdSocketPath("gone");
    auto server = std::make_unique<FakeVdServer>(socketPath);
    server->setOffset(100);

    VdClient client(makeVdHttpClient(), socketPath, TEST_CACHE_TTL, TEST_FAILURE_RETRY_INTERVAL);
    ASSERT_EQ(client.getOffset(), 100u);

    server.reset(); // VD stops: nothing listens on the socket any more
    std::this_thread::sleep_for(TEST_CACHE_TTL + 20ms);

    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(client.getOffset(), 100u);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::milliseconds {VdClient::CONNECT_TIMEOUT_MS})
        << "a scanner that is not running is a refused connection, answered at once";
}
