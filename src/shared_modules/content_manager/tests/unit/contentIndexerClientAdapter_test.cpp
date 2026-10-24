/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The indexer_client adapter of IContentIndexer (E9, I153-I159) on a real runtime over the library's fake indexer.

#include "fakes/realIndexerFixture.hpp"
#include "gtest/gtest.h"
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using cmtest::docSort;
using cmtest::matchAll;
using cmtest::numbersOf;
using cmtest::RealIndexer;
using cmtest::RealIndexerOptions;
using cmtest::waitUntil;
using content_manager::ContentIndexerOptions;
using content_manager::ContentPit;
using content_manager::IContentIndexer;
using indexer_client::testing::PitCall;
using indexer_client::testing::PitRequestView;
using indexer_client::testing::PitResponder;
using indexer_client::testing::Rule;

namespace
{
    /// Answers every PIT search with @p status and @p body.
    void answerSearchesWith(RealIndexer& env, int status, std::string body)
    {
        env.pits->intercept(
            [status, body = std::move(body)](const PitRequestView& view, Rule& reply)
            {
                if (view.call != PitCall::Search)
                {
                    return false;
                }
                reply.status = status;
                reply.body = body;
                return true;
            });
    }

    /// Holds the answer of the @p ordinal-th PIT search until FakeIndexer::releaseHeld(); the rest is normal.
    void holdSearch(RealIndexer& env, std::size_t ordinal)
    {
        env.pits->intercept(
            [ordinal](const PitRequestView& view, Rule& reply)
            {
                if (view.call == PitCall::Search && view.ordinal == ordinal)
                {
                    reply.hold = true;
                }
                return false;
            });
    }

    /// Options with short deadlines, so a hung call fails the test by deadline instead of hanging it.
    ContentIndexerOptions shortOptions()
    {
        ContentIndexerOptions options;
        options.callDeadline = 5s;
        options.pageDeadline = 4s;
        options.probeDeadline = 2s;
        return options;
    }

    ContentPit unknownPit()
    {
        return ContentPit {"never-opened", 0, "5m"};
    }
} // namespace

// ---------------------------------------------------------------- CA-E9-1

TEST(ContentIndexerClientAdapter, OpenSearchClose)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"a", "b"}, "5m", true);
    EXPECT_EQ(pit.id.rfind("cm-pit-", 0), 0U) << pit.id;

    const auto creates = env.createRequests();
    ASSERT_EQ(creates.size(), 1U);
    EXPECT_EQ(creates.front().method, "POST");
    EXPECT_EQ(creates.front().path, "/a,b/_search/point_in_time");
    EXPECT_EQ(creates.front().target, "/a,b/_search/point_in_time?keep_alive=300000ms&expand_wildcards=all");

    const std::string wirePitId = env.pits->currentId(1);
    EXPECT_NE(pit.id, wirePitId) << "ContentPit.id is an opaque key, not the PIT id";

    const nlohmann::json source {{"includes", nlohmann::json::array({"n"})}};
    const nlohmann::json slice {{"id", 0}, {"max", 2}};

    // First page: no cursor, so the total is tracked.
    const auto first = adapter->search(pit, 3, matchAll(), docSort(), std::nullopt, source, slice);
    EXPECT_EQ(numbersOf(first), (std::vector<std::int64_t> {1, 3, 5}));

    // Second page: continues after the sort of the last hit.
    const auto second = adapter->search(pit, 3, matchAll(), docSort(), nlohmann::json::array({5}), source, slice);
    EXPECT_EQ(numbersOf(second), (std::vector<std::int64_t> {7, 9, 11}));

    const auto searches = env.searchRequests();
    ASSERT_EQ(searches.size(), 2U);
    const auto body1 = RealIndexer::bodyOf(searches[0]);
    EXPECT_EQ(body1.at("size"), 3);
    EXPECT_EQ(body1.at("query"), matchAll());
    EXPECT_EQ(body1.at("sort"), docSort());
    EXPECT_EQ(body1.at("track_total_hits"), true);
    EXPECT_FALSE(body1.contains("search_after"));
    EXPECT_EQ(body1.at("_source"), source);
    EXPECT_EQ(body1.at("slice"), slice);
    EXPECT_EQ(body1.at("pit").at("id"), wirePitId);

    const auto body2 = RealIndexer::bodyOf(searches[1]);
    EXPECT_EQ(body2.at("size"), 3);
    EXPECT_EQ(body2.at("search_after"), nlohmann::json::array({5}));
    EXPECT_FALSE(body2.contains("track_total_hits"));
    EXPECT_EQ(body2.at("_source"), source);
    EXPECT_EQ(body2.at("slice"), slice);
    EXPECT_EQ(body2.at("pit").at("id"), wirePitId);

    // The PIT is deleted in the background once the adapter lets go of it.
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 0U);
    adapter->closePit(pit);
    ASSERT_TRUE(env.waitDeletes(1)) << "no DELETE within 2 s of closePit";
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 1U);
    EXPECT_EQ(env.pits->created(), 1U);
    EXPECT_EQ(env.pits->deleted(), 1U);
}

// ---------------------------------------------------------------- CA-E9-2 (CA-23)

TEST(ContentIndexerClientAdapter, RetriesSamePageSamePit)
{
    RealIndexer env;
    // A 429 on the second page, once; the library retries it on its own.
    env.pits->intercept(
        [](const PitRequestView& view, Rule& reply)
        {
            if (view.call == PitCall::Search && view.ordinal == 2)
            {
                reply.status = 429;
                reply.body = R"({"error":{"type":"too_many_requests","reason":"slow down"},"status":429})";
                return true;
            }
            return false;
        });
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    const auto page1 = adapter->search(pit, 5, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
    ASSERT_EQ(numbersOf(page1).size(), 5U);
    const auto page2 =
        adapter->search(pit, 5, matchAll(), docSort(), nlohmann::json::array({5}), std::nullopt, std::nullopt);
    EXPECT_EQ(numbersOf(page2), (std::vector<std::int64_t> {6, 7, 8, 9, 10}));

    const auto searches = env.searchRequests();
    ASSERT_EQ(searches.size(), 3U) << "page 1, then page 2 twice";
    const auto failed = RealIndexer::bodyOf(searches[1]);
    const auto retried = RealIndexer::bodyOf(searches[2]);
    EXPECT_EQ(failed.at("pit").at("id"), retried.at("pit").at("id"));
    EXPECT_EQ(failed.at("search_after"), nlohmann::json::array({5}));
    EXPECT_EQ(retried.at("search_after"), nlohmann::json::array({5}));
    EXPECT_EQ(env.pits->created(), 1U) << "a retried page must not create a new PIT";
    EXPECT_EQ(env.createRequests().size(), 1U);

    adapter->closePit(pit);
}

// ---------------------------------------------------------------- CA-E9-3 (T7b)

TEST(ContentIndexerClientAdapter, TwoSlicesOnePit)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);

    // Slice 0 reads to its end and stops; slice 1 starts later. Both go through the one PIT.
    const auto sliceZero = adapter->search(
        pit, 200, matchAll(), docSort(), std::nullopt, std::nullopt, nlohmann::json {{"id", 0}, {"max", 2}});
    EXPECT_EQ(sliceZero.at("hits").size(), 150U);
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 0U) << "the PIT is still in use";

    const auto sliceOne = adapter->search(
        pit, 200, matchAll(), docSort(), std::nullopt, std::nullopt, nlohmann::json {{"id", 1}, {"max", 2}});
    EXPECT_EQ(sliceOne.at("hits").size(), 150U);

    const auto searches = env.searchRequests();
    ASSERT_EQ(searches.size(), 2U);
    EXPECT_EQ(RealIndexer::bodyOf(searches[0]).at("pit").at("id"), RealIndexer::bodyOf(searches[1]).at("pit").at("id"));

    adapter->closePit(pit);
    ASSERT_TRUE(env.waitDeletes(1));
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(env.pits->created(), 1U);
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 1U);
    EXPECT_EQ(env.pits->deleted(), 1U);
}

TEST(ContentIndexerClientAdapter, ConcurrentSlices)
{
    RealIndexer env;
    holdSearch(env, 1);
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    // A short callDeadline: an adapter that serializes the requests fails by deadline instead of hanging.
    auto adapter = env.adapter(shortOptions());

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    const auto searchSlice = [&](int id)
    {
        return std::async(std::launch::async,
                          [&adapter, pit, id]
                          {
                              return adapter->search(pit,
                                                     10,
                                                     matchAll(),
                                                     docSort(),
                                                     std::nullopt,
                                                     std::nullopt,
                                                     nlohmann::json {{"id", id}, {"max", 2}});
                          });
    };

    // The first search is held at the fake until the second one has arrived: only concurrent requests get through.
    auto first = searchSlice(0);
    ASSERT_TRUE(env.fake->waitHeld(1, 3s)) << "the first search never reached the fake";
    auto second = searchSlice(1);
    const bool bothArrived = waitUntil([&] { return env.searches() == 2; }, 2s);
    env.fake->releaseHeld();
    ASSERT_TRUE(bothArrived) << "the second search was not sent while the first was in flight";

    ASSERT_EQ(first.wait_for(5s), std::future_status::ready);
    ASSERT_EQ(second.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(numbersOf(first.get()), (std::vector<std::int64_t> {1, 3, 5, 7, 9, 11, 13, 15, 17, 19}));
    EXPECT_EQ(numbersOf(second.get()), (std::vector<std::int64_t> {2, 4, 6, 8, 10, 12, 14, 16, 18, 20}));

    adapter->closePit(pit);
}

TEST(ContentIndexerClientAdapter, CloseDuringSearch)
{
    RealIndexer env;
    holdSearch(env, 1);
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    auto inFlight = std::async(
        std::launch::async,
        [&adapter, pit]
        { return adapter->search(pit, 4, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt); });
    ASSERT_TRUE(env.fake->waitHeld(1, 3s));

    adapter->closePit(pit);
    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 0U) << "the PIT must outlive the search in flight";

    env.fake->releaseHeld();
    ASSERT_EQ(inFlight.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(numbersOf(inFlight.get()), (std::vector<std::int64_t> {1, 2, 3, 4}));
    ASSERT_TRUE(env.waitDeletes(1)) << "the DELETE must follow the response";
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 1U);
}

// ---------------------------------------------------------------- CA-E9-4

TEST(ContentIndexerClientAdapter, ExpiredThrows)
{
    RealIndexer env;
    answerSearchesWith(env, 404, PitResponder::contextMissingBody("pit-1"));
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    try
    {
        adapter->search(pit, 5, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
        FAIL() << "an expired PIT must throw";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find(indexer_client::toString(indexer_client::Cause::PitExpired)),
                  std::string::npos)
            << e.what();
    }
    EXPECT_THROW(adapter->search(pit, 5, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt),
                 std::runtime_error);
    EXPECT_NO_THROW(adapter->closePit(pit));
}

TEST(ContentIndexerClientAdapter, UnknownPitThrows)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    try
    {
        adapter->search(unknownPit(), 5, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
        FAIL() << "an unknown key must throw";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find("Unknown PIT"), std::string::npos) << e.what();
    }
    EXPECT_EQ(env.searches(), 0U) << "an unknown key must not reach the indexer";
}

TEST(ContentIndexerClientAdapter, SearchWithoutHitsThrows)
{
    RealIndexer env;
    answerSearchesWith(env, 200, R"({"pit_id":"pit-1","took":1,"timed_out":false})");
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    try
    {
        adapter->search(pit, 5, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
        FAIL() << "a response without hits must throw";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find("hits"), std::string::npos) << e.what();
    }
    adapter->closePit(pit);
}

TEST(ContentIndexerClientAdapter, SearchIndexReturnsHits)
{
    RealIndexer env;
    // A rule of its own: a route without one answers 200 `{}`. It precedes the default one.
    Rule rule;
    rule.method = "POST";
    rule.pathRegex = "/consumers/_search";
    rule.body = R"({"took":1,"timed_out":false,"hits":{"total":{"value":1,"relation":"eq"},)"
                R"("hits":[{"_index":"consumers","_id":"c1","_source":{"status":"ready"}}]}})";
    env.fake->addRule(std::move(rule));
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const nlohmann::json query {{"ids", {{"values", nlohmann::json::array({"c1"})}}}};
    const nlohmann::json source {{"includes", nlohmann::json::array({"status"})}};
    const auto hits = adapter->searchIndex("consumers", 1, query, source);

    ASSERT_TRUE(hits.contains("hits"));
    ASSERT_EQ(hits.at("hits").size(), 1U);
    EXPECT_EQ(hits.at("hits").at(0).at("_id"), "c1");
    EXPECT_EQ(hits.at("total").at("value"), 1);

    bool seen = false;
    for (const auto& request : env.fake->requests())
    {
        if (request.method == "POST" && request.path == "/consumers/_search")
        {
            const auto body = RealIndexer::bodyOf(request);
            EXPECT_EQ(body.at("size"), 1);
            EXPECT_EQ(body.at("query"), query);
            EXPECT_EQ(body.at("_source"), source);
            seen = true;
        }
    }
    EXPECT_TRUE(seen);
    EXPECT_EQ(env.pits->created(), 0U) << "searchIndex must not pay for a PIT";
}

TEST(ContentIndexerClientAdapter, BadKeepAliveThrows)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    EXPECT_THROW(adapter->openPit({"idx"}, "5x", false), std::invalid_argument);
    EXPECT_THROW(adapter->openPit({"idx"}, "", false), std::invalid_argument);
    EXPECT_THROW(adapter->openPit({"idx"}, "0ms", false), std::invalid_argument);
    EXPECT_EQ(env.createRequests().size(), 0U) << "an invalid keep-alive must not reach the indexer";
}

TEST(ContentIndexerClientAdapter, NullClientThrows)
{
    EXPECT_THROW(content_manager::makeContentIndexer(std::shared_ptr<indexer_client::IClient> {}),
                 std::invalid_argument);
}

TEST(ContentIndexerClientAdapter, NullQueryThrows)
{
    auto client = std::make_shared<cmtest::NullQueryClient>();
    ASSERT_EQ(client->query(), nullptr);
    EXPECT_THROW(content_manager::makeContentIndexer(std::shared_ptr<indexer_client::IClient> {client}),
                 std::invalid_argument);
}

TEST(ContentIndexerClientAdapter, CloseNeverThrows)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    EXPECT_NO_THROW(adapter->closePit(pit));
    EXPECT_NO_THROW(adapter->closePit(pit)) << "a second close is a no-op";
    EXPECT_NO_THROW(adapter->closePit(unknownPit()));
    ASSERT_TRUE(env.waitDeletes(1));
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(env.pits->requests(PitCall::Delete), 1U);
}

// ---------------------------------------------------------------- CA-E9-6 (I158, I158b)

TEST(ContentIndexerClientAdapter, NoUsableNodeBoundedByProbe)
{
    RealIndexerOptions options;
    options.health = indexer_client::testing::healthStatusRule(503); // the node is Down for good
    RealIndexer env {options};
    env.startRuntime();
    ASSERT_TRUE(env.makeClient(false)) << env.startError;

    ContentIndexerOptions adapterOptions;
    adapterOptions.probeDeadline = 300ms;
    adapterOptions.callDeadline = 3s;
    adapterOptions.pageDeadline = 3s;
    auto adapter = env.adapter(adapterOptions);

    ASSERT_FALSE(env.client->health().anyUsable());
    auto started = std::chrono::steady_clock::now();
    EXPECT_THROW(adapter->openPit({"idx"}, "5m", false), std::runtime_error);
    EXPECT_LE(std::chrono::steady_clock::now() - started, 300ms + 500ms) << "the wait must end at probeDeadline";

    started = std::chrono::steady_clock::now();
    EXPECT_THROW(adapter->searchIndex("consumers", 1, matchAll(), std::nullopt), std::runtime_error);
    EXPECT_LE(std::chrono::steady_clock::now() - started, 300ms + 500ms);

    EXPECT_EQ(env.nonProbeRequests(), 0U) << "nothing is sent while no node is usable (health probes do not count)";
}

TEST(ContentIndexerClientAdapter, FirstCallWaitsForFirstProbe)
{
    RealIndexerOptions options;
    options.health.latency = 600ms; // the first probe round is slow: every node is Down until it answers
    RealIndexer env {options};
    env.startRuntime();
    ASSERT_TRUE(env.makeClient(false)) << env.startError;

    ContentIndexerOptions adapterOptions;
    adapterOptions.probeDeadline = 5s;
    adapterOptions.callDeadline = 10s;
    auto adapter = env.adapter(adapterOptions);

    ASSERT_FALSE(env.client->health().anyUsable()) << "the call must start before the first probe answered";
    ContentPit pit;
    ASSERT_NO_THROW(pit = adapter->openPit({"idx"}, "5m", false));
    EXPECT_TRUE(env.client->health().anyUsable());
    EXPECT_EQ(env.pits->created(), 1U);
    adapter->closePit(pit);
}

TEST(ContentIndexerClientAdapter, RequestCloseWakesSearch)
{
    RealIndexer env;
    holdSearch(env, 1);
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter(); // default deadlines: only requestClose() can end the call in time

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    auto inFlight = std::async(
        std::launch::async,
        [&adapter, pit] { adapter->search(pit, 4, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt); });
    ASSERT_TRUE(env.fake->waitHeld(1, 3s));

    const auto closed = std::chrono::steady_clock::now();
    env.client->requestClose();
    ASSERT_EQ(inFlight.wait_for(1s), std::future_status::ready) << "requestClose() must wake the search";
    EXPECT_LE(std::chrono::steady_clock::now() - closed, 1s);
    try
    {
        inFlight.get();
        FAIL() << "a search woken by requestClose() must throw";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find("client_closed"), std::string::npos) << e.what();
    }
}

TEST(ContentIndexerClientAdapter, ClientClosedThrows)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter(shortOptions());

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    env.client->requestClose();

    const auto expectClosed = [](const char* what, const std::function<void()>& call)
    {
        try
        {
            call();
            ADD_FAILURE() << what << " must throw after requestClose()";
        }
        catch (const std::runtime_error& e)
        {
            EXPECT_NE(std::string {e.what()}.find("client_closed"), std::string::npos) << what << ": " << e.what();
        }
    };
    expectClosed("openPit", [&] { adapter->openPit({"idx"}, "5m", false); });
    expectClosed("search",
                 [&] { adapter->search(pit, 4, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt); });
    expectClosed("searchIndex", [&] { adapter->searchIndex("consumers", 1, matchAll(), std::nullopt); });
    EXPECT_NO_THROW(adapter->closePit(pit)) << "closing is silent after requestClose()";
}

TEST(ContentIndexerClientAdapter, ReleasesConsumerName)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();
    const auto pit = adapter->openPit({"idx"}, "5m", false);

    // (i) The adapter is alive: it keeps the host's Client, so the consumer name stays reserved.
    env.client.reset();
    {
        auto again = env.ref.client(cmtest::CONSUMER_NAME, {});
        EXPECT_FALSE(again.ok()) << "the name must stay reserved while the adapter lives";
        EXPECT_EQ(again.cause, indexer_client::Cause::InvalidArgument) << again.reason;
    }

    // (ii) The adapter, its sessions and the host's Client are gone: the name is free again.
    adapter.reset();
    std::shared_ptr<indexer_client::Client> reborn;
    const bool freed = waitUntil(
        [&]
        {
            auto outcome = env.ref.client(cmtest::CONSUMER_NAME, {});
            if (outcome.ok())
            {
                reborn = outcome.value;
            }
            return outcome.ok();
        },
        5s);
    EXPECT_TRUE(freed) << "the consumer name must be released once the adapter is dropped";
    env.client = reborn;
    (void)pit;
}

// ---------------------------------------------------------------- G-diff additions (E9 step 5)

TEST(ContentIndexerClientAdapter, ReleasesConsumerNameWithoutPit)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    // No PIT was ever opened: the adapter itself keeps the host's Client (the host lets go of its own).
    env.client.reset();
    {
        auto again = env.ref.client(cmtest::CONSUMER_NAME, {});
        EXPECT_FALSE(again.ok()) << "the name must stay reserved while the adapter lives";
        EXPECT_EQ(again.cause, indexer_client::Cause::InvalidArgument) << again.reason;
    }

    adapter.reset();
    std::shared_ptr<indexer_client::Client> reborn;
    const bool freed = waitUntil(
        [&]
        {
            auto outcome = env.ref.client(cmtest::CONSUMER_NAME, {});
            if (outcome.ok())
            {
                reborn = outcome.value;
            }
            return outcome.ok();
        },
        5s);
    EXPECT_TRUE(freed) << "the consumer name must be released once the adapter is dropped";
    env.client = reborn;
}

TEST(ContentIndexerClientAdapter, TwoPitsOneAdapter)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto pitA = adapter->openPit({"idx"}, "5m", false);
    const auto pitB = adapter->openPit({"idx"}, "5m", false);
    EXPECT_NE(pitA.id, pitB.id) << "every open PIT has its own key";
    const std::string wireA = env.pits->currentId(1);
    const std::string wireB = env.pits->currentId(2);
    ASSERT_NE(wireA, wireB);

    adapter->search(pitA, 2, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
    adapter->search(pitB, 2, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
    auto searches = env.searchRequests();
    ASSERT_EQ(searches.size(), 2U);
    EXPECT_EQ(RealIndexer::bodyOf(searches[0]).at("pit").at("id"), wireA);
    EXPECT_EQ(RealIndexer::bodyOf(searches[1]).at("pit").at("id"), wireB);

    // Closing one leaves the other usable, and only the closed one is deleted.
    adapter->closePit(pitA);
    ASSERT_TRUE(env.waitDeletes(1));
    EXPECT_THROW(adapter->search(pitA, 2, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt),
                 std::runtime_error);
    EXPECT_NO_THROW(adapter->search(pitB, 2, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt));
    searches = env.searchRequests();
    ASSERT_EQ(searches.size(), 3U);
    EXPECT_EQ(RealIndexer::bodyOf(searches[2]).at("pit").at("id"), wireB);

    std::string deleted;
    for (const auto& request : env.fake->requests())
    {
        if (request.method == "DELETE")
        {
            deleted += request.body;
        }
    }
    EXPECT_NE(deleted.find(wireA), std::string::npos) << deleted;
    EXPECT_EQ(deleted.find(wireB), std::string::npos) << deleted;

    adapter->closePit(pitB);
    ASSERT_TRUE(env.waitDeletes(2));
}

TEST(ContentIndexerClientAdapter, PageDeadlineFromOptions)
{
    RealIndexer env;
    holdSearch(env, 1);
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    ContentIndexerOptions options;
    options.callDeadline = 5s;
    options.pageDeadline = 400ms;
    options.probeDeadline = 2s;
    auto adapter = env.adapter(options);

    const auto pit = adapter->openPit({"idx"}, "5m", false);
    const auto started = std::chrono::steady_clock::now();
    try
    {
        adapter->search(pit, 4, matchAll(), docSort(), std::nullopt, std::nullopt, std::nullopt);
        FAIL() << "a page held past pageDeadline must fail";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find("page deadline"), std::string::npos) << e.what();
    }
    EXPECT_LT(std::chrono::steady_clock::now() - started, 3s)
        << "the page deadline must end the call before callDeadline";
}

TEST(ContentIndexerClientAdapter, SearchIndexUsesProbeDeadline)
{
    RealIndexer env;
    Rule held;
    held.method = "POST";
    held.pathRegex = "/consumers/_search";
    held.hold = true;
    env.fake->addRule(std::move(held));
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    ContentIndexerOptions options;
    options.callDeadline = 8s;
    options.pageDeadline = 8s;
    options.probeDeadline = 500ms;
    auto adapter = env.adapter(options);

    const auto started = std::chrono::steady_clock::now();
    EXPECT_THROW(adapter->searchIndex("consumers", 1, matchAll(), std::nullopt), std::runtime_error);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, 400ms);
    EXPECT_LT(elapsed, 3s) << "searchIndex is bounded by probeDeadline, not callDeadline";
}

TEST(ContentIndexerClientAdapter, KeepAliveUnits)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const std::vector<std::pair<std::string, std::string>> cases {{"5000000nanos", "5"},
                                                                  {"3000micros", "3"},
                                                                  {"7ms", "7"},
                                                                  {"2s", "2000"},
                                                                  {"2m", "120000"},
                                                                  {"1h", "3600000"},
                                                                  {"1d", "86400000"}};
    std::size_t opened {0};
    for (const auto& [keepAlive, millis] : cases)
    {
        const auto pit = adapter->openPit({"idx"}, keepAlive, false);
        ++opened;
        const auto creates = env.createRequests();
        ASSERT_EQ(creates.size(), opened);
        EXPECT_EQ(creates.back().target, "/idx/_search/point_in_time?keep_alive=" + millis + "ms")
            << "keepAlive " << keepAlive;
        EXPECT_EQ(pit.keepAlive, keepAlive);
        adapter->closePit(pit);
    }
}

TEST(ContentIndexerClientAdapter, SearchIndexWithoutHitsIsEmpty)
{
    RealIndexer env;
    Rule rule;
    rule.method = "POST";
    rule.pathRegex = "/consumers/_search";
    rule.body = R"({"took":1,"timed_out":false})";
    env.fake->addRule(std::move(rule));
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const auto hits = adapter->searchIndex("consumers", 1, matchAll(), std::nullopt);
    EXPECT_TRUE(hits.is_object());
    EXPECT_TRUE(hits.empty()) << hits.dump();
}

TEST(ContentIndexerClientAdapter, ThrottledNodeIsUsable)
{
    RealIndexerOptions options;
    options.health = indexer_client::testing::throttledRule(indexer_client::testing::Durability::Transient);
    RealIndexer env {options};
    // The PIT creation takes longer than probeDeadline: only a call that keeps its callDeadline gets through.
    env.pits->intercept(
        [](const PitRequestView& view, Rule& reply)
        {
            if (view.call == PitCall::Create)
            {
                reply.latency = 800ms;
            }
            return false;
        });
    env.startRuntime();
    ASSERT_TRUE(env.makeClient(false)) << env.startError;
    ASSERT_TRUE(waitUntil(
        [&]
        {
            const auto nodes = env.client->health().nodes;
            return !nodes.empty() && nodes.front().state == indexer_client::HealthView::NodeState::Throttled;
        }))
        << "the node never became Throttled";

    ContentIndexerOptions adapterOptions;
    adapterOptions.probeDeadline = 300ms;
    adapterOptions.callDeadline = 6s;
    adapterOptions.pageDeadline = 6s;
    auto adapter = env.adapter(adapterOptions);

    ASSERT_TRUE(env.client->health().anyUsable());
    ASSERT_FALSE(env.client->health().anyAvailable());
    ContentPit pit;
    ASSERT_NO_THROW(pit = adapter->openPit({"idx"}, "5m", false)) << "a Throttled node is usable: no probeDeadline cut";
    adapter->closePit(pit);
}

TEST(ContentIndexerClientAdapter, NonPositiveDeadlineThrows)
{
    RealIndexer env;
    env.startRuntime();
    ASSERT_TRUE(env.makeClient()) << env.startError;

    const auto expectInvalid = [&env](const char* what, const std::function<void(ContentIndexerOptions&)>& zero)
    {
        ContentIndexerOptions options;
        zero(options);
        try
        {
            env.adapter(options);
            ADD_FAILURE() << what << ": a non-positive deadline must be refused";
        }
        catch (const std::invalid_argument& e)
        {
            EXPECT_NE(std::string {e.what()}.find("deadline"), std::string::npos) << what << ": " << e.what();
        }
    };
    expectInvalid("callDeadline 0", [](auto& o) { o.callDeadline = 0ms; });
    expectInvalid("pageDeadline 0", [](auto& o) { o.pageDeadline = 0ms; });
    expectInvalid("probeDeadline 0", [](auto& o) { o.probeDeadline = 0ms; });
    expectInvalid("callDeadline < 0", [](auto& o) { o.callDeadline = -5ms; });
    expectInvalid("pageDeadline < 0", [](auto& o) { o.pageDeadline = -5ms; });
    expectInvalid("probeDeadline < 0", [](auto& o) { o.probeDeadline = -5ms; });
}
