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

// The managed PIT end to end (plan 18, plan-E4b §Tests; contract: src/query/pit.hpp): creation, cursors with slice,
// Pit::search, retries, expiry and staleness over the real transport and the fake indexer's PitResponder. Oracles: the
// recorded requests (method, path, query string, body), the Outcome (cause, reason), times and pitStats() deltas.
// The registry's cases (slots, deletes, drain) are pitRegistry_test.cpp.

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "queryFixture.hpp"

using namespace query_component;

namespace
{
    nlohmann::json parsed(const RecordedRequest& request)
    {
        return nlohmann::json::parse(request.body);
    }

    /// Pages `cursor` until it is exhausted (at most `limit` calls); every page must be Ok.
    std::vector<std::int64_t> drainCursor(ic::PitSession& cursor, int limit = 50)
    {
        std::vector<std::int64_t> out;
        for (int i = 0; i < limit && !cursor.exhausted(); ++i)
        {
            auto page = cursor.next(in(10s));
            EXPECT_TRUE(page.ok()) << ic::toString(page.cause) << ": " << page.reason;
            if (!page.ok())
            {
                break;
            }
            const auto got = numbers(page.value);
            out.insert(out.end(), got.begin(), got.end());
        }
        return out;
    }

    std::vector<std::int64_t> range(std::int64_t from, std::int64_t to)
    {
        std::vector<std::int64_t> out;
        for (auto k = from; k <= to; ++k)
        {
            out.push_back(k);
        }
        return out;
    }
} // namespace

// T7, CA-23: a 429 on page 3 is retried with the same pit.id and the same search_after (the same body); one creation;
// dropping the Pit deletes it once and open goes back to 0. Mutant: the retry re-reads search_after from the cursor
// already advanced.
TEST_F(PitTest, Pit429RetriesSamePage)
{
    auto pits = std::make_shared<PitResponder>(9);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Search && request.ordinal == 3)
            {
                reply.status = 429;
                reply.body = errorBody("rejected_execution_exception", "too many requests", 429);
                return true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    const auto before = q::pitStats();
    {
        auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
        ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
        auto cursor = created.value.cursor(cursorQuery(2));
        EXPECT_EQ(drainCursor(cursor), range(1, 9));

        const auto searches = pitSearches(*node);
        ASSERT_EQ(searches.size(), 6u) << "5 pages and one retry";
        const auto third = parsed(searches[2]);
        const auto retried = parsed(searches[3]);
        EXPECT_EQ(retried, third) << "the retry repeats the page's request";
        EXPECT_EQ(retried.at("search_after"), nlohmann::json::array({4}));
        EXPECT_EQ(retried.at("pit").at("id"), "pit-1");
        EXPECT_EQ(pits->created(), 1u);
        EXPECT_EQ(q::pitStats().open, 1u);
        EXPECT_EQ(pitDeletes(*node).size(), 0u);
    }
    ASSERT_TRUE(component::eventually([&] { return pits->deleted() == 1 && q::pitStats().open == 0; }, scaled(5000ms)))
        << "the PIT was not deleted after its last handle went";
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.created, 1u);
    EXPECT_EQ(d.deletesConfirmed, 1u);
    EXPECT_EQ(d.deletesPending, 0u);
    const auto deletes = pitDeletes(*node);
    ASSERT_EQ(deletes.size(), 1u);
    EXPECT_EQ(parsed(deletes[0]), (nlohmann::json {{"pit_id", "pit-1"}}));
}

// T7b: two cursors (slice 0/2 and 1/2) on different threads, opened and closed at different times: every request
// carries the same id, the union of their hits is the index without duplicates, one creation, and the one delete
// comes only after the last handle (the second cursor) goes. Mutant: delete when a cursor is destroyed.
TEST_F(PitTest, TwoSlicesShareOnePit)
{
    auto pits = std::make_shared<PitResponder>(20);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    const auto before = q::pitStats();

    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto pit = std::make_unique<ic::Pit>(std::move(created.value)); // The only handle.

    std::promise<void> aHalf;
    std::promise<void> aGo;
    std::promise<void> bGo;
    std::vector<std::int64_t> fromA;
    std::vector<std::int64_t> fromB;

    auto first = std::make_unique<ic::PitSession>(pit->cursor(cursorQuery(3), ic::Slice {0, 2}));
    std::thread threadA(
        [&, cursor = std::move(first), go = aGo.get_future()]() mutable
        {
            for (int i = 0; i < 2; ++i)
            {
                auto page = cursor->next(in(10s));
                EXPECT_TRUE(page.ok()) << page.reason;
                const auto got = numbers(page.value);
                fromA.insert(fromA.end(), got.begin(), got.end());
            }
            aHalf.set_value();
            go.wait();
            const auto rest = drainCursor(*cursor);
            fromA.insert(fromA.end(), rest.begin(), rest.end());
            cursor.reset(); // A closes first.
        });
    aHalf.get_future().wait();

    auto second = std::make_unique<ic::PitSession>(pit->cursor(cursorQuery(3), ic::Slice {1, 2}));
    pit.reset(); // Only the cursors hold the PIT from now on.
    std::promise<void> bPaged;
    std::thread threadB(
        [&, cursor = std::move(second), go = bGo.get_future()]() mutable
        {
            auto page = cursor->next(in(10s));
            EXPECT_TRUE(page.ok()) << page.reason;
            const auto got = numbers(page.value);
            fromB.insert(fromB.end(), got.begin(), got.end());
            bPaged.set_value();
            go.wait();
            const auto rest = drainCursor(*cursor);
            fromB.insert(fromB.end(), rest.begin(), rest.end());
            cursor.reset();
        });
    bPaged.get_future().wait();
    aGo.set_value();
    threadA.join();

    // A is gone, B is alive and not finished: no delete.
    std::this_thread::sleep_for(scaled(300ms));
    EXPECT_EQ(pitDeletes(*node).size(), 0u) << "deleted while a cursor still holds the PIT";
    EXPECT_EQ(q::pitStats().open, 1u);

    bGo.set_value();
    threadB.join();
    ASSERT_TRUE(component::eventually([&] { return pits->deleted() == 1 && q::pitStats().open == 0; }, scaled(5000ms)));

    std::vector<std::int64_t> all = fromA;
    all.insert(all.end(), fromB.begin(), fromB.end());
    std::sort(all.begin(), all.end());
    EXPECT_EQ(all, range(1, 20)) << "the union of the slices is the index, without duplicates";
    for (const auto k : fromA)
    {
        EXPECT_EQ((k - 1) % 2, 0) << k;
    }
    for (const auto& request : pitSearches(*node))
    {
        EXPECT_EQ(parsed(request).at("pit").at("id"), "pit-1");
    }
    EXPECT_EQ(pits->created(), 1u);
    EXPECT_EQ(pitDeletes(*node).size(), 1u);
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.created, 1u);
    EXPECT_EQ(d.deletesConfirmed, 1u);
}

// T19: slice 0 finished, slice 1 half way, slice 2 asleep in a 429's Retry-After (2 s). The fake expires the PIT: the
// next page of slice 1 ⇒ PitExpired (one 404); slice 2 wakes ⇒ PitExpired without a request; afterwards next() and
// Pit::search ⇒ PitExpired without a request; expired + 1. Mutant: only the call that saw the expiry fails (it is not
// recorded on the shared PIT). Two nodes share the PIT: the 429 parks the node that sent it for every caller (I109), so
// slice 1 sees the expiry on the other node while slice 2 sleeps.
TEST_F(PitTest, PitExpiryReachesEveryCursor)
{
    auto pits = std::make_shared<PitResponder>(30);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Search && request.body.is_object() && request.body.contains("slice") &&
                request.body.at("slice").at("id") == 2)
            {
                reply.status = 429;
                reply.retryAfter = "2";
                reply.body = errorBody("rejected_execution_exception", "too many requests", 429);
                return true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    const auto other = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl(), other->baseUrl()}));
    const auto searches = [&]
    {
        return pitSearches(*node).size() + pitSearches(*other).size();
    };
    auto owner = client();
    const auto before = q::pitStats();

    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto pit = created.value;
    auto done = pit.cursor(cursorQuery(4), ic::Slice {0, 3});
    EXPECT_EQ(drainCursor(done).size(), 10u);
    auto half = pit.cursor(cursorQuery(4), ic::Slice {1, 3});
    ASSERT_TRUE(half.next(in(10s)).ok());

    const auto sliceTwo = [&]
    {
        std::size_t n = 0;
        for (const auto* fake : {node.get(), other.get()})
        {
            for (const auto& request : pitSearches(*fake))
            {
                const auto body = parsed(request);
                n += body.contains("slice") && body.at("slice").at("id") == 2 ? 1 : 0;
            }
        }
        return n;
    };
    auto sleeping = std::make_shared<ic::PitSession>(pit.cursor(cursorQuery(4), ic::Slice {2, 3}));
    auto slept = std::make_shared<ic::Outcome<ic::PitPage>>();
    const auto sleptAt = now();
    component::AsyncCall call([sleeping, slept] { *slept = sleeping->next(in(30s)); });
    ASSERT_TRUE(component::eventually([&] { return sliceTwo() == 1; }, scaled(5000ms)));

    pits->expireAll();
    const auto searchesBefore = searches();
    auto seen = half.next(in(10s));
    EXPECT_EQ(seen.cause, ic::Cause::PitExpired) << seen.reason;
    EXPECT_EQ(searches(), searchesBefore + 1) << "slice 1 saw the 404";

    ASSERT_TRUE(call.wait(scaled(5000ms))) << "the sleeping cursor never woke";
    EXPECT_EQ(slept->cause, ic::Cause::PitExpired) << slept->reason;
    EXPECT_GE(since(sleptAt), 1500ms) << "it woke before its Retry-After";
    EXPECT_EQ(sliceTwo(), 1u) << "the woken cursor sent a request on an expired PIT";

    const auto searchesAfter = searches();
    EXPECT_EQ(half.next(in(5s)).cause, ic::Cause::PitExpired);
    EXPECT_EQ(sleeping->next(in(5s)).cause, ic::Cause::PitExpired);
    EXPECT_EQ(pit.search({{"query", {{"match_all", nlohmann::json::object()}}}}, in(5s)).cause, ic::Cause::PitExpired);
    auto fresh = pit.cursor(cursorQuery(4));
    EXPECT_EQ(fresh.next(in(5s)).cause, ic::Cause::PitExpired);
    EXPECT_EQ(searches(), searchesAfter) << "no request on an expired PIT";
    EXPECT_EQ(pitDelta(before, q::pitStats()).expired, 1u);
}

// T19, D52: a 200 whose _shards reports a failed shard of type search_context_missing_exception ⇒ PitExpired, never a
// page; every search URL carries allow_partial_search_results=false. Mutant: accept the partial 200 as a page.
TEST_F(PitTest, PartialShardFailureIsNotAPage)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Search && request.ordinal == 2)
            {
                reply.status = 200;
                reply.body = PitResponder::partialFailureBody("pit-1",
                                                              {PitResponder::document(3), PitResponder::document(4)},
                                                              indexer_client::testing::SEARCH_CONTEXT_MISSING_TYPE);
                return true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    const auto before = q::pitStats();

    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto cursor = created.value.cursor(cursorQuery(2));
    auto first = cursor.next(in(5s));
    ASSERT_TRUE(first.ok()) << first.reason;
    EXPECT_EQ(numbers(first.value), (std::vector<std::int64_t> {1, 2}));
    auto partial = cursor.next(in(5s));
    EXPECT_EQ(partial.cause, ic::Cause::PitExpired) << partial.reason;
    EXPECT_TRUE(partial.value.hits.empty()) << "a partial answer is never a page";
    EXPECT_EQ(cursor.next(in(5s)).cause, ic::Cause::PitExpired);

    const auto searches = pitSearches(*node);
    ASSERT_EQ(searches.size(), 2u);
    for (const auto& request : searches)
    {
        EXPECT_EQ(queryString(request), "allow_partial_search_results=false");
    }
    EXPECT_EQ(pitDelta(before, q::pitStats()).expired, 1u);
}

// I229: a PIT opened with PitOptions::wholeResponseCap takes pages up to maxResponseBytes (here 64000), not
// maxResponseBytes / QUERY_DOM_FACTOR (8000), on Pit::search and on its cursors; a PIT without it still refuses them
// (ItemPermanent, responseTooLarge), and a page over maxResponseBytes is refused by both. Mutant: the classifier
// ignores the option.
TEST_F(PitTest, WholeResponseCapPit)
{
    constexpr std::uint64_t MAX_RESPONSE = 64000;
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call != PitCall::Search || !request.body.is_object())
            {
                return false;
            }
            const auto size = request.body.value("size", 0);
            const std::size_t pad = size == 3 ? 20000 : (size == 4 ? 70000 : 0); // 8000 < 20000 < 64000 < 70000.
            if (pad == 0)
            {
                return false;
            }
            reply.status = 200;
            reply.body = nlohmann::json {{"pit_id", request.body.at("pit").at("id")},
                                         {"took", 1},
                                         {"timed_out", false},
                                         {"_shards", {{"total", 1}, {"successful", 1}, {"skipped", 0}, {"failed", 0}}},
                                         {"hits",
                                          {{"total", {{"value", 1}, {"relation", "eq"}}},
                                           {"hits", nlohmann::json::array({PitResponder::document(1)})}}},
                                         {"pad", std::string(pad, 'x')}}
                             .dump();
            return true;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"max_response_bytes", std::to_string(MAX_RESPONSE)}}));
    auto owner = client();

    auto wholeOptions = keepAlive(60s);
    wholeOptions.wholeResponseCap = true;
    auto whole = owner->query()->pit({"idx"}, wholeOptions, fastOptions(), in(5s));
    ASSERT_TRUE(whole.ok()) << ic::toString(whole.cause) << ": " << whole.reason;
    auto plain = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(plain.ok()) << ic::toString(plain.cause) << ": " << plain.reason;

    const nlohmann::json between {{"size", 3}};
    const nlohmann::json over {{"size", 4}};

    auto wholeSearch = whole.value.search(between, in(5s));
    ASSERT_TRUE(wholeSearch.ok()) << ic::toString(wholeSearch.cause) << ": " << wholeSearch.reason;
    EXPECT_EQ(wholeSearch.value.at("pad").get<std::string>().size(), 20000u);
    auto wholeCursor = whole.value.cursor(cursorQuery(3));
    auto wholePage = wholeCursor.next(in(5s));
    ASSERT_TRUE(wholePage.ok()) << ic::toString(wholePage.cause) << ": " << wholePage.reason;
    EXPECT_EQ(numbers(wholePage.value), (std::vector<std::int64_t> {1}));

    auto plainSearch = plain.value.search(between, in(5s));
    EXPECT_EQ(plainSearch.cause, ic::Cause::ItemPermanent) << plainSearch.reason;
    EXPECT_TRUE(plainSearch.responseTooLarge);
    auto plainCursor = plain.value.cursor(cursorQuery(3));
    auto plainPage = plainCursor.next(in(5s));
    EXPECT_EQ(plainPage.cause, ic::Cause::ItemPermanent) << plainPage.reason;
    EXPECT_TRUE(plainPage.responseTooLarge);

    for (auto* pit : {&whole.value, &plain.value})
    {
        auto tooLarge = pit->search(over, in(5s));
        EXPECT_EQ(tooLarge.cause, ic::Cause::ItemPermanent) << tooLarge.reason;
        EXPECT_TRUE(tooLarge.responseTooLarge) << tooLarge.reason;
    }
}

// T19: a page held by the fake is released after another cursor saw the expiry: that cursor gets PitExpired and
// stale + 1. Mutant: accept the late page.
TEST_F(PitTest, StaleGenerationDiscarded)
{
    auto pits = std::make_shared<PitResponder>(20);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            // Slice 0's second page is answered (computed now, while the PIT lives) but held.
            if (request.call == PitCall::Search && request.body.is_object() && request.body.contains("slice") &&
                request.body.at("slice").at("id") == 0 && request.body.contains("search_after"))
            {
                reply.hold = true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    const auto before = q::pitStats();

    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto pit = created.value;
    auto late = std::make_shared<ic::PitSession>(pit.cursor(cursorQuery(2), ic::Slice {0, 2}));
    auto other = pit.cursor(cursorQuery(2), ic::Slice {1, 2});
    ASSERT_TRUE(late->next(in(5s)).ok());
    ASSERT_TRUE(other.next(in(5s)).ok());

    auto held = std::make_shared<ic::Outcome<ic::PitPage>>();
    component::AsyncCall call([late, held] { *held = late->next(in(30s)); });
    ASSERT_TRUE(node->waitHeld(1, scaled(5000ms)));
    pits->expireAll();
    auto seen = other.next(in(5s));
    EXPECT_EQ(seen.cause, ic::Cause::PitExpired) << seen.reason;
    node->releaseHeld();
    ASSERT_TRUE(call.wait(scaled(5000ms)));
    EXPECT_EQ(held->cause, ic::Cause::PitExpired) << held->reason;
    EXPECT_TRUE(held->value.hits.empty());
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.stale, 1u);
    EXPECT_EQ(d.expired, 1u);
}

// I90, obj. 4: keepAlive 1 s and a page every 600 ms for 3 s: never PitExpired (the fake expires a PIT by the
// keep_alive of its last request); every search carries pit.keep_alive. Mutant: no keep_alive in the searches.
TEST_F(PitTest, KeepAliveRenewedByEachSearch)
{
    auto pits = std::make_shared<PitResponder>(10);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    const auto span = scaled(1000ms);
    const auto pause = scaled(600ms);

    auto created = owner->query()->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto cursor = created.value.cursor(cursorQuery(1));
    const auto started = now();
    std::vector<std::int64_t> seen;
    while (since(started) < scaled(3000ms))
    {
        std::this_thread::sleep_for(pause);
        auto page = cursor.next(in(5s));
        ASSERT_TRUE(page.ok()) << ic::toString(page.cause) << ": " << page.reason;
        const auto got = numbers(page.value);
        seen.insert(seen.end(), got.begin(), got.end());
    }
    EXPECT_GE(seen.size(), 5u);
    EXPECT_EQ(pits->expired(), 0u);
    const auto text = std::to_string(span.count()) + "ms";
    for (const auto& request : pitSearches(*node))
    {
        EXPECT_EQ(parsed(request).at("pit").at("keep_alive"), text);
    }
}

// I92: the first page carries track_total_hits: true and PitPage::total; the following ones search_after and no
// total; a short page is last; next() after last ⇒ Ok, empty, last, no request.
TEST_F(PitTest, FirstPageCarriesTotal)
{
    auto pits = std::make_shared<PitResponder>(7);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();

    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto pit = created.value;
    auto cursor = pit.cursor(cursorQuery(3));
    auto first = cursor.next(in(5s));
    ASSERT_TRUE(first.ok()) << first.reason;
    ASSERT_TRUE(first.value.total.has_value());
    EXPECT_EQ(*first.value.total, 7u);
    EXPECT_FALSE(first.value.last);
    EXPECT_EQ(first.value.generation, pit.generation());
    EXPECT_NE(pit.generation(), 0u);
    auto second = cursor.next(in(5s));
    ASSERT_TRUE(second.ok()) << second.reason;
    EXPECT_FALSE(second.value.total.has_value());
    EXPECT_FALSE(second.value.last);
    auto third = cursor.next(in(5s));
    ASSERT_TRUE(third.ok()) << third.reason;
    EXPECT_EQ(numbers(third.value), (std::vector<std::int64_t> {7}));
    EXPECT_TRUE(third.value.last);
    EXPECT_FALSE(third.value.total.has_value());
    EXPECT_TRUE(cursor.exhausted());

    const auto searches = pitSearches(*node);
    ASSERT_EQ(searches.size(), 3u);
    EXPECT_EQ(parsed(searches[0]).at("track_total_hits"), true);
    EXPECT_FALSE(parsed(searches[0]).contains("search_after"));
    EXPECT_FALSE(parsed(searches[1]).contains("track_total_hits"));
    EXPECT_EQ(parsed(searches[1]).at("search_after"), nlohmann::json::array({3}));
    EXPECT_EQ(parsed(searches[2]).at("search_after"), nlohmann::json::array({6}));

    auto after = cursor.next(in(5s));
    ASSERT_TRUE(after.ok()) << after.reason;
    EXPECT_TRUE(after.value.hits.empty());
    EXPECT_TRUE(after.value.last);
    EXPECT_EQ(pitSearches(*node).size(), 3u) << "next() after last sent a request";
}

// I93: the request shapes. Creation: POST /a,b/_search/point_in_time?keep_alive=<ms>ms[&expand_wildcards=all], no
// body. Search: POST /_search?allow_partial_search_results=false with pit {id, keep_alive}; an empty sort becomes
// [{"_shard_doc":"asc"}] and a consumer sort is kept as given; Pit::search overwrites body.pit and keeps the rest; a
// new pit_id in a response is the one the next request uses.
TEST_F(PitTest, PitRequestShapes)
{
    auto pits = std::make_shared<PitResponder>(10);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    ic::PitOptions options = keepAlive(60s);
    options.expandWildcardsAll = true;
    auto created = query->pit({"a", "b"}, options, fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    auto plain = query->pit({"a"}, {}, fastOptions(), in(5s));
    ASSERT_TRUE(plain.ok()) << plain.reason;
    const auto creates = pitCreates(*node);
    ASSERT_EQ(creates.size(), 2u);
    EXPECT_EQ(creates[0].path, "/a,b/_search/point_in_time");
    EXPECT_EQ(queryString(creates[0]), "keep_alive=60000ms&expand_wildcards=all");
    EXPECT_EQ(creates[0].bodySize, 0u);
    EXPECT_EQ(creates[1].path, "/a/_search/point_in_time");
    EXPECT_EQ(queryString(creates[1]), "keep_alive=300000ms");

    auto pit = created.value;
    ic::CursorQuery shaped;
    shaped.query = {{"term", {{"kind", "x"}}}};
    shaped.source = nlohmann::json::array({"n"});
    shaped.pageSize = 2;
    auto cursor = pit.cursor(shaped);
    ASSERT_TRUE(cursor.next(in(5s)).ok());
    ic::CursorQuery sorted = cursorQuery(2);
    sorted.sort = nlohmann::json::array({{{"n", "asc"}}});
    auto custom = pit.cursor(sorted, ic::Slice {1, 2});
    ASSERT_TRUE(custom.next(in(5s)).ok());

    auto searches = pitSearches(*node);
    ASSERT_EQ(searches.size(), 2u);
    for (const auto& request : searches)
    {
        EXPECT_EQ(queryString(request), "allow_partial_search_results=false");
    }
    const nlohmann::json pitField {{"id", "pit-1"}, {"keep_alive", "60000ms"}};
    EXPECT_EQ(parsed(searches[0]),
              (nlohmann::json {{"size", 2},
                               {"query", shaped.query},
                               {"sort", nlohmann::json::array({{{"_shard_doc", "asc"}}})},
                               {"_source", shaped.source},
                               {"pit", pitField},
                               {"track_total_hits", true}}));
    EXPECT_EQ(parsed(searches[1]).at("sort"), sorted.sort) << "a consumer sort gets no tiebreaker";
    EXPECT_EQ(parsed(searches[1]).at("slice"), (nlohmann::json {{"id", 1}, {"max", 2}}));

    // Pit::search: body.pit overwritten, the rest untouched; the response carries a renewed id.
    const nlohmann::json body {{"query", {{"match_all", nlohmann::json::object()}}},
                               {"size", 5},
                               {"aggs", {{"k", {{"terms", {{"field", "n"}}}}}}},
                               {"pit", {{"id", "bogus"}, {"keep_alive", "1m"}}}};
    pits->renewIdOnNextSearch();
    auto searched = pit.search(body, in(5s));
    ASSERT_TRUE(searched.ok()) << searched.reason;
    EXPECT_EQ(searched.value.at("pit_id"), "pit-1-r1");
    searches = pitSearches(*node);
    ASSERT_EQ(searches.size(), 3u);
    auto expected = body;
    expected["pit"] = pitField;
    EXPECT_EQ(parsed(searches[2]), expected);

    ASSERT_TRUE(cursor.next(in(5s)).ok());
    searches = pitSearches(*node);
    ASSERT_EQ(searches.size(), 4u);
    EXPECT_EQ(parsed(searches[3]).at("pit").at("id"), "pit-1-r1") << "the renewed id is used next";
}

// I93: invalid arguments ⇒ InvalidArgument naming the field and no request: keepAlive 0, index "a/b" (pit()); a
// cursor with slice.id >= max, max 1 or pageSize 0 (its first next()).
TEST_F(PitTest, PitRejectsBadArguments)
{
    auto pits = std::make_shared<PitResponder>(10);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto zero = query->pit({"idx"}, keepAlive(0ms), fastOptions(), in(5s));
    EXPECT_EQ(zero.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(zero.reason.rfind("pitOptions.keepAlive", 0), 0u) << zero.reason;
    auto unsafe = query->pit({"a/b"}, keepAlive(60s), fastOptions(), in(5s));
    EXPECT_EQ(unsafe.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(unsafe.reason.rfind("indices[0]", 0), 0u) << unsafe.reason;
    EXPECT_EQ(queries(*node).size(), 0u);

    auto created = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << created.reason;
    auto pit = created.value;
    struct Bad
    {
        ic::CursorQuery query;
        std::optional<ic::Slice> slice;
        std::string field;
    };
    const std::vector<Bad> bad {{cursorQuery(2), ic::Slice {2, 2}, "slice.id"},
                                {cursorQuery(2), ic::Slice {0, 1}, "slice.max"},
                                {cursorQuery(0), std::nullopt, "query.pageSize"}};
    for (const auto& one : bad)
    {
        auto cursor = pit.cursor(one.query, one.slice);
        auto out = cursor.next(in(5s));
        EXPECT_EQ(out.cause, ic::Cause::InvalidArgument) << one.field;
        EXPECT_EQ(out.reason.rfind(one.field, 0), 0u) << out.reason;
    }
    EXPECT_EQ(pitSearches(*node).size(), 0u);
    EXPECT_EQ(queries(*node).size(), 1u) << "only the valid creation";
}

// RF-27, I37: pit(), next() and search() from a runtime thread ⇒ Reentrancy; after requestClose() ⇒ ClientClosed;
// both without a request. A Pit that outlives the runtime is destroyed without a request (the shutdown drain already
// deleted it) and answers Shutdown.
TEST_F(PitTest, PitReentrancyAndClose)
{
    auto pits = std::make_shared<PitResponder>(10);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    auto created = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << created.reason;
    auto pit = std::make_shared<ic::Pit>(created.value);
    auto cursor = std::make_shared<ic::PitSession>(pit->cursor(cursorQuery(2)));
    const auto sent = queries(*node).size();

    struct Seen
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::size_t done {0};
        std::vector<std::vector<ic::Cause>> causes;
    };
    auto seen = std::make_shared<Seen>();
    const auto task = [seen, query, pit, cursor]
    {
        std::vector<ic::Cause> causes;
        causes.push_back(query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s)).cause);
        causes.push_back(cursor->next(in(5s)).cause);
        causes.push_back(pit->search(nlohmann::json::object(), in(5s)).cause);
        {
            std::lock_guard<std::mutex> lock(seen->mutex);
            seen->causes.push_back(std::move(causes));
            ++seen->done;
        }
        seen->cv.notify_all();
    };
    ASSERT_TRUE(indexer_client::detail::testing::postToPool(task));
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(task));
    {
        std::unique_lock<std::mutex> lock(seen->mutex);
        ASSERT_TRUE(seen->cv.wait_for(lock, 5s, [&] { return seen->done == 2; }));
    }
    for (const auto& causes : seen->causes)
    {
        EXPECT_EQ(causes, std::vector<ic::Cause>(3, ic::Cause::Reentrancy));
    }
    EXPECT_EQ(queries(*node).size(), sent);

    // requestClose(): every call ⇒ ClientClosed, no request.
    owner->requestClose();
    EXPECT_EQ(query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s)).cause, ic::Cause::ClientClosed);
    EXPECT_EQ(cursor->next(in(5s)).cause, ic::Cause::ClientClosed);
    EXPECT_EQ(pit->search(nlohmann::json::object(), in(5s)).cause, ic::Cause::ClientClosed);
    EXPECT_EQ(queries(*node).size(), sent);

    // A Pit that outlives the runtime: the drain deletes it once; its destruction sends nothing.
    auto survivorClient = client("survivor");
    std::unique_ptr<ic::Pit> alive;
    {
        auto survivor = survivorClient->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
        ASSERT_TRUE(survivor.ok()) << survivor.reason;
        alive = std::make_unique<ic::Pit>(survivor.value);
    }
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto atShutdown = queries(*node).size();
    EXPECT_EQ(pitDeletes(*node).size(), 2u) << "the drain deleted both live PITs";
    EXPECT_EQ(alive->search(nlohmann::json::object(), in(5s)).cause, ic::Cause::Shutdown);
    alive.reset();
    pit.reset();
    cursor.reset();
    std::this_thread::sleep_for(scaled(200ms));
    EXPECT_EQ(queries(*node).size(), atShutdown) << "a Pit destroyed after the runtime sent a request";
}
