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

// The PIT registry end to end (plan 18, plan-E4b §Tests; contract: src/query/pit.hpp CREATE slots, LIFETIME AND
// DELETE, SHUTDOWN, STATS): the open-PIT cap, the reservation of a creation of unknown result, the DELETE with its
// retries and its expiry, and the shutdown drain, over the real transport and the fake indexer's PitResponder.

#include <chrono>
#include <memory>
#include <optional>
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

    /// Polls pitStats() until `predicate` holds; the time it took, or nothing past `timeout`.
    template<class P>
    std::optional<std::chrono::milliseconds> whenStats(P predicate, std::chrono::milliseconds timeout)
    {
        const auto started = now();
        if (component::eventually([&] { return predicate(q::pitStats()); }, timeout))
        {
            return since(started);
        }
        return std::nullopt;
    }
} // namespace

// I91, T19: maxOpenPits = 2. The first creation's answer is cut after it was sent (the PIT may exist) and the
// failover attempt creates: Ok, reserved = 1, open = 1; one more pit() ⇒ QueueFull without a request; once the
// keepAlive passed, pitStats().reserved = 0 without another pit(), and a pit() gets in. Mutant: no reservation.
TEST_F(PitTest, LostCreateReserves)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Create && request.ordinal == 1)
            {
                reply.cutAfter = 5; // The PIT is created; its answer never arrives whole.
            }
            return false;
        });
    const auto first = pitFake(pits);
    const auto second = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({first->baseUrl(), second->baseUrl()}, {{"max_open_pits", "2"}}));
    auto owner = client();
    auto query = owner->query();
    const auto span = scaled(1500ms);
    const auto before = q::pitStats();

    const auto called = now();
    auto created = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;
    EXPECT_EQ(pits->requests(PitCall::Create), 2u) << "the cut attempt and the failover";
    auto stats = q::pitStats();
    EXPECT_EQ(stats.open, 1u);
    EXPECT_EQ(stats.reserved, 1u) << "the cut creation holds its slot until its keep_alive";

    auto refused = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
    EXPECT_EQ(refused.cause, ic::Cause::QueueFull) << refused.reason;
    EXPECT_NE(refused.reason.find(q::PIT_FULL), std::string::npos) << refused.reason;
    EXPECT_EQ(pits->requests(PitCall::Create), 2u) << "a refusal sends nothing";
    EXPECT_EQ(pitDelta(before, q::pitStats()).refusedFull, 1u);

    ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.reserved == 0; }, span + scaled(2000ms)))
        << "the reservation never lapsed";
    EXPECT_GE(since(called), span) << "the reservation lapsed before its keep_alive";
    auto again = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
    EXPECT_TRUE(again.ok()) << ic::toString(again.cause) << ": " << again.reason;
    EXPECT_EQ(q::pitStats().open, 2u);
}

// maxOpenPits = 1. A creation answered 2xx that the library refuses without a usable pit_id means the indexer created a
// PIT nobody can address: (1) a body over the response cap (max_response_bytes / 8), (2) an unparsable body. Each fails
// the call ItemPermanent and keeps its slot reserved until its keepAlive, so the next pit() is QueueFull without a
// request; once it lapsed a pit() gets in. Mutant: the refused 2xx releases its slot (an orphan outside the cap).
TEST_F(PitTest, RefusedCreate2xxReserves)
{
    constexpr std::size_t MAX_RESPONSE = 8000; // A query's 2xx may hold 1000 bytes.
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call != PitCall::Create || (request.ordinal != 1 && request.ordinal != 3))
            {
                return false;
            }
            reply.status = 200;
            reply.body = request.ordinal == 1
                             ? nlohmann::json {{"pit_id", "pit-big"},
                                               {"_shards", {{"total", 1}, {"successful", 1}, {"failed", 0}}},
                                               {"pad", std::string(2000, 'x')}}
                                   .dump()
                             : std::string(R"({"pit_id":"pit-cut)");
            return true;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(
        start({node->baseUrl()}, {{"max_open_pits", "1"}, {"max_response_bytes", std::to_string(MAX_RESPONSE)}}));
    auto owner = client();
    auto query = owner->query();
    const auto span = scaled(1500ms);

    for (const auto* what : {"over the response cap", "unparsable"})
    {
        ASSERT_TRUE(
            whenStats([](const q::PitStats& s) { return s.open == 0 && s.deletesPending == 0; }, scaled(5000ms)))
            << what << ": the previous PIT was not deleted";
        const auto creates = pits->requests(PitCall::Create);
        const auto called = now();
        auto refused = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
        ASSERT_FALSE(refused.ok()) << what;
        EXPECT_EQ(refused.cause, ic::Cause::ItemPermanent) << what << ": " << refused.reason;
        EXPECT_EQ(q::pitStats().reserved, 1u) << what << ": the refused 2xx released its slot";
        EXPECT_EQ(q::pitStats().open, 0u) << what;

        auto full = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
        EXPECT_EQ(full.cause, ic::Cause::QueueFull) << what << ": " << full.reason;
        EXPECT_EQ(pits->requests(PitCall::Create), creates + 1) << what << ": a refusal sends nothing";

        ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.reserved == 0; }, span + scaled(2000ms)))
            << what << ": the reservation never lapsed";
        EXPECT_GE(since(called), span) << what << ": the reservation lapsed before its keep_alive";
        auto again = query->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
        ASSERT_TRUE(again.ok()) << what << ": " << ic::toString(again.cause) << ": " << again.reason;
        EXPECT_EQ(q::pitStats().open, 1u);
    }
}

// I91: a creation held by the fake and abandoned, (1) by its Deadline ⇒ Unavailable, (2) by requestClose() ⇒
// ClientClosed: each leaves one reservation until its keepAlive, then none. Mutant: a cancelled attempt frees its slot.
TEST_F(PitTest, CancelledCreateReserves)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Create)
            {
                reply.hold = true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    const auto span = scaled(2000ms);

    // (1) The Deadline.
    auto owner = client();
    const auto called = now();
    auto expired = owner->query()->pit({"idx"}, keepAlive(span), fastOptions(), in(scaled(300ms)));
    EXPECT_EQ(expired.cause, ic::Cause::Unavailable) << expired.reason;
    EXPECT_EQ(q::pitStats().reserved, 1u);
    EXPECT_EQ(q::pitStats().open, 0u);
    EXPECT_EQ(node->heldNow(), 1u);

    // (2) requestClose() while the next creation is held.
    auto closing = client("closing");
    auto closingQuery = closing->query();
    auto closed = std::make_shared<ic::Outcome<ic::Pit>>();
    {
        component::AsyncCall call([closingQuery, closed, span]
                                  { *closed = closingQuery->pit({"idx"}, keepAlive(span), fastOptions(), in(30s)); });
        ASSERT_TRUE(node->waitHeld(2, scaled(5000ms)));
        closing->requestClose();
        ASSERT_TRUE(call.wait(scaled(2000ms)));
    }
    EXPECT_EQ(closed->cause, ic::Cause::ClientClosed) << closed->reason;
    EXPECT_EQ(q::pitStats().reserved, 2u);
    node->releaseHeld();

    ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.reserved == 0; }, span + scaled(3000ms)))
        << "the reservations never lapsed";
    EXPECT_GE(since(called), span) << "a reservation lapsed before its keep_alive";
    EXPECT_EQ(q::pitStats().open, 0u);
}

// I89: maxOpenPits = 2: a creation answered 400 leaves open + reserved as it was; with two open the third pit() ⇒
// QueueFull without a request (refusedFull + 1); once one is released and deleted (bounded poll) open = 1 and a
// pit() gets in.
TEST_F(PitTest, PitCapRefuses)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Create && request.ordinal == 2)
            {
                reply.status = 400;
                reply.body = errorBody("illegal_argument_exception", "bad keep_alive", 400);
                return true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"max_open_pits", "2"}}));
    auto owner = client();
    auto query = owner->query();
    const auto before = q::pitStats();

    auto one = std::make_unique<ic::Pit>();
    {
        auto created = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
        ASSERT_TRUE(created.ok()) << created.reason;
        *one = created.value;
    }
    auto rejected = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    EXPECT_FALSE(rejected.ok());
    EXPECT_EQ(rejected.httpStatus, 400) << rejected.reason;
    auto stats = q::pitStats();
    EXPECT_EQ(stats.open + stats.reserved, 1u) << "a 400 gives its slot back";

    auto two = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(two.ok()) << two.reason;
    auto three = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    EXPECT_EQ(three.cause, ic::Cause::QueueFull) << three.reason;
    EXPECT_EQ(three.reason, std::string(q::PIT_FULL) + " (2)");
    EXPECT_EQ(pits->requests(PitCall::Create), 3u) << "the refused pit() sent nothing";
    EXPECT_EQ(pitDelta(before, q::pitStats()).refusedFull, 1u);

    one.reset();
    ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.open == 1 && s.deletesPending == 0; }, scaled(5000ms)))
        << "the released PIT never freed its slot";
    auto four = query->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    EXPECT_TRUE(four.ok()) << ic::toString(four.cause) << ": " << four.reason;
    EXPECT_EQ(pits->requests(PitCall::Create), 4u);
}

// I90: the DELETE answered 503 twice and then 200: confirmed, deleteRetries = 2, deletesPending 0, the slot free;
// every DELETE carries {"pit_id": id} with the id renewed by a search, spaced by the 1 s backoff. Mutant: no retry.
TEST_F(PitTest, DeleteRetriesUntilConfirmed)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Delete && request.ordinal <= 2)
            {
                reply.status = 503;
                reply.body = errorBody("unavailable", "busy", 503);
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
        ASSERT_TRUE(created.ok()) << created.reason;
        auto cursor = created.value.cursor(cursorQuery(2));
        pits->renewIdOnNextSearch();
        ASSERT_TRUE(cursor.next(in(5s)).ok());
    }
    ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.deletesPending == 0 && s.open == 0; }, scaled(10000ms)))
        << "the delete never settled";
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.deletesConfirmed, 1u);
    EXPECT_EQ(d.deletesExpired, 0u);
    EXPECT_EQ(d.deleteRetries, 2u);
    EXPECT_EQ(pits->deleted(), 1u);
    const auto deletes = pitDeletes(*node);
    ASSERT_EQ(deletes.size(), 3u);
    for (const auto& request : deletes)
    {
        EXPECT_EQ(parsed(request), (nlohmann::json {{"pit_id", "pit-1-r1"}}));
    }
    // backoffDelay(1 s, 15 s) with the default ±50 % jitter: >= 500 ms, then >= 1 s.
    EXPECT_GE(gap(deletes[0], deletes[1]), 450ms);
    EXPECT_GE(gap(deletes[1], deletes[2]), 950ms);
}

// I90: the node fails every DELETE (connection cut; the probe brings it back every 300 ms): the DELETE is retried until
// lastUse + keepAlive (never past it, never expired before it), then deletesExpired + 1, the slot free, and no request
// afterwards; deleteRetries counts the requests sent after the first, never a wait without a usable node.
TEST_F(PitTest, DeleteExpiresWithoutIndexer)
{
    auto pits = std::make_shared<PitResponder>(10);
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Delete)
            {
                reply.status = 200;
                reply.body = std::string(64, ' ');
                reply.cutAfter = 3;
                return true;
            }
            return false;
        });
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"probe_interval_ms", "300"}}));
    auto owner = client();
    const auto span = scaled(2500ms);
    const auto before = q::pitStats();
    ic::TimePoint lastAnswered;
    {
        auto created = owner->query()->pit({"idx"}, keepAlive(span), fastOptions(), in(5s));
        ASSERT_TRUE(created.ok()) << created.reason;
        auto cursor = created.value.cursor(cursorQuery(2));
        ASSERT_TRUE(cursor.next(in(5s)).ok());
        lastAnswered = now();
    }
    const auto lastSent = pitSearches(*node).back().receivedAt;

    ASSERT_TRUE(component::eventually([] { return q::pitStats().deletesPending == 1; }, scaled(1000ms)));
    ASSERT_TRUE(component::eventually([&] { return pitDelta(before, q::pitStats()).deletesExpired == 1; },
                                      span + scaled(3000ms)))
        << "the delete never expired";
    const auto expiredAt = now();
    EXPECT_GE(expiredAt, lastSent + span) << "expired before lastUse + keepAlive";
    EXPECT_LE(expiredAt, lastAnswered + span + scaled(500ms)) << "kept retrying past lastUse + keepAlive";
    auto stats = q::pitStats();
    EXPECT_EQ(stats.deletesPending, 0u);
    EXPECT_EQ(stats.open, 0u);
    EXPECT_EQ(pitDelta(before, stats).deletesConfirmed, 0u);

    const auto deletes = pitDeletes(*node);
    EXPECT_GE(deletes.size(), 2u) << "retried while the PIT could live";
    // A retry is counted when it is sent to a node (pit.hpp LIFETIME): the waits without a usable node, while the
    // cut node is down until the next probe, count nothing.
    EXPECT_EQ(pitDelta(before, stats).deleteRetries, deletes.size() - 1);
    for (const auto& request : deletes)
    {
        EXPECT_LT(request.receivedAt, lastAnswered + span);
    }
    std::this_thread::sleep_for(scaled(1000ms));
    EXPECT_EQ(pitDeletes(*node).size(), deletes.size()) << "a request after the expiry";
}

// I93 (SHUTDOWN): two live Pits at shutdown() ⇒ two DELETEs confirmed before it returns, and their later destruction
// sends nothing; with a DELETE held by the fake, the drain waits for it until DRAIN_STOP_MARGIN before the deadline
// (drain_ms 2 s), shutdown() returns before that deadline (never scaled) and the held one counts as expired.
TEST_F(PitTest, ShutdownDeletesOpenPits)
{
    auto pits = std::make_shared<PitResponder>(10);
    auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto before = q::pitStats();
    std::unique_ptr<ic::Pit> one;
    std::unique_ptr<ic::Pit> two;
    {
        auto owner = client();
        auto first = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
        auto second = owner->query()->pit({"other"}, keepAlive(60s), fastOptions(), in(5s));
        ASSERT_TRUE(first.ok() && second.ok()) << first.reason << " / " << second.reason;
        one = std::make_unique<ic::Pit>(first.value);
        two = std::make_unique<ic::Pit>(second.value);
    }
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    EXPECT_EQ(pitDeletes(*node).size(), 2u) << "both DELETEs before shutdown() returned";
    EXPECT_EQ(pits->deleted(), 2u);
    EXPECT_EQ(pitDelta(before, q::pitStats()).deletesConfirmed, 2u);
    const auto sent = queries(*node).size();
    one.reset();
    two.reset();
    std::this_thread::sleep_for(scaled(200ms));
    EXPECT_EQ(queries(*node).size(), sent);

    // A held DELETE: the drain gives it up at its end and shutdown() keeps its deadline.
    pits->intercept(
        [](const PitRequestView& request, Rule& reply)
        {
            if (request.call == PitCall::Delete)
            {
                reply.hold = true;
            }
            return false;
        });
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"drain_ms", "2000"}}));
    before = q::pitStats();
    {
        auto owner = client("held");
        auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
        ASSERT_TRUE(created.ok()) << created.reason;
        one = std::make_unique<ic::Pit>(created.value);
    }
    const auto started = now();
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto took = since(started);
    // The deadline itself is not scaled: shutdown() must keep it. The drain ends DRAIN_STOP_MARGIN before it (never
    // before: the held DELETE was sent) and the transport stop and the joins fit in that margin.
    EXPECT_LT(took, 2000ms) << "shutdown() overran its deadline";
    EXPECT_LT(took, 2000ms - q::DRAIN_STOP_MARGIN + scaled(300ms)) << "the drain did not end DRAIN_STOP_MARGIN early";
    EXPECT_GE(took, 2000ms - q::DRAIN_STOP_MARGIN - 50ms) << "the drain gave up before its end";
    EXPECT_EQ(node->heldNow(), 1u) << "the DELETE was sent and held";
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.deletesExpired, 1u);
    EXPECT_EQ(d.deletesConfirmed, 0u);
    node->releaseHeld();
    one.reset();
}

// G-diff E6a obj. 8 (I109): the DELETE of a PIT whose only node is parked is rescheduled to the end of the park
// (NodeSet::earliestNotBefore()), not to min(delete backoff, probe interval): one node, a PIT open, the node parked for
// 300 ms by a 429 with Retry-After reported to the NodeSet (what a query's 429 does; a Retry-After header counts whole
// seconds, which the 1 s ± 50 % delete backoff could not be told apart from), then the last handle goes ⇒ the one
// DELETE arrives at the park's end, within a short margin, and is confirmed with no retry counted (a wait without a
// usable node is no retry). Mutant: settle() without the `parked` cap (the DELETE waits the 500-1500 ms backoff).
TEST_F(PitTest, DeleteWaitsForParkedNode)
{
    auto pits = std::make_shared<PitResponder>(10);
    const auto node = pitFake(pits);
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto created = owner->query()->pit({"idx"}, keepAlive(60s), fastOptions(), in(5s));
    ASSERT_TRUE(created.ok()) << created.reason;
    auto pit = std::make_unique<ic::Pit>(std::move(created.value));
    const auto before = q::pitStats();

    indexer_client::detail::HttpResult throttled;
    throttled.cause = indexer_client::detail::TransportCause::None;
    throttled.status = 429;
    throttled.body = errorBody("rejected_execution_exception", "busy", 429);
    throttled.retryAfter = ic::Duration {300};
    const auto set = indexer_client::detail::runtimeNodeSet();
    set->report(0, throttled);
    const auto parkedUntil = set->notBefore(0);
    ASSERT_GT(parkedUntil, now() + 200ms) << "the 429 did not park the node";
    pit.reset(); // The last handle: the DELETE finds no node to choose.
    ASSERT_LT(now(), parkedUntil - 100ms) << "precondition: the DELETE was attempted while the node was parked";

    ASSERT_TRUE(whenStats([](const q::PitStats& s) { return s.deletesPending == 0 && s.open == 0; }, scaled(5000ms)))
        << "the delete never settled";
    const auto deletes = pitDeletes(*node);
    ASSERT_EQ(deletes.size(), 1u);
    EXPECT_GE(deletes[0].receivedAt, parkedUntil) << "the DELETE reached the parked node";
    EXPECT_LT(deletes[0].receivedAt, parkedUntil + scaled(150ms)) << "the DELETE did not go when the park ended";
    const auto d = pitDelta(before, q::pitStats());
    EXPECT_EQ(d.deletesConfirmed, 1u);
    EXPECT_EQ(d.deletesExpired, 0u);
    EXPECT_EQ(d.deleteRetries, 0u) << "a wait without a usable node counted as a retry";
    EXPECT_EQ(pits->deleted(), 1u);
}
