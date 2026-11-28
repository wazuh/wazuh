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

// deleteByQuery and updateByQuery end to end: routes, bodies, the
// conflict budget (its base shortened to 50 ms through the test hook) and the 200 outcomes over the real transport.

#include <chrono>
#include <string>
#include <vector>

#include "dropOnReuseServer.hpp"
#include "queryFixture.hpp"

using namespace query_component;

namespace
{
    constexpr std::int64_t CONFLICT_BASE_MS = 50;

    const nlohmann::json BY_AGENT = {{"query", {{"term", {{"wazuh.agent.id", "001"}}}}}};

    /// A DBQ/UBQ 200 answer (OpenSearch's shape) with these counters and failures.
    std::string byQueryResponse(std::uint64_t conflicts,
                                const nlohmann::json& failures = nlohmann::json::array(),
                                bool timedOut = false)
    {
        return nlohmann::json {{"took", 3},
                               {"timed_out", timedOut},
                               {"total", 2},
                               {"deleted", 2 - conflicts},
                               {"batches", 1},
                               {"version_conflicts", conflicts},
                               {"noops", 0},
                               {"retries", {{"bulk", 0}, {"search", 0}}},
                               {"throttled_millis", 0},
                               {"requests_per_second", -1.0},
                               {"throttled_until_millis", 0},
                               {"failures", failures}}
            .dump();
    }

    Rule times(Rule r, std::size_t n)
    {
        r.times = n;
        return r;
    }

    /// maxAttempts = 2: a conflict that spent a retry attempt would exhaust it before the third request.
    ic::QueryOptions conflictOptions()
    {
        auto options = fastOptions();
        options.retry.maxAttempts = 2;
        return options;
    }
} // namespace

// (base 50 ms) conflicts x2 and then clean ⇒ Ok in 3 requests with growing gaps; conflicts every time ⇒
// VersionConflict after 3; a 503 after two conflicts is retried (a fresh conflict series); multi-index routes
// /a,b/_delete_by_query?conflicts=proceed and /a,b/_update_by_query?conflicts=proceed with the query as the body.
// Mutant: a conflict retry spends the retry budget.
TEST_F(QueryTest, ByQueryConflictsRetryThenExhaust)
{
    indexer_client::testing_hooks::setQueryConflictBaseMs(CONFLICT_BASE_MS);
    const auto conflict = rule("POST", "/a,b/_(delete|update)_by_query", 200, byQueryResponse(1));
    const auto clean = rule("POST", "/a,b/_(delete|update)_by_query", 200, byQueryResponse(0));
    const auto node = fake({times(conflict, 2), clean});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    // Conflicts x2, then clean.
    auto before = q::queryStats();
    auto out = query->deleteByQuery({"a", "b"}, BY_AGENT, {}, conflictOptions(), in(10s));
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(out.value.at("version_conflicts"), 0);
    auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 3u);
    for (const auto& request : sent)
    {
        EXPECT_EQ(request.method, "POST");
        EXPECT_EQ(request.path, "/a,b/_delete_by_query");
        EXPECT_EQ(queryString(request), "conflicts=proceed");
        EXPECT_EQ(nlohmann::json::parse(request.body), BY_AGENT);
    }
    EXPECT_GE(gap(sent[0], sent[1]), std::chrono::milliseconds(CONFLICT_BASE_MS));
    EXPECT_GE(gap(sent[1], sent[2]), std::chrono::milliseconds(2 * CONFLICT_BASE_MS));
    EXPECT_EQ(delta(before, q::queryStats()).conflictRetries, 2u);

    // Conflicts every time.
    rules(*node, {conflict});
    node->clearRequests();
    before = q::queryStats();
    out = query->updateByQuery({"a", "b"}, BY_AGENT, conflictOptions(), in(10s));
    EXPECT_EQ(out.cause, ic::Cause::VersionConflict) << out.reason;
    EXPECT_EQ(out.httpStatus, 200);
    sent = queries(*node);
    ASSERT_EQ(sent.size(), q::CONFLICT_ATTEMPTS);
    for (const auto& request : sent)
    {
        EXPECT_EQ(request.path, "/a,b/_update_by_query");
        EXPECT_EQ(queryString(request), "conflicts=proceed");
        EXPECT_EQ(nlohmann::json::parse(request.body), BY_AGENT);
    }
    EXPECT_EQ(delta(before, q::queryStats()).conflictRetries, q::CONFLICT_ATTEMPTS - 1);

    // Conflicts x2, a 503, then clean: the 503 opens no new conflict and is retried under a fresh conflict series.
    rules(*node,
          {times(conflict, 2),
           times(rule("POST", "/a,b/_delete_by_query", 503, errorBody("unavailable", "busy", 503)), 1),
           clean});
    node->clearRequests();
    out = query->deleteByQuery({"a", "b"}, BY_AGENT, {}, conflictOptions(), in(10s));
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(queries(*node).size(), 4u);
}

// End to end: a clean 200 returns the response; proceedOnConflicts = false drops conflicts=proceed and its
// 409-only failures are conflicts (retried); another failure ⇒ ItemPermanent with it in reason after one request;
// timed_out ⇒ retried with an attempt and then Ok.
TEST_F(QueryTest, ByQueryOutcomesEndToEnd)
{
    indexer_client::testing_hooks::setQueryConflictBaseMs(CONFLICT_BASE_MS);
    const nlohmann::json conflictFailures = nlohmann::json::array(
        {{{"index", "x"},
          {"id", "1"},
          {"cause",
           {{"type", "version_conflict_engine_exception"}, {"reason", "[1]: version conflict"}, {"index", "x"}}},
          {"status", 409}}});
    const nlohmann::json mappingFailure = nlohmann::json::array(
        {{{"index", "y"},
          {"id", "7"},
          {"cause", {{"type", "mapper_parsing_exception"}, {"reason", "failed to parse field [n]"}}},
          {"status", 400}}});
    const auto node = fake({times(rule("POST", "/x/_delete_by_query", 200, byQueryResponse(1, conflictFailures)), 1),
                            rule("POST", "/x/_delete_by_query", 200, byQueryResponse(0)),
                            rule("POST", "/y/_update_by_query", 200, byQueryResponse(0, mappingFailure)),
                            times(rule("POST", "/z/_update_by_query", 200, byQueryResponse(0, {}, true)), 1),
                            rule("POST", "/z/_update_by_query", 200, byQueryResponse(0))});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    ic::DbqOptions strict;
    strict.proceedOnConflicts = false;
    auto before = q::queryStats();
    auto dbq = query->deleteByQuery({"x"}, BY_AGENT, strict, fastOptions(), in(10s));
    ASSERT_TRUE(dbq.ok()) << ic::toString(dbq.cause) << ": " << dbq.reason;
    EXPECT_EQ(dbq.value, nlohmann::json::parse(byQueryResponse(0)));
    auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[0].target, "/x/_delete_by_query");
    EXPECT_EQ(sent[1].target, "/x/_delete_by_query");
    EXPECT_EQ(delta(before, q::queryStats()).conflictRetries, 1u);

    node->clearRequests();
    auto ubq = query->updateByQuery({"y"}, BY_AGENT, fastOptions(), in(10s));
    EXPECT_EQ(ubq.cause, ic::Cause::ItemPermanent) << ubq.reason;
    EXPECT_NE(ubq.reason.find("mapper_parsing_exception"), std::string::npos) << ubq.reason;
    EXPECT_EQ(queries(*node).size(), 1u);

    node->clearRequests();
    before = q::queryStats();
    auto timedOut = query->updateByQuery({"z"}, BY_AGENT, fastOptions(), in(10s));
    ASSERT_TRUE(timedOut.ok()) << ic::toString(timedOut.cause) << ": " << timedOut.reason;
    EXPECT_EQ(queries(*node).size(), 2u);
    EXPECT_EQ(delta(before, q::queryStats()).conflictRetries, 0u);

    auto onlyOne = fastOptions();
    onlyOne.retry.maxAttempts = 1;
    rules(*node, {rule("POST", "/z/_update_by_query", 200, byQueryResponse(0, {}, true))});
    node->clearRequests();
    auto exhausted = query->updateByQuery({"z"}, BY_AGENT, onlyOne, in(10s));
    EXPECT_EQ(exhausted.cause, ic::Cause::RetryExhausted) << exhausted.reason;
    EXPECT_EQ(queries(*node).size(), 1u);
}

// A by-query with maxAttempts = 3 against one node that answers the probe and holds the by-query: each attempt times
// out on its own budget (request_timeout_ms 200 inside a 3 s page), is counted and goes to the same node again. The
// node never leaves Available (no transition), so no other consumer stops using it, and the call ends RetryExhausted
// after exactly three requests. Mutant: NodeSet::report puts the node Down for the Timeout (one request, then
// Unavailable when the page ends).
TEST_F(QueryTest, ByQueryTimeoutsOnSlowNodeDoNotFlapIt)
{
    auto held = rule("POST", "/x/_delete_by_query");
    held.hold = true;
    const auto node = fake({held});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"request_timeout_ms", "200"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    const auto transitionsBefore = transitions(0);
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.retry.maxAttempts = 3;
    options.pageDeadline = 3s;

    const auto before = q::queryStats();
    const auto started = now();
    const auto out = query->deleteByQuery({"x"}, BY_AGENT, {}, options, in(10s));
    const auto took = since(started);
    EXPECT_EQ(out.cause, ic::Cause::RetryExhausted) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(queries(*node).size(), 3u);
    EXPECT_EQ(delta(before, q::queryStats()).failovers, 3u);
    EXPECT_EQ(nodeState(0), NodeState::Available) << "a slow by-query put the node Down";
    EXPECT_EQ(transitions(0), transitionsBefore) << "the node flapped";
    EXPECT_GE(took, 600ms);
    EXPECT_LT(took, 600ms + scaled(1500ms)) << "an attempt waited for something else than its own timeout";
    node->releaseHeld();
}

// conflictAttempts = 1: a by-query whose answer reports version conflicts is not resent -- one request, then
// VersionConflict -- whatever the retry policy still allows; the request after it (a clean answer) runs alone.
// Mutant: the budget stays CONFLICT_ATTEMPTS (a second request after the conflict delay).
TEST_F(QueryTest, ByQueryOneConflictAttemptNeverResends)
{
    indexer_client::testing_hooks::setQueryConflictBaseMs(CONFLICT_BASE_MS);
    const auto conflict = rule("POST", "/a/_(delete|update)_by_query", 200, byQueryResponse(1));
    const auto clean = rule("POST", "/a/_(delete|update)_by_query", 200, byQueryResponse(0));
    const auto node = fake({times(conflict, 2), clean});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto once = fastOptions();
    once.conflictAttempts = 1;
    auto before = q::queryStats();
    auto dbq = query->deleteByQuery({"a"}, BY_AGENT, {}, once, in(10s));
    EXPECT_EQ(dbq.cause, ic::Cause::VersionConflict) << dbq.reason;
    EXPECT_EQ(queries(*node).size(), 1u);
    auto ubq = query->updateByQuery({"a"}, BY_AGENT, once, in(10s));
    EXPECT_EQ(ubq.cause, ic::Cause::VersionConflict) << ubq.reason;
    EXPECT_EQ(queries(*node).size(), 2u);
    EXPECT_EQ(delta(before, q::queryStats()).conflictRetries, 0u);

    auto ok = query->deleteByQuery({"a"}, BY_AGENT, {}, once, in(10s));
    ASSERT_TRUE(ok.ok()) << ic::toString(ok.cause) << ": " << ok.reason;
    EXPECT_EQ(queries(*node).size(), 3u);
}

namespace
{
    /// The fake's answer: health green, a search with no hits, any by-query a clean 200.
    std::string answerByTarget(const std::string& target)
    {
        if (target == indexer_client::testing::HEALTH_PATH)
        {
            return indexer_client::testing::healthBody("green");
        }
        return target.find("/_search") != std::string::npos ? searchResponse(nlohmann::json::array())
                                                            : byQueryResponse(0);
    }

    /// The inventory sync sweep's options: one attempt, a 1 ms series, one conflict attempt.
    ic::QueryOptions singleAttempt()
    {
        ic::QueryOptions once;
        once.retry.maxAttempts = 1;
        once.retry.maxDuration = ic::Duration {1};
        once.conflictAttempts = 1;
        return once;
    }
} // namespace

// retry.maxAttempts = 1 (the inventory sync sweep's options): a delete- or update-by-query goes on a new connection,
// so libcurl never resends it inside the one attempt. The node drops every by-query that arrives on a reused
// keep-alive connection (a peer closing idle connections); none does, so each call succeeds and the node reads each
// one once. Mutant: the transport ignores freshConnection, or the query does not set it (a by-query goes over the
// pooled connection, is dropped and resent by curl: the node reads it twice).
TEST_F(QueryTest, SingleAttemptByQueryGoesOnFreshConnection)
{
    indexer_client::testing::DropOnReuseServer server("_by_query", 0, answerByTarget, true);
    ASSERT_NO_FATAL_FAILURE(start({server.baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto first = query->deleteByQuery({"a"}, BY_AGENT, {}, singleAttempt(), in(10s));
    ASSERT_TRUE(first.ok()) << ic::toString(first.cause) << ": " << first.reason;
    auto update = query->updateByQuery({"a"}, BY_AGENT, singleAttempt(), in(10s));
    ASSERT_TRUE(update.ok()) << ic::toString(update.cause) << ": " << update.reason;
    auto second = query->deleteByQuery({"a"}, BY_AGENT, {}, singleAttempt(), in(10s));
    ASSERT_TRUE(second.ok()) << ic::toString(second.cause) << ": " << second.reason;

    const auto sent = server.requestsTo("_by_query");
    ASSERT_EQ(sent.size(), 3u) << "a by-query reached the node twice";
    for (const auto& request : sent)
    {
        EXPECT_EQ(request.onConnection, 0u) << request.target << " went over a reused connection";
        EXPECT_FALSE(request.dropped);
    }
    EXPECT_EQ(nodeState(0), NodeState::Available);
}

// Fresh connections are for single-attempt mutations only: a single-attempt search (an idempotent read, like the
// engine's remote configuration poll) and a by-query with more than one attempt keep reusing the pooled connection.
// Mutant: freshConnection set for every single-attempt query, or for every by-query.
TEST_F(QueryTest, ReadsAndMultiAttemptByQueryReuseConnections)
{
    indexer_client::testing::DropOnReuseServer server("_never_dropped_", 0, answerByTarget);
    ASSERT_NO_FATAL_FAILURE(start({server.baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto search = query->search("idx", nlohmann::json::object(), singleAttempt(), in(10s));
    ASSERT_TRUE(search.ok()) << ic::toString(search.cause) << ": " << search.reason;
    auto twice = singleAttempt();
    twice.retry.maxAttempts = 2;
    auto dbq = query->deleteByQuery({"a"}, BY_AGENT, {}, twice, in(10s));
    ASSERT_TRUE(dbq.ok()) << ic::toString(dbq.cause) << ": " << dbq.reason;

    // The probe's round left a pooled connection: both go over it.
    const auto searched = server.requestsTo("/_search");
    ASSERT_EQ(searched.size(), 1u);
    EXPECT_GT(searched[0].onConnection, 0u) << "the single-attempt search did not reuse the pooled connection";
    const auto deleted = server.requestsTo("/_delete_by_query");
    ASSERT_EQ(deleted.size(), 1u);
    EXPECT_GT(deleted[0].onConnection, 0u) << "the two-attempt by-query did not reuse the pooled connection";
    EXPECT_EQ(server.accepted(), 1u);
}

// Creating a PIT is no idempotent read: a creation curl resent inside the one submission would leave two PITs on the
// node for one reserved slot. The node drops every creation that arrives on a reused keep-alive connection; none
// does, so the call succeeds and the node reads one creation. Mutant: the creation route does not ask for a fresh
// connection (it goes over the probe's pooled connection, is dropped and resent by curl: the node reads it twice).
TEST_F(QueryTest, PitCreationGoesOnFreshConnection)
{
    const std::string createTarget = "/idx/_search/point_in_time";
    indexer_client::testing::DropOnReuseServer server(
        createTarget,
        0,
        [&createTarget](const std::string& target)
        {
            return target.find(createTarget) != std::string::npos ? std::string(R"({"pit_id":"pit-1"})")
                                                                  : answerByTarget(target);
        },
        true);
    ASSERT_NO_FATAL_FAILURE(start({server.baseUrl()}));
    auto owner = client();

    ic::PitOptions pitOptions;
    pitOptions.keepAlive = 60s;
    auto created = owner->query()->pit({"idx"}, pitOptions, ic::QueryOptions {}, in(10s));
    ASSERT_TRUE(created.ok()) << ic::toString(created.cause) << ": " << created.reason;

    const auto sent = server.requestsTo(createTarget);
    ASSERT_EQ(sent.size(), 1u) << "the creation reached the node twice";
    EXPECT_EQ(sent[0].onConnection, 0u) << "the creation went over a reused connection";
    EXPECT_FALSE(sent[0].dropped);
}

namespace
{
    /// A by-query body over curl's 1 MiB Expect threshold (lib/http.h EXPECT_100_THRESHOLD).
    const nlohmann::json LARGE_BY_AGENT = {{"query", {{"term", {{"wazuh.agent.id", std::string(1536 * 1024, '7')}}}}}};
    constexpr std::size_t ONE_MIB = 1024 * 1024;

    /// The by-query requests that carried a whole body (not a head refused with 417).
    std::vector<indexer_client::testing::RawRequest>
    wholeByQueries(const indexer_client::testing::DropOnReuseServer& server)
    {
        std::vector<indexer_client::testing::RawRequest> out;
        for (auto& request : server.requestsTo("_by_query"))
        {
            if (!request.refusedExpectation)
            {
                out.push_back(std::move(request));
            }
        }
        return out;
    }
} // namespace

// A single-attempt by-query over 1 MiB goes without `Expect: 100-continue`: the node answers 417 to any by-query head
// that carries it and drops every whole by-query that arrives on a reused connection. A 417 would make curl send the
// request again as a follow-up, which skips the fresh-connection check (lib/url.c) and may go over a pooled
// connection, where a drop is resent by curl itself. None of that happens: each call succeeds and the node reads each
// body once, with no Expect, on a new connection. Mutant: configure() leaves Expect to curl for freshConnection
// (417, follow-up on a pooled connection, dropped, resent: the node reads the body two or more times).
TEST_F(QueryTest, SingleAttemptLargeByQueryGoesWithoutExpect)
{
    indexer_client::testing::DropOnReuseServer server("_by_query", 0, answerByTarget, true, true);
    ASSERT_NO_FATAL_FAILURE(start({server.baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto dbq = query->deleteByQuery({"a"}, LARGE_BY_AGENT, {}, singleAttempt(), in(10s));
    ASSERT_TRUE(dbq.ok()) << ic::toString(dbq.cause) << ": " << dbq.reason;
    auto ubq = query->updateByQuery({"a"}, LARGE_BY_AGENT, singleAttempt(), in(10s));
    ASSERT_TRUE(ubq.ok()) << ic::toString(ubq.cause) << ": " << ubq.reason;

    for (const auto& request : server.requestsTo("_by_query"))
    {
        EXPECT_FALSE(request.expectContinue) << request.target << " went with Expect: 100-continue";
    }
    const auto whole = wholeByQueries(server);
    ASSERT_EQ(whole.size(), 2u) << "a by-query body reached the node more than once";
    EXPECT_NE(whole[0].target.find("/_delete_by_query"), std::string::npos);
    EXPECT_NE(whole[1].target.find("/_update_by_query"), std::string::npos);
    for (const auto& request : whole)
    {
        EXPECT_GT(request.body.size(), ONE_MIB) << request.target;
        EXPECT_EQ(request.onConnection, 0u) << request.target << " went over a reused connection";
        EXPECT_FALSE(request.dropped) << request.target;
    }
    EXPECT_EQ(nodeState(0), NodeState::Available);
}

// Control for the previous case, same node and body: a by-query with two attempts keeps curl's Expect. The head goes
// over the pooled connection and gets 417; curl's follow-up reuses that connection, is dropped, and curl resends it
// on a new one inside the same attempt. The node reads the body twice although the call made one attempt: the path
// the single-attempt by-query must never take. Mutant: the fake does not refuse the expectation (the body is read
// once), which would make the previous case vacuous.
TEST_F(QueryTest, MultiAttemptLargeByQueryIsResentAfter417)
{
    indexer_client::testing::DropOnReuseServer server("_by_query", 0, answerByTarget, true, true);
    ASSERT_NO_FATAL_FAILURE(start({server.baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto twice = singleAttempt();
    twice.retry.maxAttempts = 2;
    auto dbq = query->deleteByQuery({"a"}, LARGE_BY_AGENT, {}, twice, in(10s));
    ASSERT_TRUE(dbq.ok()) << ic::toString(dbq.cause) << ": " << dbq.reason;

    const auto sent = server.requestsTo("_by_query");
    ASSERT_FALSE(sent.empty());
    EXPECT_TRUE(sent[0].expectContinue) << "a body over 1 MiB with two attempts goes with Expect: 100-continue";
    EXPECT_TRUE(sent[0].refusedExpectation);
    const auto whole = wholeByQueries(server);
    ASSERT_EQ(whole.size(), 2u) << "curl did not resend the follow-up dropped on the reused connection";
    EXPECT_GT(whole[0].onConnection, 0u);
    EXPECT_TRUE(whole[0].dropped);
    EXPECT_EQ(whole[1].onConnection, 0u);
    EXPECT_FALSE(whole[1].dropped);
    for (const auto& request : whole)
    {
        EXPECT_FALSE(request.expectContinue) << "the follow-up goes without Expect";
        EXPECT_GT(request.body.size(), ONE_MIB);
    }
}
