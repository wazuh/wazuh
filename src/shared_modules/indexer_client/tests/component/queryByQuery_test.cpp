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
