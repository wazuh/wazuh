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
