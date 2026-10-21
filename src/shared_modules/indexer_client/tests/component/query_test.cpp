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

// The query engine end to end (plan 18, plan-E4a §Tests; contract: src/query/query.hpp): search, searchAfter,
// indexExists and the failure paths over the real transport and the fake indexer. Oracles: the recorded requests
// (method, path, query string, body), the Outcome (cause, httpStatus, reason), times and queryStats() deltas.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "queryFixture.hpp"
#include "tlsMaterialFactory.hpp"

using namespace query_component;

namespace
{
    const nlohmann::json MATCH_ALL = {{"query", {{"match_all", nlohmann::json::object()}}}};

    /// A searchAfter body: sort by `n`, `size` hits per page.
    nlohmann::json pagedBody(std::int64_t size)
    {
        return {{"query", {{"match_all", nlohmann::json::object()}}}, {"sort", {{{"n", "asc"}}}}, {"size", size}};
    }

    /// `_search` answered by the `search_after` of the request: none ⇒ hits 1,2; [2] ⇒ 3,4; [4] ⇒ 5; else none.
    Rule pagedRule(const std::string& pathRegex)
    {
        auto r = rule("POST", pathRegex);
        r.dynamic = [](const httplib::Request& request, Rule& reply)
        {
            const auto body = nlohmann::json::parse(request.body, nullptr, false);
            nlohmann::json hits = nlohmann::json::array();
            const auto after = body.is_object() ? body.find("search_after") : body.end();
            const std::int64_t from = after == body.end() ? 0 : after->at(0).get<std::int64_t>();
            for (std::int64_t k = from + 1; k <= std::min<std::int64_t>(from + 2, 5); ++k)
            {
                hits.push_back(hit(k));
            }
            reply.body = searchResponse(hits);
        };
        return r;
    }
} // namespace

// CA-5: search posts the body to /<index>/_search and returns the whole response; with expandWildcardsAll every
// route (search, HEAD, DBQ, UBQ) carries expand_wildcards=all, and without it none does.
TEST_F(QueryTest, SearchReturnsWholeResponse)
{
    const std::string answer = searchResponse({hit(1), hit(2)});
    const auto node = fake({rule("POST", "/idx/_search", 200, answer)});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto out = query->search("idx", MATCH_ALL, fastOptions(), in(5s));
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(out.value, nlohmann::json::parse(answer));
    auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].method, "POST");
    EXPECT_EQ(sent[0].path, "/idx/_search");
    EXPECT_EQ(queryString(sent[0]), "");
    EXPECT_EQ(nlohmann::json::parse(sent[0].body), MATCH_ALL);

    auto all = fastOptions();
    all.expandWildcardsAll = true;
    ASSERT_TRUE(query->search("idx", MATCH_ALL, all, in(5s)).ok());
    ASSERT_TRUE(query->indexExists("idx", all, in(5s)).ok());
    ASSERT_TRUE(query->deleteByQuery({"idx"}, MATCH_ALL, {}, all, in(5s)).ok());
    ASSERT_TRUE(query->updateByQuery({"idx"}, MATCH_ALL, all, in(5s)).ok());
    sent = queries(*node);
    ASSERT_EQ(sent.size(), 5u);
    EXPECT_EQ(sent[1].path, "/idx/_search");
    EXPECT_EQ(queryString(sent[1]), "expand_wildcards=all");
    EXPECT_EQ(sent[2].method, "HEAD");
    EXPECT_EQ(sent[2].path, "/idx");
    EXPECT_EQ(queryString(sent[2]), "expand_wildcards=all");
    EXPECT_EQ(sent[3].path, "/idx/_delete_by_query");
    EXPECT_EQ(queryString(sent[3]), "conflicts=proceed&expand_wildcards=all");
    EXPECT_EQ(sent[4].path, "/idx/_update_by_query");
    EXPECT_EQ(queryString(sent[4]), "conflicts=proceed&expand_wildcards=all");
}

// CA-5: pages of 2, 2 and 1 with size 2 ⇒ page() x3, each later request carries search_after = the sort of the last
// hit; page() = false on the first ⇒ one request, Ok; a body without sort or without size ⇒ InvalidArgument without a
// request. Mutant: search_after not advanced.
TEST_F(QueryTest, SearchAfterPagesUntilShort)
{
    const auto node = fake({pagedRule("/idx/_search")});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    std::vector<std::size_t> pageSizes;
    auto out = query->searchAfter(
        "idx",
        pagedBody(2),
        [&](const nlohmann::json& response)
        {
            pageSizes.push_back(response.at("hits").at("hits").size());
            return true;
        },
        fastOptions(),
        in(5s));
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(pageSizes, (std::vector<std::size_t> {2, 2, 1}));
    auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 3u);
    EXPECT_FALSE(nlohmann::json::parse(sent[0].body).contains("search_after"));
    EXPECT_EQ(nlohmann::json::parse(sent[1].body).at("search_after"), nlohmann::json::array({2}));
    EXPECT_EQ(nlohmann::json::parse(sent[2].body).at("search_after"), nlohmann::json::array({4}));
    EXPECT_EQ(nlohmann::json::parse(sent[1].body).at("size"), 2);

    node->clearRequests();
    int calls = 0;
    out = query->searchAfter(
        "idx",
        pagedBody(2),
        [&](const nlohmann::json&)
        {
            ++calls;
            return false;
        },
        fastOptions(),
        in(5s));
    EXPECT_TRUE(out.ok()) << out.reason;
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(queries(*node).size(), 1u);

    node->clearRequests();
    auto noSort = pagedBody(2);
    noSort.erase("sort");
    auto noSize = pagedBody(2);
    noSize.erase("size");
    const auto never = [](const nlohmann::json&)
    {
        ADD_FAILURE() << "page() called for an invalid body";
        return true;
    };
    out = query->searchAfter("idx", noSort, never, fastOptions(), in(5s));
    EXPECT_EQ(out.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(out.reason.rfind("body.sort", 0), 0u) << out.reason;
    out = query->searchAfter("idx", noSize, never, fastOptions(), in(5s));
    EXPECT_EQ(out.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(out.reason.rfind("body.size", 0), 0u) << out.reason;
    EXPECT_EQ(queries(*node).size(), 0u);
}

// I87: the page deadline bounds each page. Page 2 is held with a long Deadline (10 s) and pageDeadline 500 ms ⇒
// Unavailable "page deadline expired" ~500 ms after page 2 started, page() called once.
TEST_F(QueryTest, SearchAfterPageDeadlineIsPerPage)
{
    auto paged = pagedRule("/idx/_search");
    auto answer = paged.dynamic;
    paged.dynamic = [answer](const httplib::Request& request, Rule& reply)
    {
        answer(request, reply);
        reply.hold = request.body.find("search_after") != std::string::npos;
    };
    const auto node = fake({paged});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.pageDeadline = 500ms;

    int calls = 0;
    const auto started = now();
    auto out = query->searchAfter(
        "idx",
        pagedBody(2),
        [&](const nlohmann::json&)
        {
            ++calls;
            return true;
        },
        options,
        started + 10s);
    const auto took = since(started);
    node->releaseHeld();
    EXPECT_EQ(out.cause, ic::Cause::Unavailable);
    EXPECT_NE(out.reason.find("page deadline expired"), std::string::npos) << out.reason;
    EXPECT_EQ(calls, 1);
    const auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 2u);
    const auto page2 = std::chrono::duration_cast<std::chrono::milliseconds>(now() - sent[1].receivedAt);
    EXPECT_GE(took, 500ms);
    EXPECT_LT(took, 500ms + scaled(500ms)) << "the page ended late";
    EXPECT_GE(page2, 450ms) << "page 2 ended before its own deadline";
}

// CA-14: node A Available with its port closed now, B sound ⇒ every search Ok through B, A goes Down (one failover).
// Mutant: the failover retried on the same node.
TEST_F(QueryTest, ReadFailsOverToOtherNode)
{
    const auto a = fake({rule("POST", "/idx/_search", 200, searchResponse(nlohmann::json::array()))});
    const auto b = fake({rule("POST", "/idx/_search", 200, searchResponse(nlohmann::json::array()))});
    ASSERT_NO_FATAL_FAILURE(start({a->baseUrl(), b->baseUrl()}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Available);
    auto owner = client();
    auto query = owner->query();
    a->stop(); // Still Available in the NodeSet; connecting is refused now.

    const auto before = q::queryStats();
    for (int i = 0; i < 2; ++i)
    {
        auto out = query->search("idx", MATCH_ALL, fastOptions(), in(3s));
        ASSERT_TRUE(out.ok()) << i << ": " << ic::toString(out.cause) << ": " << out.reason;
    }
    const auto d = delta(before, q::queryStats());
    EXPECT_EQ(d.failovers, 1u);
    EXPECT_EQ(nodeState(0), NodeState::Down);
    EXPECT_EQ(nodeState(1), NodeState::Available);
    EXPECT_EQ(queries(*b).size(), 2u);
}

// CA-14: every node Down ⇒ search, indexExists and deleteByQuery end Unavailable when the Deadline expires, never
// `false` or an empty answer, and send nothing. Mutant: indexExists answers false on an error.
TEST_F(QueryTest, ReadsUnavailableWhenAllDown)
{
    const std::string a = "http://127.0.0.1:" + std::to_string(component::closedPort());
    const std::string b = "http://127.0.0.1:" + std::to_string(component::closedPort());
    ASSERT_NO_FATAL_FAILURE(start({a, b}));
    ASSERT_EQ(nodeState(0), NodeState::Down);
    ASSERT_EQ(nodeState(1), NodeState::Down);
    auto owner = client();
    auto query = owner->query();
    constexpr auto DEADLINE = 300ms;
    const auto before = q::queryStats();

    auto started = now();
    auto search = query->search("idx", MATCH_ALL, fastOptions(), started + DEADLINE);
    auto took = since(started);
    EXPECT_EQ(search.cause, ic::Cause::Unavailable) << search.reason;
    EXPECT_NE(search.reason.find("deadline expired"), std::string::npos) << search.reason;
    EXPECT_GE(took, DEADLINE);
    EXPECT_LT(took, DEADLINE + scaled(500ms));

    started = now();
    auto exists = query->indexExists("idx", fastOptions(), started + DEADLINE);
    took = since(started);
    EXPECT_EQ(exists.cause, ic::Cause::Unavailable) << "value " << exists.value << ": " << exists.reason;
    EXPECT_FALSE(exists.ok());
    EXPECT_GE(took, DEADLINE);
    EXPECT_LT(took, DEADLINE + scaled(500ms));

    started = now();
    auto dbq = query->deleteByQuery({"idx"}, MATCH_ALL, {}, fastOptions(), started + DEADLINE);
    took = since(started);
    EXPECT_EQ(dbq.cause, ic::Cause::Unavailable) << dbq.reason;
    EXPECT_GE(took, DEADLINE);
    EXPECT_LT(took, DEADLINE + scaled(500ms));

    const auto d = delta(before, q::queryStats());
    EXPECT_EQ(d.requests, 0u);
    EXPECT_EQ(d.unavailable, 3u);
}

// I87: the consumer's Deadline is never an HTTP timeout. A held search with a 200 ms Deadline ⇒ Unavailable at the
// Deadline; the node stays Available with no transition. Mutant: the HTTP timeout = Deadline - now (the transfer
// ends by its own timeout, which is reported).
TEST_F(QueryTest, ShortDeadlineKeepsNodeAvailable)
{
    auto held = rule("POST", "/idx/_search");
    held.hold = true;
    const auto node = fake({held});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    const auto transitionsBefore = transitions(0);
    auto owner = client();
    auto query = owner->query();

    const auto started = now();
    auto out = query->search("idx", MATCH_ALL, fastOptions(), started + 200ms);
    const auto took = since(started);
    EXPECT_EQ(out.cause, ic::Cause::Unavailable) << out.reason;
    EXPECT_NE(out.reason.find("deadline expired"), std::string::npos) << out.reason;
    EXPECT_GE(took, 200ms);
    EXPECT_LT(took, 200ms + scaled(500ms));
    std::this_thread::sleep_for(100ms); // The cancelled transfer's callback lands in the meantime.
    EXPECT_EQ(nodeState(0), NodeState::Available);
    EXPECT_EQ(transitions(0), transitionsBefore);
    node->releaseHeld();
}

// I87/I82, CA-14: a node that accepts and never answers. request_timeout_ms = 300 and pageDeadline 2 s: the attempt has
// the whole per-attempt budget, so its Timeout is reported ⇒ A Down (one transition), the search fails over to B and
// both searches are Ok. Mutant: the Timeout not reported to the NodeSet.
TEST_F(QueryTest, HungNodeTimesOutAndFailsOver)
{
    auto held = rule("POST", "/idx/_search");
    held.hold = true;
    const auto a = fake({held});
    const auto b = fake({rule("POST", "/idx/_search", 200, searchResponse(nlohmann::json::array()))});
    ASSERT_NO_FATAL_FAILURE(start({a->baseUrl(), b->baseUrl()}, {{"request_timeout_ms", "300"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Available);
    const auto transitionsBefore = transitions(0);
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.pageDeadline = 2s;

    const auto before = q::queryStats();
    const auto started = now();
    for (int i = 0; i < 2; ++i)
    {
        auto out = query->search("idx", MATCH_ALL, options, in(5s));
        ASSERT_TRUE(out.ok()) << i << ": " << ic::toString(out.cause) << ": " << out.reason;
    }
    const auto took = since(started);
    const auto d = delta(before, q::queryStats());
    EXPECT_EQ(d.failovers, 1u);
    EXPECT_EQ(d.unavailable, 0u);
    EXPECT_EQ(nodeState(0), NodeState::Down);
    EXPECT_EQ(transitions(0), transitionsBefore + 1);
    EXPECT_EQ(nodeState(1), NodeState::Available);
    EXPECT_EQ(queries(*a).size(), 1u) << "the hung node was chosen again";
    EXPECT_EQ(queries(*b).size(), 2u);
    EXPECT_GE(took, 300ms) << "the hung attempt ended before its timeout";
    EXPECT_LT(took, 300ms + scaled(1000ms)) << "the failover waited for the page deadline";
    a->releaseHeld();
}

// G-diff E4a obj. 1 (b): with pageDeadline < requestTimeout (the defaults' shape) the first attempt's timeout is the
// page itself; the result wait runs TIMEOUT_GRACE past the page so curl's Timeout reaches NodeSet::report. A single
// hung node: the query ends Unavailable (its page is spent) and the node is Down. Mutant: the wait bounded by the page.
TEST_F(QueryTest, HungNodeReportedWhenThePageIsTheBudget)
{
    auto held = rule("POST", "/idx/_search");
    held.hold = true;
    const auto a = fake({held});
    ASSERT_NO_FATAL_FAILURE(start({a->baseUrl()}, {{"request_timeout_ms", "5000"}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.pageDeadline = 500ms;

    const auto started = now();
    const auto out = query->search("idx", MATCH_ALL, options, in(5s));
    const auto took = since(started);
    EXPECT_EQ(out.cause, ic::Cause::Unavailable) << out.reason;
    EXPECT_EQ(nodeState(0), NodeState::Down) << "the hung node was not reported";
    EXPECT_GE(took, 500ms);
    EXPECT_LT(took, 500ms + scaled(1500ms));
    a->releaseHeld();
}

// I82: a 429 with Retry-After: 1 and then 200 ⇒ Ok, the second request >= 1 s after the first; with maxAttempts = 1
// too (a 429 spends no attempt). Mutant: Retry-After ignored.
TEST_F(QueryTest, Query429HonoursRetryAfter)
{
    auto throttled = []
    {
        auto r = rule("POST", "/idx/_search", 429, errorBody("rejected_execution_exception", "busy", 429));
        r.retryAfter = "1";
        r.times = 1;
        return r;
    };
    const auto ok = rule("POST", "/idx/_search", 200, searchResponse(nlohmann::json::array()));
    const auto node = fake({throttled(), ok});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    for (const std::uint32_t attempts : {5u, 1u})
    {
        auto options = fastOptions();
        options.retry.maxAttempts = attempts;
        const auto before = q::queryStats();
        auto out = query->search("idx", MATCH_ALL, options, in(10s));
        ASSERT_TRUE(out.ok()) << attempts << ": " << ic::toString(out.cause) << ": " << out.reason;
        const auto sent = queries(*node);
        ASSERT_EQ(sent.size(), 2u);
        EXPECT_GE(gap(sent[0], sent[1]), 1000ms) << "maxAttempts " << attempts;
        EXPECT_LT(gap(sent[0], sent[1]), 1000ms + scaled(500ms)) << "maxAttempts " << attempts;
        EXPECT_EQ(delta(before, q::queryStats()).throttles, 1u);
        rules(*node, {throttled(), ok});
        node->clearRequests();
    }
}

// I82: three 429 without Retry-After back off with growing gaps (base 100 ms, no jitter: ~100, 200, 400 ms) and
// spend no attempt (maxAttempts = 1, then Ok).
TEST_F(QueryTest, Query429WithoutRetryAfterBacksOff)
{
    auto throttled = rule("POST", "/idx/_search", 429, errorBody("rejected_execution_exception", "busy", 429));
    throttled.times = 3;
    const auto node = fake({throttled, rule("POST", "/idx/_search", 200, searchResponse(nlohmann::json::array()))});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.retry.base = ic::Duration {100};
    options.retry.cap = ic::Duration {10000};
    options.retry.maxAttempts = 1;

    auto out = query->search("idx", MATCH_ALL, options, in(10s));
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    const auto sent = queries(*node);
    ASSERT_EQ(sent.size(), 4u);
    const auto g1 = gap(sent[0], sent[1]);
    const auto g2 = gap(sent[1], sent[2]);
    const auto g3 = gap(sent[2], sent[3]);
    EXPECT_GE(g1, 100ms);
    EXPECT_GE(g2, 200ms);
    EXPECT_GE(g3, 400ms);
    EXPECT_GT(g2, g1);
    EXPECT_GT(g3, g2);
}

// I82: retry.base = 0, retry.cap < retry.base, retry.jitter > 1 or NaN, retry.maxAttempts = 0, retry.maxDuration = 0
// and pageDeadline = 0 ⇒ InvalidArgument naming the field, no request.
TEST_F(QueryTest, QueryRejectsZeroBase)
{
    const auto node = fake();
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    const auto before = q::queryStats();

    auto zeroBase = fastOptions();
    zeroBase.retry.base = ic::Duration {0};
    auto capBelow = fastOptions();
    capBelow.retry.base = ic::Duration {100};
    capBelow.retry.cap = ic::Duration {50};
    auto zeroPage = fastOptions();
    zeroPage.pageDeadline = ic::Duration {0};
    auto jitterAbove = fastOptions();
    jitterAbove.retry.jitter = 1.5;
    auto jitterNan = fastOptions();
    jitterNan.retry.jitter = std::numeric_limits<double>::quiet_NaN();
    auto zeroAttempts = fastOptions();
    zeroAttempts.retry.maxAttempts = 0u;
    auto zeroDuration = fastOptions();
    zeroDuration.retry.maxDuration = ic::Duration {0};
    const std::vector<std::pair<ic::QueryOptions, std::string>> cases {{zeroBase, "retry.base"},
                                                                       {capBelow, "retry.cap"},
                                                                       {zeroPage, "pageDeadline"},
                                                                       {jitterAbove, "retry.jitter"},
                                                                       {jitterNan, "retry.jitter"},
                                                                       {zeroAttempts, "retry.maxAttempts"},
                                                                       {zeroDuration, "retry.maxDuration"}};
    for (const auto& [options, field] : cases)
    {
        auto search = query->search("idx", MATCH_ALL, options, in(5s));
        EXPECT_EQ(search.cause, ic::Cause::InvalidArgument) << field;
        EXPECT_EQ(search.reason.rfind(field, 0), 0u) << search.reason;
        auto exists = query->indexExists("idx", options, in(5s));
        EXPECT_EQ(exists.cause, ic::Cause::InvalidArgument) << field;
        auto dbq = query->deleteByQuery({"idx"}, MATCH_ALL, {}, options, in(5s));
        EXPECT_EQ(dbq.cause, ic::Cause::InvalidArgument) << field;
        auto ubq = query->updateByQuery({"idx"}, MATCH_ALL, options, in(5s));
        EXPECT_EQ(ubq.cause, ic::Cause::InvalidArgument) << field;
        auto paged =
            query->searchAfter("idx", pagedBody(2), [](const nlohmann::json&) { return true; }, options, in(5s));
        EXPECT_EQ(paged.cause, ic::Cause::InvalidArgument) << field;
    }
    EXPECT_EQ(delta(before, q::queryStats()).requests, 0u);
    EXPECT_EQ(queries(*node).size(), 0u);
}

// I82: a 503 every time with maxAttempts = 3 ⇒ RetryExhausted after 3 requests; a 400 ⇒ Client4xx after 1, its
// reason the error type and at most REASON_BODY_BYTES of the body.
TEST_F(QueryTest, QueryRetriesAndExhausts)
{
    const std::string longReason(1000, 'r');
    const auto node = fake({rule("POST", "/busy/_search", 503, errorBody("unavailable", "busy", 503)),
                            rule("POST", "/bad/_search", 400, errorBody("parsing_exception", longReason, 400))});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    auto options = fastOptions();
    options.retry.maxAttempts = 3;

    auto out = query->search("busy", MATCH_ALL, options, in(10s));
    EXPECT_EQ(out.cause, ic::Cause::RetryExhausted) << out.reason;
    EXPECT_EQ(out.httpStatus, 503);
    EXPECT_EQ(queries(*node).size(), 3u);

    node->clearRequests();
    out = query->search("bad", MATCH_ALL, options, in(10s));
    EXPECT_EQ(out.cause, ic::Cause::Client4xx) << out.reason;
    EXPECT_EQ(out.httpStatus, 400);
    EXPECT_EQ(queries(*node).size(), 1u);
    const std::string prefix = "400 parsing_exception: ";
    EXPECT_EQ(out.reason.rfind(prefix, 0), 0u) << out.reason;
    EXPECT_LE(out.reason.size(), prefix.size() + q::REASON_BODY_BYTES) << out.reason;
    EXPECT_NE(out.reason.find("rrrr"), std::string::npos) << out.reason;
}

// I83: indexExists is a HEAD: 200 ⇒ true, 404 ⇒ false, 503 then 200 ⇒ true; also over the fake's TLS. Mutant: a 404
// treated as an error.
TEST_F(QueryTest, IndexExistsUsesHead)
{
    const auto exercise = [](ic::IQuery& query, indexer_client::testing::FakeIndexer& node, const std::string& label)
    {
        auto present = query.indexExists("present", fastOptions(), in(5s));
        ASSERT_TRUE(present.ok()) << label << ": " << ic::toString(present.cause) << ": " << present.reason;
        EXPECT_TRUE(present.value) << label;
        auto absent = query.indexExists("absent", fastOptions(), in(5s));
        ASSERT_TRUE(absent.ok()) << label << ": " << ic::toString(absent.cause) << ": " << absent.reason;
        EXPECT_FALSE(absent.value) << label;
        auto flaky = query.indexExists("flaky", fastOptions(), in(5s));
        ASSERT_TRUE(flaky.ok()) << label << ": " << ic::toString(flaky.cause) << ": " << flaky.reason;
        EXPECT_TRUE(flaky.value) << label;
        const auto sent = queries(node);
        ASSERT_EQ(sent.size(), 4u) << label;
        const std::vector<std::string> paths {"/present", "/absent", "/flaky", "/flaky"};
        for (std::size_t i = 0; i < sent.size(); ++i)
        {
            EXPECT_EQ(sent[i].method, "HEAD") << label << " " << i;
            EXPECT_EQ(sent[i].path, paths[i]) << label << " " << i;
            EXPECT_EQ(sent[i].bodySize, 0u) << label << " " << i;
        }
    };
    const auto headRules = []
    {
        auto flaky = rule("HEAD", "/flaky", 503);
        flaky.times = 1;
        return std::vector<Rule> {
            rule("HEAD", "/present", 200), rule("HEAD", "/absent", 404), flaky, rule("HEAD", "/flaky", 200)};
    };

    {
        const auto node = fake(headRules());
        ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
        auto c = client();
        ASSERT_NO_FATAL_FAILURE(exercise(*c->query(), *node, "http"));
    }
    indexer_client::RuntimeOwner::shutdown();

    indexer_client::testing::TlsMaterialFactory material;
    FakeIndexerOptions tlsOptions;
    tlsOptions.recordBodies = true;
    tlsOptions.tls = indexer_client::testing::FakeTlsOptions {material.serverCertificate(), material.serverKey(), {}};
    const auto secure = fake(headRules(), tlsOptions);
    ASSERT_TRUE(secure->tls());
    ASSERT_NO_FATAL_FAILURE(start(
        {secure->baseUrl()}, {}, nlohmann::json {{"certificate_authorities", {material.caCertificate()}}}.dump()));
    ASSERT_EQ(nodeState(0), NodeState::Available) << "the TLS node never became Available";
    auto c = client();
    ASSERT_NO_FATAL_FAILURE(exercise(*c->query(), *secure, "https"));
}

// I85: a 404 index_not_found_exception ⇒ search, searchAfter and UBQ NotFound with the type in reason, DBQ Ok({}); a
// 404 of another type ⇒ Client4xx for search and DBQ.
TEST_F(QueryTest, MissingIndexIsNotFound)
{
    const auto otherNotFound = errorBody("resource_not_found_exception", "no such thing", 404);
    const auto node = fake({rule("POST", "/missing/_search", 404, indexNotFound("missing")),
                            rule("POST", "/missing/_update_by_query", 404, indexNotFound("missing")),
                            rule("POST", "/missing/_delete_by_query", 404, indexNotFound("missing")),
                            rule("POST", "/other/_search", 404, otherNotFound),
                            rule("POST", "/other/_delete_by_query", 404, otherNotFound)});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    auto search = query->search("missing", MATCH_ALL, fastOptions(), in(5s));
    EXPECT_EQ(search.cause, ic::Cause::NotFound) << search.reason;
    EXPECT_EQ(search.httpStatus, 404);
    EXPECT_NE(search.reason.find("index_not_found_exception"), std::string::npos) << search.reason;

    bool paged = false;
    auto after = query->searchAfter(
        "missing",
        pagedBody(2),
        [&](const nlohmann::json&)
        {
            paged = true;
            return true;
        },
        fastOptions(),
        in(5s));
    EXPECT_EQ(after.cause, ic::Cause::NotFound) << after.reason;
    EXPECT_NE(after.reason.find("index_not_found_exception"), std::string::npos) << after.reason;
    EXPECT_FALSE(paged);

    auto ubq = query->updateByQuery({"missing"}, MATCH_ALL, fastOptions(), in(5s));
    EXPECT_EQ(ubq.cause, ic::Cause::NotFound) << ubq.reason;
    EXPECT_NE(ubq.reason.find("index_not_found_exception"), std::string::npos) << ubq.reason;

    auto dbq = query->deleteByQuery({"missing"}, MATCH_ALL, {}, fastOptions(), in(5s));
    ASSERT_TRUE(dbq.ok()) << ic::toString(dbq.cause) << ": " << dbq.reason;
    EXPECT_EQ(dbq.value, nlohmann::json::object());

    auto other = query->search("other", MATCH_ALL, fastOptions(), in(5s));
    EXPECT_EQ(other.cause, ic::Cause::Client4xx) << other.reason;
    EXPECT_EQ(other.httpStatus, 404);
    auto otherDbq = query->deleteByQuery({"other"}, MATCH_ALL, {}, fastOptions(), in(5s));
    EXPECT_EQ(otherDbq.cause, ic::Cause::Client4xx) << otherDbq.reason;
    EXPECT_EQ(otherDbq.httpStatus, 404);
    EXPECT_EQ(queries(*node).size(), 6u) << "each 404 is final: one request per call";
}

// RF-27: every operation called from a runtime thread (a CPU-pool task and a network-loop task) ⇒ Reentrancy, no
// request.
TEST_F(QueryTest, QueryFromRuntimeThreadIsReentrancy)
{
    const auto node = fake();
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();

    struct Seen
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::size_t done {0};
        std::vector<bool> onRuntimeThread;
        std::vector<std::vector<ic::Cause>> causes;
    };
    auto seen = std::make_shared<Seen>();
    const auto task = [seen, query]
    {
        std::vector<ic::Cause> causes;
        causes.push_back(query->search("idx", MATCH_ALL, fastOptions(), in(5s)).cause);
        causes.push_back(
            query->searchAfter(
                     "idx", pagedBody(2), [](const nlohmann::json&) { return true; }, fastOptions(), in(5s))
                .cause);
        causes.push_back(query->pit({"idx"}, {}, fastOptions(), in(5s)).cause);
        causes.push_back(query->deleteByQuery({"idx"}, MATCH_ALL, {}, fastOptions(), in(5s)).cause);
        causes.push_back(query->updateByQuery({"idx"}, MATCH_ALL, fastOptions(), in(5s)).cause);
        causes.push_back(query->indexExists("idx", fastOptions(), in(5s)).cause);
        {
            std::lock_guard<std::mutex> lock(seen->mutex);
            seen->onRuntimeThread.push_back(indexer_client::detail::testing::onRuntimeThread());
            seen->causes.push_back(std::move(causes));
            ++seen->done;
        }
        seen->cv.notify_all();
    };
    const auto before = q::queryStats();
    ASSERT_TRUE(indexer_client::detail::testing::postToPool(task));
    ASSERT_TRUE(indexer_client::detail::testing::postToIoLoop(task));
    {
        std::unique_lock<std::mutex> lock(seen->mutex);
        ASSERT_TRUE(seen->cv.wait_for(lock, 5s, [&] { return seen->done == 2; }));
    }
    EXPECT_EQ(seen->onRuntimeThread, (std::vector<bool> {true, true}));
    for (const auto& causes : seen->causes)
    {
        EXPECT_EQ(causes, std::vector<ic::Cause>(6, ic::Cause::Reentrancy));
    }
    EXPECT_EQ(delta(before, q::queryStats()).requests, 0u);
    EXPECT_EQ(queries(*node).size(), 0u);
}

// I87: no wait outlives a close. (1) A 503 with a 10 s backoff: requestClose() ⇒ ClientClosed < 1 s. (2) A held
// request: shutdown() (from the owner thread; the query runs on another) ⇒ Shutdown < 1 s. (3) A query with the
// runtime stopped ⇒ Shutdown, no request. Mutant: neither requestClose() nor stopAndJoin() wakes the gate.
TEST_F(QueryTest, QueryWakesOnCloseAndShutdown)
{
    auto held = rule("POST", "/held/_search");
    held.hold = true;
    const auto node = fake({rule("POST", "/busy/_search", 503, errorBody("unavailable", "busy", 503)), held});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto options = fastOptions();
    options.retry.base = ic::Duration {10000};
    options.retry.cap = ic::Duration {10000};

    // (1) requestClose() during the backoff.
    auto closing = client("closing");
    auto closingQuery = closing->query();
    auto closed = std::make_shared<ic::Outcome<nlohmann::json>>();
    {
        component::AsyncCall call([closingQuery, options, closed]
                                  { *closed = closingQuery->search("busy", MATCH_ALL, options, in(30s)); });
        ASSERT_TRUE(component::eventually([&] { return queries(*node).size() == 1; }, 5s))
            << "the search never reached the fake";
        std::this_thread::sleep_for(100ms); // In its backoff now.
        const auto t0 = now();
        closing->requestClose();
        ASSERT_TRUE(call.wait(scaled(1000ms))) << "requestClose() did not wake the backoff";
        EXPECT_LT(since(t0), scaled(1000ms));
    }
    EXPECT_EQ(closed->cause, ic::Cause::ClientClosed) << closed->reason;

    // (2) shutdown() while the attempt is held.
    auto c = client("held");
    auto query = c->query();
    auto stopped = std::make_shared<ic::Outcome<nlohmann::json>>();
    {
        component::AsyncCall call([query, stopped]
                                  { *stopped = query->search("held", MATCH_ALL, fastOptions(), in(30s)); });
        ASSERT_TRUE(node->waitHeld(1, 5s)) << "the search was never held";
        const auto t0 = now();
        indexer_client::RuntimeOwner::shutdown();
        ASSERT_TRUE(call.wait(scaled(1000ms))) << "shutdown() did not end the held query";
        EXPECT_LT(since(t0), scaled(1000ms));
    }
    EXPECT_EQ(stopped->cause, ic::Cause::Shutdown) << stopped->reason;

    // (3) The runtime is gone.
    node->releaseHeld();
    const auto before = q::queryStats();
    const auto requestsBefore = node->requestCount();
    auto late = query->search("held", MATCH_ALL, fastOptions(), in(1s));
    EXPECT_EQ(late.cause, ic::Cause::Shutdown) << late.reason;
    auto lateExists = query->indexExists("held", fastOptions(), in(1s));
    EXPECT_EQ(lateExists.cause, ic::Cause::Shutdown) << lateExists.reason;
    EXPECT_EQ(delta(before, q::queryStats()).requests, 0u);
    EXPECT_EQ(node->requestCount(), requestsBefore);
}

// I84: a 2xx body above maxResponseBytes / QUERY_DOM_FACTOR ⇒ ItemPermanent without parsing (queryStats.tooLarge);
// a valid body of exactly that size is Ok.
TEST_F(QueryTest, QueryResponseCap)
{
    constexpr std::uint64_t MAX_RESPONSE = 64000;
    const std::uint64_t fits = MAX_RESPONSE / q::QUERY_DOM_FACTOR;
    const auto jsonOf = [](std::uint64_t bytes)
    {
        return R"({"p":")" + std::string(bytes - 8, 'x') + R"("})";
    };
    ASSERT_EQ(jsonOf(fits).size(), fits);
    const auto node =
        fake({rule("POST", "/fits/_search", 200, jsonOf(fits)), rule("POST", "/large/_search", 200, jsonOf(fits + 1))});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"max_response_bytes", std::to_string(MAX_RESPONSE)}}));
    auto owner = client();
    auto query = owner->query();

    auto before = q::queryStats();
    auto ok = query->search("fits", MATCH_ALL, fastOptions(), in(5s));
    ASSERT_TRUE(ok.ok()) << ic::toString(ok.cause) << ": " << ok.reason;
    EXPECT_EQ(ok.value.at("p").get<std::string>().size(), fits - 8);
    EXPECT_EQ(delta(before, q::queryStats()).tooLarge, 0u);

    before = q::queryStats();
    auto large = query->search("large", MATCH_ALL, fastOptions(), in(5s));
    EXPECT_EQ(large.cause, ic::Cause::ItemPermanent) << large.reason;
    EXPECT_NE(large.reason.find("response too large"), std::string::npos) << large.reason;
    const auto d = delta(before, q::queryStats());
    EXPECT_EQ(d.tooLarge, 1u);
    EXPECT_EQ(d.requests, 1u) << "a too-large answer is final";
}

// I87: unsafe or missing index names (also "." and "..", which libcurl collapses, and "_all") ⇒ InvalidArgument naming
// the field, no request; pit() validates its indices the same way (E4b).
TEST_F(QueryTest, QueryRejectsUnsafeIndex)
{
    const auto node = fake();
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto owner = client();
    auto query = owner->query();
    const auto before = q::queryStats();

    for (const std::string bad : {"", "a/b", "a?b", "a b", "a#b", ".", "..", "...", "_all", "_search"})
    {
        auto search = query->search(bad, MATCH_ALL, fastOptions(), in(5s));
        EXPECT_EQ(search.cause, ic::Cause::InvalidArgument) << "'" << bad << "'";
        EXPECT_EQ(search.reason.rfind("index", 0), 0u) << search.reason;
        auto exists = query->indexExists(bad, fastOptions(), in(5s));
        EXPECT_EQ(exists.cause, ic::Cause::InvalidArgument) << "'" << bad << "'";
        EXPECT_EQ(exists.reason.rfind("index", 0), 0u) << exists.reason;
        auto paged =
            query->searchAfter(bad, pagedBody(2), [](const nlohmann::json&) { return true; }, fastOptions(), in(5s));
        EXPECT_EQ(paged.cause, ic::Cause::InvalidArgument) << "'" << bad << "'";
        auto dbq = query->deleteByQuery({"ok", bad}, MATCH_ALL, {}, fastOptions(), in(5s));
        EXPECT_EQ(dbq.cause, ic::Cause::InvalidArgument) << "'" << bad << "'";
        EXPECT_EQ(dbq.reason.rfind("indices[1]", 0), 0u) << dbq.reason;
        auto ubq = query->updateByQuery({bad}, MATCH_ALL, fastOptions(), in(5s));
        EXPECT_EQ(ubq.cause, ic::Cause::InvalidArgument) << "'" << bad << "'";
        EXPECT_EQ(ubq.reason.rfind("indices[0]", 0), 0u) << ubq.reason;
    }
    auto emptyDbq = query->deleteByQuery({}, MATCH_ALL, {}, fastOptions(), in(5s));
    EXPECT_EQ(emptyDbq.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(emptyDbq.reason.rfind("indices", 0), 0u) << emptyDbq.reason;
    auto emptyUbq = query->updateByQuery({}, MATCH_ALL, fastOptions(), in(5s));
    EXPECT_EQ(emptyUbq.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(emptyUbq.reason.rfind("indices", 0), 0u) << emptyUbq.reason;

    auto pit = query->pit({"a/b"}, {}, fastOptions(), in(5s));
    EXPECT_EQ(pit.cause, ic::Cause::InvalidArgument);
    EXPECT_EQ(pit.reason.rfind("indices[0]", 0), 0u) << pit.reason;

    EXPECT_EQ(delta(before, q::queryStats()).requests, 0u);
    EXPECT_EQ(queries(*node).size(), 0u);
}
