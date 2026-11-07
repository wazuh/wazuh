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

// The NodeSet's notBefore (plan 18, plan-E6a step 3, I109/I109b, CA-E6a-4): a 429 with Retry-After from any path
// (report() in any state, a probe round, a bulk, a query) parks the node for every consumer; choose() skips it; a read
// whose usable nodes are all parked waits for the first one within its deadline. Oracles: NodeSet::notBefore() and
// earliestNotBefore(), choose(), the recorded requests (path, arrival time) and the query Outcome. detail::NodeSet is
// hidden in the .so the utest links, so these cases live in the component suite. The cases that need the sender's
// mirror of notBefore belong to step 4.

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "bulkFixture.hpp"
#include "queryFixture.hpp"
#include "write/sender.hpp"

namespace
{
    using namespace std::chrono_literals;
    namespace ic = indexer_client;
    namespace q = indexer_client::detail::query;
    using bulk_component::BulkScript;
    using indexer_client::detail::NodeSet;
    using indexer_client::detail::TransportCause;
    using indexer_client::testing::Durability;
    using indexer_client::testing::RecordedRequest;
    using query_component::scaled;
    using NodeState = ic::HealthView::NodeState;
    namespace wr = indexer_client::detail::write;

    const nlohmann::json MATCH_ALL = {{"query", {{"match_all", nlohmann::json::object()}}}};
    const std::string SEARCH_PATH = "/idx/_search";

    std::shared_ptr<NodeSet> nodes()
    {
        return indexer_client::detail::runtimeNodeSet();
    }

    ic::TimePoint now()
    {
        return std::chrono::steady_clock::now();
    }

    /// A passive 429 (the body of a rejected execution), with `retryAfter` when given.
    indexer_client::detail::HttpResult throttled(std::optional<ic::Duration> retryAfter = std::nullopt)
    {
        indexer_client::detail::HttpResult result;
        result.cause = TransportCause::None;
        result.status = 429;
        result.body = R"({"error":{"type":"rejected_execution_exception","reason":"busy"},"status":429})";
        result.retryAfter = retryAfter;
        return result;
    }

    /// `POST /idx/_search` ⇒ 200 with no hits.
    indexer_client::testing::Rule searchOk()
    {
        return query_component::rule(
            "POST", SEARCH_PATH, 200, query_component::searchResponse(nlohmann::json::array()));
    }

    /// The search requests a fake received, in arrival order.
    std::vector<RecordedRequest> searches(const indexer_client::testing::FakeIndexer& fake)
    {
        std::vector<RecordedRequest> out;
        for (auto& request : fake.requests())
        {
            if (request.method == "POST" && request.path == SEARCH_PATH)
            {
                out.push_back(std::move(request));
            }
        }
        return out;
    }

    /// A bucket of one-op batches with a fast retry (as bulkVerdicts_test's fastBucket).
    ic::BucketSpec oneOpBucket(std::string name)
    {
        auto spec = write_component::bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, 1);
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        return spec;
    }

    /// A host nothing listens on: its probe is refused, so the node is Down.
    std::string closedHost()
    {
        return "http://127.0.0.1:" + std::to_string(component::closedPort());
    }
} // namespace

class NodeRetryAfterTest : public BulkTest
{
};

// I109: report() parks a node from a 429 with Retry-After whatever its state (Available, Throttled, Down), with max():
// a shorter one never moves it back, a longer one raises it; a 429 without Retry-After or a 2xx leaves it alone. A
// Down node's notBefore is kept but earliestNotBefore() ignores it; choose() skips the parked nodes.
TEST_F(NodeRetryAfterTest, ReportInAnyState)
{
    const auto a = startNode();
    const auto b = startNode();
    const auto c = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url(), c.url()}));
    auto set = nodes();
    ASSERT_EQ(nodeState(0), NodeState::Available);
    ASSERT_EQ(nodeState(1), NodeState::Available);
    ASSERT_EQ(nodeState(2), NodeState::Available);
    EXPECT_EQ(set->notBefore(0), ic::TimePoint {});
    EXPECT_FALSE(set->earliestNotBefore().has_value());

    // Available: the 429 makes it Throttled and parks it.
    auto before = now();
    set->report(0, throttled(5000ms));
    auto after = now();
    EXPECT_EQ(nodeState(0), NodeState::Throttled);
    EXPECT_GE(set->notBefore(0), before + 5000ms);
    EXPECT_LE(set->notBefore(0), after + 5000ms);

    // Throttled: a 429 without Retry-After does not park; one with it does.
    set->report(1, throttled());
    ASSERT_EQ(nodeState(1), NodeState::Throttled);
    EXPECT_EQ(set->notBefore(1), ic::TimePoint {}) << "a 429 without Retry-After parked the node";
    before = now();
    set->report(1, throttled(4000ms));
    after = now();
    EXPECT_GE(set->notBefore(1), before + 4000ms);
    EXPECT_LE(set->notBefore(1), after + 4000ms);

    // Down: parked too (kept for when the probe brings it back), never counted by earliestNotBefore().
    indexer_client::detail::HttpResult refused;
    refused.cause = TransportCause::Connect;
    refused.curlCode = 7;
    set->report(2, refused);
    ASSERT_EQ(nodeState(2), NodeState::Down);
    before = now();
    set->report(2, throttled(1000ms));
    EXPECT_EQ(nodeState(2), NodeState::Down) << "a 429 never revives a Down node";
    EXPECT_GE(set->notBefore(2), before + 1000ms);

    // max(): shorter, absent or a 2xx never move it back; a longer one raises it.
    const auto parked0 = set->notBefore(0);
    set->report(0, throttled(1000ms));
    set->report(0, throttled());
    indexer_client::detail::HttpResult ok;
    ok.status = 200;
    set->report(0, ok);
    EXPECT_EQ(set->notBefore(0), parked0) << "a later, shorter Retry-After moved notBefore back";
    set->report(0, throttled(10000ms));
    EXPECT_GT(set->notBefore(0), parked0);

    // Node 1 (4 s) is the earliest among the not Down; node 2 (1 s) is Down. Nothing is choosable.
    ASSERT_TRUE(set->earliestNotBefore().has_value());
    EXPECT_EQ(*set->earliestNotBefore(), set->notBefore(1));
    EXPECT_EQ(set->choose(), std::nullopt) << "a parked node was chosen";
    EXPECT_EQ(set->choose([](std::size_t) { return true; }), std::nullopt);
}

// I109b: the probe's own 429 with Retry-After parks the node too. Both nodes Throttled (B without Retry-After): the
// round robin would alternate; the parked A is skipped.
TEST_F(NodeRetryAfterTest, ProbeRetryAfter)
{
    const auto a = startNode();
    const auto b = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));

    auto parkedHealth = indexer_client::testing::throttledRule(Durability::Transient);
    parkedHealth.retryAfter = "2";
    a.fake->clearRules();
    a.fake->addRule(parkedHealth);
    a.fake->addRule(indexer_client::testing::bulkRule(a.bulk));
    b.fake->clearRules();
    b.fake->addRule(indexer_client::testing::throttledRule(Durability::Transient));
    b.fake->addRule(indexer_client::testing::bulkRule(b.bulk));

    const auto before = now();
    ASSERT_TRUE(probeNowAndWait());
    const auto after = now();
    auto set = nodes();
    ASSERT_EQ(nodeState(0), NodeState::Throttled);
    ASSERT_EQ(nodeState(1), NodeState::Throttled);
    EXPECT_GE(set->notBefore(0), before + 2000ms);
    EXPECT_LE(set->notBefore(0), after + 2000ms);
    EXPECT_EQ(set->notBefore(1), ic::TimePoint {});
    ASSERT_TRUE(set->earliestNotBefore().has_value());
    EXPECT_EQ(*set->earliestNotBefore(), set->notBefore(0));

    for (int i = 0; i < 6; ++i)
    {
        EXPECT_EQ(set->choose(), std::optional<std::size_t> {1}) << "pick " << i;
    }
    ASSERT_LT(now() - before, 1500ms) << "the picks must end well before Retry-After";
}

// CA-E6a-4 (RF-9): a bulk 429 with Retry-After: 2 on A parks A for the queries too, even once the probe has it
// Available again; they all go to B. Mutant: report() ignores retryAfter (the round robin sends a query to A).
TEST_F(NodeRetryAfterTest, BulkThrottleParksNodeForQuery)
{
    const auto a = startNode();
    const auto b = startNode();
    a.fake->addRule(searchOk());
    b.fake->addRule(searchOk());
    a.bulk->push(BulkScript::throttled("2"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    auto owner = client("c", {oneOpBucket("b")});
    auto writer = owner->writer("b");
    auto results = write_component::Results::create();

    ASSERT_TRUE(writer->submit(write_component::indexOp("k0"), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    const auto throttledAt = now();
    ASSERT_EQ(results->result(0)->status, ic::Status::Ok);
    ASSERT_EQ(a.bulk->answered(), 1u) << "round robin starts at A";
    ASSERT_EQ(b.bulk->answered(), 1u);
    EXPECT_GT(nodes()->notBefore(0), throttledAt) << "the bulk 429 did not park A";

    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available) << "the probe cleared the passive Throttled";

    auto query = owner->query();
    for (int i = 0; i < 6; ++i)
    {
        const auto out = query->search("idx", MATCH_ALL, query_component::fastOptions(), now() + 5s);
        EXPECT_TRUE(out.ok()) << i << ": " << ic::toString(out.cause) << ": " << out.reason;
    }
    ASSERT_LT(now() - throttledAt, 1500ms) << "the queries must end well before Retry-After";
    EXPECT_EQ(searches(*a.fake).size(), 0u) << "a query went to the parked node";
    EXPECT_EQ(searches(*b.fake).size(), 6u);
}

// CA-E6a-4 (I109): A Down and B parked by a bulk 429 with Retry-After: 2 ⇒ a query with a deadline and a pageDeadline
// past Retry-After waits for B's notBefore and succeeds on B; never Unavailable, never sent early.
TEST_F(NodeRetryAfterTest, AllParkedQueryWaits)
{
    const auto b = startNode();
    b.fake->addRule(searchOk());
    b.bulk->push(BulkScript::throttled("2"));
    ASSERT_NO_FATAL_FAILURE(startOn({closedHost(), b.url()}));
    ASSERT_EQ(nodeState(0), NodeState::Down);
    auto owner = client("c", {oneOpBucket("b")});
    auto writer = owner->writer("b");
    auto results = write_component::Results::create();

    ASSERT_TRUE(writer->submit(write_component::indexOp("k0"), results->callback(0)).accepted);
    ASSERT_TRUE(component::eventually([&b] { return b.bulk->answered() >= 1; }, 5000ms));
    const auto answeredAt = now(); // At most a poll after the 429 left the fake: B's wait ends >= answeredAt + ~2 s.
    EXPECT_TRUE(component::eventually([] { return nodes()->notBefore(1) > now(); }, 1000ms))
        << "the bulk 429 did not park B";
    const auto parkedUntil = nodes()->notBefore(1);
    EXPECT_EQ(nodes()->earliestNotBefore(), std::optional<ic::TimePoint> {parkedUntil});

    auto options = query_component::fastOptions();
    options.pageDeadline = 4000ms;
    const auto statsBefore = q::queryStats();
    const auto started = now();
    const auto out = owner->query()->search("idx", MATCH_ALL, options, started + 6s);
    const auto finished = now();
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_EQ(q::queryStats().unavailable - statsBefore.unavailable, 0u);
    const auto sent = searches(*b.fake);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_GE(sent[0].receivedAt, parkedUntil) << "the query reached B before its notBefore";
    EXPECT_GE(sent[0].receivedAt, answeredAt + 1900ms) << "the query did not wait for Retry-After";
    EXPECT_GE(finished, parkedUntil);
    EXPECT_LT(finished, parkedUntil + scaled(1000ms)) << "the query did not wake when B's wait ended";

    ASSERT_TRUE(results->waitTotal(1, 10s)) << "the throttled batch never went back to B";
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
}

// I109: a Retry-After past the consumer's deadline ⇒ the query ends Unavailable at its deadline (no request), not
// after Retry-After. B is parked for 10 s by an earlier query's 429.
TEST_F(NodeRetryAfterTest, QueryRetryAfterBounded)
{
    const auto b = startNode();
    auto parking = query_component::rule(
        "POST", SEARCH_PATH, 429, query_component::errorBody("rejected_execution_exception", "busy", 429));
    parking.retryAfter = "10";
    parking.times = 1;
    b.fake->addRule(parking);
    b.fake->addRule(searchOk());
    ASSERT_NO_FATAL_FAILURE(startOn({closedHost(), b.url()}));
    ASSERT_EQ(nodeState(0), NodeState::Down);
    auto owner = client("c", {});
    auto query = owner->query();

    const auto first = query->search("idx", MATCH_ALL, query_component::fastOptions(), now() + 300ms);
    EXPECT_EQ(first.cause, ic::Cause::Unavailable) << first.reason;
    ASSERT_EQ(searches(*b.fake).size(), 1u);
    EXPECT_GT(nodes()->notBefore(1), now() + 8000ms) << "the query 429 did not park B";

    const auto started = now();
    const auto out = query->search("idx", MATCH_ALL, query_component::fastOptions(), started + 1000ms);
    const auto took = now() - started;
    EXPECT_EQ(out.cause, ic::Cause::Unavailable) << out.reason;
    EXPECT_EQ(searches(*b.fake).size(), 1u) << "a request went to the parked node";
    EXPECT_GE(took, 1000ms);
    EXPECT_LT(took, 1000ms + scaled(500ms)) << "the wait went past the deadline";
}

namespace
{
    /// `POST /idx/_search` ⇒ one 429 with `Retry-After: <seconds>` (then the rule stops matching).
    indexer_client::testing::Rule searchParks(const std::string& seconds)
    {
        auto rule = query_component::rule(
            "POST", SEARCH_PATH, 429, query_component::errorBody("rejected_execution_exception", "busy", 429));
        rule.retryAfter = seconds;
        rule.times = 1;
        return rule;
    }

    /// When each `_bulk` request reached `fake`, in arrival order.
    std::vector<ic::TimePoint> bulkArrivals(const indexer_client::testing::FakeIndexer& fake)
    {
        std::vector<ic::TimePoint> out;
        for (const auto& request : fake.requests())
        {
            if (request.method == "POST" && request.path.find("/_bulk") != std::string::npos)
            {
                out.push_back(request.receivedAt);
            }
        }
        return out;
    }

    std::chrono::milliseconds until(ic::TimePoint when)
    {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(when - std::chrono::steady_clock::now());
        return left.count() > 0 ? left : std::chrono::milliseconds {0};
    }
} // namespace

// CA-E6a-4 (I109b, step 4): the only node is parked by a query's 429 with Retry-After: 2. The sender mirrors the
// NodeSet's notBefore (refreshMirror), so its capacity is 0: no `_bulk` reaches the node during those 2 s and loop 0
// does not spin (runs <= MAX_RUNS, as OrderedNoIdleSpin); the sender's notBefore timer sends the batch once the wait
// ends, without a probe round. Mutant: the mirror without notBefore (dispatch finds no node, requeues and re-slices
// until the node's wait ends: runs explode).
TEST_F(NodeRetryAfterTest, QueryThrottleParksOnlyNodeBulkWaitsNoSpin)
{
    constexpr std::uint64_t MAX_RUNS = 20;
    const auto a = startNode();
    a.fake->addRule(searchParks("2"));
    a.fake->addRule(searchOk());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    const auto scheduler = m_path->scheduler();
    ASSERT_NE(scheduler, nullptr);
    auto owner = client("c", {oneOpBucket("b")});
    auto writer = owner->writer("b");
    auto results = write_component::Results::create();
    const auto rounds = probeRounds();

    const auto first = owner->query()->search("idx", MATCH_ALL, query_component::fastOptions(), now() + 300ms);
    EXPECT_FALSE(first.ok()) << "the query was not throttled";
    ASSERT_EQ(searches(*a.fake).size(), 1u);
    const auto parkedUntil = nodes()->notBefore(0);
    ASSERT_GT(parkedUntil, now() + 1000ms) << "the query 429 did not park A";

    const auto runs = scheduler->stats().runs;
    ASSERT_TRUE(writer->submit(write_component::indexOp("k0"), results->callback(0)).accepted);
    EXPECT_FALSE(component::eventually([&a] { return a.bulk->answered() > 0; }, until(parkedUntil - 100ms)))
        << "a bulk reached the parked node";
    EXPECT_LE(scheduler->stats().runs - runs, MAX_RUNS) << "loop 0 spun while the node was parked";

    ASSERT_TRUE(results->waitTotal(1, 3s)) << "nothing woke the scheduler when the node's wait ended";
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    const auto arrivals = bulkArrivals(*a.fake);
    ASSERT_EQ(arrivals.size(), 1u);
    EXPECT_GE(arrivals[0], parkedUntil) << "sent before Retry-After";
    EXPECT_LT(arrivals[0], parkedUntil + scaled(1000ms)) << "the timer did not send it when the wait ended";
    EXPECT_EQ(probeRounds(), rounds) << "a probe round was needed";
}

// CA-E6a-4 (I109): two nodes; a query's 429 with Retry-After: 2 parks A for the bulk sender too, even once the probe
// has A Available again (the round robin would alternate): every batch goes to B within the 2 s. Mutant: report()
// ignores retryAfter.
TEST_F(NodeRetryAfterTest, QueryThrottleParksNodeForBulk)
{
    constexpr std::uint64_t OPS = 6;
    const auto a = startNode();
    const auto b = startNode();
    a.fake->addRule(searchParks("2"));
    a.fake->addRule(searchOk());
    b.fake->addRule(searchOk());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    auto owner = client("c", {oneOpBucket("b")});
    auto writer = owner->writer("b");
    auto results = write_component::Results::create();

    const auto throttledAt = now();
    const auto first = owner->query()->search("idx", MATCH_ALL, query_component::fastOptions(), now() + 300ms);
    EXPECT_FALSE(first.ok()) << "the query was not throttled";
    ASSERT_EQ(searches(*a.fake).size(), 1u) << "round robin starts at A";
    const auto parkedUntil = nodes()->notBefore(0);
    ASSERT_GT(parkedUntil, now() + 1000ms) << "the query 429 did not park A";
    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available) << "the probe cleared the passive Throttled";

    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(write_component::indexOp("k" + std::to_string(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(OPS, 1000ms));
    ASSERT_LT(now(), parkedUntil) << "the batches must end well before Retry-After";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    EXPECT_EQ(a.bulk->answered(), 0u) << "a bulk went to the parked node";
    EXPECT_EQ(b.bulk->answered(), OPS);
    EXPECT_LT(now() - throttledAt, 2000ms);
}

namespace
{
    /// The sender's view of node `index` (pace, notBefore, paceRelaxed...).
    wr::SenderNodeStats senderNode(std::size_t index)
    {
        const auto stats = wr::senderStats();
        EXPECT_GT(stats.nodes.size(), index);
        return stats.nodes.size() > index ? stats.nodes[index] : wr::SenderNodeStats {};
    }
} // namespace

// G-diff E6a obj. 1 (I98 with the I109b mirror): a park mirrored from a query's 429 must not break the pacing burst.
// One node, its whole window (4) of one-op batches held, each scripted as a 429 without Retry-After; a query's 429 with
// Retry-After: 3 parks the node (mirrored into the sender's notBefore, beyond now + pace); then the four 429 are
// released: one burst doubles the pace once (pace == paceInitial, not x8), and once the park ends the batches go out
// as 2xx clean sends and paceRelaxAfter (2) of them relax the pace (paceRelaxed == 1, pace 0). Mutant: the burst
// marker moved only when notBefore is raised (every 429 doubles: pace 8 x paceInitial; the marker never set: the pace
// never relaxes).
TEST_F(NodeRetryAfterTest, MirroredParkKeepsOnePaceDoublingPerBurst)
{
    constexpr auto PACE = 200ms;
    const std::uint32_t window = ic::RuntimeConfig {}.nodeWindowMax;
    const auto a = startNode();
    for (std::uint32_t k = 0; k < window; ++k)
    {
        a.bulk->push(BulkScript::throttled().held());
    }
    a.fake->addRule(searchParks("3"));
    ASSERT_NO_FATAL_FAILURE(
        startOn({a.url()}, std::chrono::hours(1), {{"pace_initial_ms", "200"}, {"pace_relax_after", "2"}}));
    auto owner = client("c", {oneOpBucket("b")});
    auto writer = owner->writer("b");
    auto results = write_component::Results::create();
    for (std::uint64_t k = 0; k < window; ++k)
    {
        ASSERT_TRUE(writer->submit(write_component::indexOp("k" + std::to_string(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(a.fake->waitHeld(window, 3s));

    const auto first = owner->query()->search("idx", MATCH_ALL, query_component::fastOptions(), now() + 300ms);
    EXPECT_FALSE(first.ok()) << "the query was not throttled";
    const auto parkedUntil = nodes()->notBefore(0);
    ASSERT_GT(parkedUntil, now() + 2000ms) << "the query 429 did not park A";
    ASSERT_TRUE(component::eventually([&] { return senderNode(0).notBefore == std::optional {parkedUntil}; }, 3s))
        << "the sender did not mirror the park";
    const auto parked = senderNode(0);
    EXPECT_EQ(parked.pace, ic::Duration {0}) << "precondition: no bulk 429 yet";

    a.fake->releaseHeld();
    ASSERT_TRUE(component::eventually([] { return wr::senderStats().throttled == 4u; }, 3s));
    ASSERT_LT(now(), parkedUntil) << "the burst must complete inside the park";
    const auto burst = senderNode(0);
    EXPECT_EQ(burst.pace, ic::Duration {PACE}) << "one burst doubles the pace once (paceInitial)";
    EXPECT_EQ(burst.notBefore, std::optional {parkedUntil}) << "the park is still the notBefore in force";
    EXPECT_EQ(burst.paceRelaxed, 0u);

    ASSERT_TRUE(results->waitTotal(window, 10s)) << "the throttled batches never went out after the park";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), window);
    const auto arrivals = bulkArrivals(*a.fake);
    ASSERT_EQ(arrivals.size(), 2u * window);
    EXPECT_GE(arrivals[window], parkedUntil) << "a batch left before the park ended";
    ASSERT_TRUE(component::eventually([] { return senderNode(0).paceRelaxed == 1u; }, 3s))
        << "the pace never relaxed after the park (paceRelaxed " << senderNode(0).paceRelaxed << ")";
    EXPECT_EQ(senderNode(0).pace, ic::Duration {0}) << "PACE / 2 is below paceInitial";
}
