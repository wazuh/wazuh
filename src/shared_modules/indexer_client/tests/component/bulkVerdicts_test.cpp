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

// The bulk sender end to end: the body it sends, the item and request verdicts it
// applies, the retry policy of the bucket, the splits and the per-node 429
// state (notBefore, pace, the passive report). Every case runs the production sink over the real transport against
// one fake per node (bulkFixture.hpp); the probe interval is an hour, so a case moves health only with
// probeNowAndWait(). Every wait is bounded; every case ends with the charge and the retained ops at 0 (TearDown).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "bulkFixture.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;
using ::testing::HasSubstr;

namespace
{
    using NodeState = ic::HealthView::NodeState;

    /// Fixed-width ids: the key is recoverable from the `_id` the fake received.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    ic::Op deleteOp(std::string docId, std::string index = "wazuh-states-test")
    {
        ic::Op op;
        op.kind = ic::Op::Kind::Delete;
        op.index = std::move(index);
        op.id = std::move(docId);
        return op;
    }

    /// A bucket of `maxDocs`-op batches (no age-based batch) with a fast retry: 5 ms, capped at 20 ms, no jitter,
    /// `maxAttempts` (nullopt: unlimited) and no maxDuration.
    ic::BucketSpec fastBucket(std::string name, std::size_t maxDocs, std::optional<std::uint32_t> maxAttempts)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = maxAttempts;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        return spec;
    }

    /// Every op the fake received with this `_id`, over all its requests.
    std::size_t receivedWithId(const bulk_component::Node& node, const std::string& docId)
    {
        std::size_t n = 0;
        for (const auto& request : node.bulk->received())
        {
            for (const auto& op : request)
            {
                n += op.id == docId ? 1 : 0;
            }
        }
        return n;
    }

    /// The `_bulk` requests the fake recorded (the probe's GETs left out).
    std::vector<indexer_client::testing::RecordedRequest> bulkRequests(const bulk_component::Node& node)
    {
        std::vector<indexer_client::testing::RecordedRequest> out;
        for (auto& request : node.fake->requests())
        {
            if (request.method == "POST")
            {
                out.push_back(std::move(request));
            }
        }
        return out;
    }

    wr::SenderNodeStats senderNode(std::size_t index)
    {
        const auto stats = wr::senderStats();
        EXPECT_GT(stats.nodes.size(), index);
        return stats.nodes.size() > index ? stats.nodes[index] : wr::SenderNodeStats {};
    }

    std::string describe(const std::optional<ic::OpResult>& result)
    {
        if (!result)
        {
            return "no result";
        }
        const char* status = result->status == ic::Status::Ok       ? "Ok"
                             : result->status == ic::Status::Failed ? "Failed"
                                                                    : "Dropped";
        return std::string(status) + "/" + ic::toString(result->cause) + " http " + std::to_string(result->httpStatus) +
               " type '" + result->itemErrorType + "' reason '" + result->reason + "'";
    }
} // namespace

// One batch is one `POST {host}/_bulk` (application/json) whose body is the ops' encoded lines, concatenated in
// submit order. Mutant: the lines appended in reverse.
TEST_F(BulkTest, BulkBodyIsTheEncodedLines)
{
    bulk_component::FakeIndexerOptions options;
    options.recordBodies = true;
    const auto a = startNode(BulkScript::items(), "green", options);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 5, 5)});
    auto writer = c->writer("b");

    std::vector<ic::Op> ops {indexOp(id(0)),
                             deleteOp(id(1)),
                             indexOp(id(2), 40),
                             indexOp(id(3), 16, "wazuh-states-other"),
                             deleteOp(id(4), "wazuh-states-other")};
    std::string expected;
    for (const auto& op : ops)
    {
        auto encoded = wr::encode(ic::Op(op), ic::ConflictPolicy {});
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        expected += wireOf(encoded.value);
    }
    auto results = Results::create();
    for (std::uint64_t k = 0; k < ops.size(); ++k)
    {
        ASSERT_TRUE(writer->submit(ops[k], results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(ops.size()));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), ops.size());

    const auto requests = bulkRequests(a);
    ASSERT_EQ(requests.size(), 1u) << "five ops, maxDocs 5: one batch";
    EXPECT_EQ(requests[0].path, "/_bulk");
    const auto type = requests[0].headers.find("Content-Type");
    ASSERT_NE(type, requests[0].headers.end());
    EXPECT_EQ(type->second, "application/json");
    EXPECT_EQ(requests[0].body, expected) << "the body is the encoded lines in submit order";
    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 1u);
    ASSERT_EQ(received[0].size(), ops.size());
    for (std::size_t i = 0; i < ops.size(); ++i)
    {
        EXPECT_EQ(received[0][i].id, id(i)) << "position " << i;
    }
    EXPECT_EQ(wr::senderStats().sent, 1u);
}

// `errors:false` never skips the items: each op gets its own outcome (created, updated, noop, deleted)
// and status. Mutant: a body with `errors:false` resolves every op Ok without reading the items.
TEST_F(BulkTest, ErrorsFalseStillPerItem)
{
    auto script = BulkScript::items({{0, BulkItem::ok(201, "created")},
                                     {1, BulkItem::ok(200, "updated")},
                                     {2, BulkItem::ok(200, "noop")}}); // 3: the delete's default 200 `deleted`.
    script.errors = false;
    const auto a = startNode(script);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 4, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(writer->submit(deleteOp(id(3)), results->callback(3)).accepted);
    ASSERT_TRUE(results->waitTotal(4));

    const std::vector<std::pair<ic::ItemOutcome, int>> expected {{ic::ItemOutcome::Created, 201},
                                                                 {ic::ItemOutcome::Updated, 200},
                                                                 {ic::ItemOutcome::Noop, 200},
                                                                 {ic::ItemOutcome::Deleted, 200}};
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = results->result(k);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
        EXPECT_EQ(result->cause, ic::Cause::None);
        EXPECT_EQ(result->outcome, expected[k].first) << describe(result);
        EXPECT_EQ(result->httpStatus, expected[k].second) << describe(result);
    }
    EXPECT_EQ(a.bulk->answered(), 1u);
}

// A delete of a missing document (404 without `error`) is an idempotent success.
TEST_F(BulkTest, DeleteNotFoundIsOk)
{
    const auto a = startNode(BulkScript::all(BulkItem::notFound()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(deleteOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::None);
    EXPECT_EQ(result->outcome, ic::ItemOutcome::NotFound);
    EXPECT_EQ(result->httpStatus, 404);
    EXPECT_EQ(a.bulk->answered(), 1u) << "never retried";
}

// A 404 carrying `index_not_found_exception` is a permanent item failure, never retried.
TEST_F(BulkTest, IndexNotFoundIsPermanent)
{
    const auto a = startNode(
        BulkScript::all(BulkItem::failed(404, "index_not_found_exception", "no such index [wazuh-states-test]")));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Failed) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::ItemPermanent);
    EXPECT_EQ(result->httpStatus, 404);
    EXPECT_EQ(result->itemErrorType, "index_not_found_exception");
    EXPECT_THAT(result->reason, HasSubstr("no such index"));
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 200ms)) << "never retried";
}

// One batch with ok / 429 / mapping error / 409 ⇒ Ok, retried then Ok, Failed(ItemPermanent), Ok keeping
// the 409; only the 429 item goes back, so the fake receives N + 1 ops. Mutant: a retryable item sends the whole
// batch back.
TEST_F(BulkTest, MixedItems)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items({{1, BulkItem::rejected()},
                                    {2, BulkItem::failed(400, "mapper_parsing_exception", "failed to parse field")},
                                    {3, BulkItem::conflict()}}));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 4, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(4));

    auto r0 = results->result(0);
    EXPECT_EQ(r0->status, ic::Status::Ok) << describe(r0);
    EXPECT_EQ(r0->outcome, ic::ItemOutcome::Created);
    auto r1 = results->result(1);
    EXPECT_EQ(r1->status, ic::Status::Ok) << describe(r1);
    EXPECT_EQ(r1->outcome, ic::ItemOutcome::Created) << "the retry succeeded";
    auto r2 = results->result(2);
    EXPECT_EQ(r2->status, ic::Status::Failed) << describe(r2);
    EXPECT_EQ(r2->cause, ic::Cause::ItemPermanent);
    EXPECT_EQ(r2->httpStatus, 400);
    EXPECT_EQ(r2->itemErrorType, "mapper_parsing_exception");
    auto r3 = results->result(3);
    EXPECT_EQ(r3->status, ic::Status::Ok) << describe(r3);
    EXPECT_EQ(r3->cause, ic::Cause::None);
    EXPECT_EQ(r3->httpStatus, 409);
    EXPECT_EQ(r3->itemErrorType, "version_conflict_engine_exception");

    for (std::uint64_t k = 0; k < 4; ++k)
    {
        EXPECT_EQ(results->count(k), 1) << k;
    }
    EXPECT_EQ(a.bulk->opCount(), 5u) << "N + 1 ops: only the 429 item was sent again";
    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 2u);
    ASSERT_EQ(received[1].size(), 1u);
    EXPECT_EQ(received[1][0].id, id(1));
    expectInvariants(stats("b"));
}

// 300 ops, several scripted requests with retryable items: every op gets exactly one result, all Ok, and the
// fake receives each op once plus once per retry. Mutant: the retryable items are never requeued (the table's
// «no CAS in resolve» survives here: nothing races the resolution in this scenario; see mutantes.log, 4a).
TEST_F(BulkTest, EveryOpOneResult)
{
    constexpr std::uint64_t OPS = 300;
    constexpr std::size_t SCRIPTED = 10;
    const std::set<std::size_t> retried {0, 2, 5};
    const auto a = startNode();
    for (std::size_t i = 0; i < SCRIPTED; ++i)
    {
        a.bulk->push(BulkScript::items({{0, BulkItem::rejected()},
                                        {2, BulkItem::failed(503, "unavailable_shards_exception")},
                                        {5, BulkItem::rejected()}}));
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 10, std::nullopt)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(OPS, 10s)) << results->total() << " of " << OPS;
    EXPECT_FALSE(eventually([&] { return results->total() > OPS; }, 200ms)) << "a second result";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), OPS);
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        EXPECT_EQ(results->count(k), 1) << k;
    }

    const auto received = a.bulk->received();
    ASSERT_GE(received.size(), SCRIPTED);
    std::size_t retries = 0;
    for (std::size_t i = 0; i < SCRIPTED; ++i)
    {
        for (const auto position : retried)
        {
            retries += position < received[i].size() ? 1 : 0;
        }
    }
    EXPECT_GT(retries, 0u);
    EXPECT_EQ(a.bulk->opCount(), OPS + retries) << "each op once, plus once per retryable item";
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        EXPECT_GE(receivedWithId(a, id(k)), 1u) << k;
    }
    auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, OPS) << describe(s);
    EXPECT_EQ(s.resolvedFailed + s.resolvedDropped, 0u) << describe(s);
    expectInvariants(s);
}

// A bucket with maxAttempts = 3 against a node that always answers 503 ⇒ Failed(RetryExhausted) after exactly
// three requests, its last error (Server5xx, 503) kept. Mutant: the Retry verdict requeues without counting an
// attempt.
TEST_F(BulkTest, LimitedRetryExhausts)
{
    const auto a = startNode(BulkScript::serverError(503));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 3)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1)) << "requests so far: " << a.bulk->answered();
    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Failed) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::RetryExhausted);
    EXPECT_EQ(result->httpStatus, 503);
    EXPECT_THAT(result->reason, HasSubstr(ic::toString(ic::Cause::Server5xx)));
    EXPECT_EQ(a.bulk->answered(), 3u) << "maxAttempts = 3: three requests";
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 3; }, 200ms)) << "nothing after the exhaustion";
    EXPECT_EQ(wr::senderStats().exhausted, 1u);
}

// An unlimited bucket survives a node that answers 503 eight times in a row: every op ends Ok, none lost.
// Mutant: an unset maxAttempts counted as the default five.
TEST_F(BulkTest, UnlimitedSurvives5xx)
{
    constexpr std::size_t FAILURES = 8;
    const auto a = startNode();
    for (std::size_t i = 0; i < FAILURES; ++i)
    {
        a.bulk->push(BulkScript::serverError(503));
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 5, std::nullopt)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 5; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(5)) << "requests so far: " << a.bulk->answered();
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 5u);
    EXPECT_EQ(a.bulk->answered(), FAILURES + 1);
    EXPECT_EQ(wr::senderStats().retries, FAILURES);
    auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, 5u) << describe(s);
    expectInvariants(s);
}

// A document with an invalid mapping is Failed(ItemPermanent) once and never sent again; the rest of its batch
// and the next batch go through. Mutant: a permanent item is requeued for retry.
TEST_F(BulkTest, PoisonDoesNotBlock)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items(
        {{1, BulkItem::failed(400, "mapper_parsing_exception", "failed to parse field [p] of type [long]")}}));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 4, std::nullopt)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(4));
    for (std::uint64_t k = 4; k < 8; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(8));

    const auto poison = results->result(1);
    EXPECT_EQ(poison->status, ic::Status::Failed) << describe(poison);
    EXPECT_EQ(poison->cause, ic::Cause::ItemPermanent);
    EXPECT_EQ(poison->itemErrorType, "mapper_parsing_exception");
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 7u);
    EXPECT_EQ(receivedWithId(a, id(1)), 1u) << "the poison is never sent again";
    EXPECT_EQ(a.bulk->opCount(), 8u);
}

// `tooLargeAbove(1)` ⇒ every multi-op request gets 413 and the batch is halved until single ops go through;
// one op whose single request still gets 413 ends Failed(PayloadTooLarge), the rest enter. Mutant: the Split verdict
// requeues without halving.
TEST_F(BulkTest, Split413)
{
    const std::string big = std::string("\"_id\":\"") + id(4) + "\"";
    const auto a = startNode(BulkScript::tooLargeAbove(1),
                             "green",
                             {},
                             [big](const httplib::Request& request, indexer_client::testing::Rule& reply)
                             {
                                 const auto lines = std::count(request.body.begin(), request.body.end(), '\n');
                                 if (lines == 2 && request.body.find(big) != std::string::npos)
                                 {
                                     reply.status = 413; // Over http.max_content_length even alone.
                                     reply.body.clear();
                                 }
                             });
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 5, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 5; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(5)) << "requests so far: " << a.bulk->answered();

    for (std::uint64_t k = 0; k < 4; ++k)
    {
        const auto result = results->result(k);
        EXPECT_EQ(result->status, ic::Status::Ok) << k << ": " << describe(result);
    }
    const auto tooLarge = results->result(4);
    EXPECT_EQ(tooLarge->status, ic::Status::Failed) << describe(tooLarge);
    EXPECT_EQ(tooLarge->cause, ic::Cause::PayloadTooLarge);
    EXPECT_EQ(tooLarge->httpStatus, 413);

    const auto received = a.bulk->received();
    ASSERT_FALSE(received.empty());
    EXPECT_EQ(received.front().size(), 5u) << "the first request is the whole batch";
    std::size_t singles = 0;
    for (const auto& request : received)
    {
        singles += request.size() == 1 ? 1 : 0;
    }
    EXPECT_EQ(singles, 5u) << "halved down to one op each, each sent alone once";
    EXPECT_GE(wr::senderStats().splits, 3u) << "5 -> 2 + 2 + 1 -> singles";
}

// A `_bulk` response over max_response_bytes ⇒ the batch is halved; a single op whose response is still over
// the cap ends Failed(ItemPermanent); the others go through.
TEST_F(BulkTest, ResponseTooLargeSplits)
{
    const std::string index = "wazuh-states-" + std::string(200, 'i');
    const std::string longId(512, 'L');
    // The cap: two short items fit, three do not, a long item alone does not, the health body does.
    auto render = [&](const std::vector<std::string>& ids)
    {
        std::vector<indexer_client::testing::BulkOp> ops;
        for (const auto& docId : ids)
        {
            ops.push_back({"index", index, docId, "{}"});
        }
        return indexer_client::testing::BulkResponder::renderItems(ops, BulkScript::items(), 100000).size();
    };
    const auto cap = render({id(0), id(1)}) + 40;
    ASSERT_GT(render({id(0), id(1), id(2)}), cap);
    ASSERT_GT(render({longId}), cap);
    ASSERT_LT(indexer_client::testing::healthBody("green").size() + 50, cap) << "the probe must still fit";

    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"max_response_bytes", std::to_string(cap)}}));
    ASSERT_EQ(nodeState(0), NodeState::Available);
    auto c = client("c", {fastBucket("b", 5, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 4; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k), 16, index), results->callback(k)).accepted);
    }
    ASSERT_TRUE(writer->submit(indexOp(longId, 16, index), results->callback(4)).accepted);
    ASSERT_TRUE(results->waitTotal(5)) << "requests so far: " << a.bulk->answered();

    for (std::uint64_t k = 0; k < 4; ++k)
    {
        const auto result = results->result(k);
        EXPECT_EQ(result->status, ic::Status::Ok) << k << ": " << describe(result);
    }
    const auto failed = results->result(4);
    EXPECT_EQ(failed->status, ic::Status::Failed) << describe(failed);
    EXPECT_EQ(failed->cause, ic::Cause::ItemPermanent);
    EXPECT_THAT(failed->reason, HasSubstr("maxResponseBytes"));
    const auto received = a.bulk->received();
    ASSERT_FALSE(received.empty());
    EXPECT_EQ(received.front().size(), 5u);
    EXPECT_GE(wr::senderStats().splits, 1u);
    EXPECT_EQ(nodeState(0), NodeState::Available) << "a response over the cap is not the node's fault";
}

// `Retry-After: 2` from node A ⇒ nothing goes to A for 2 s even once the probe has it Available again, while B
// keeps taking the traffic; afterwards A takes traffic again. A 429 costs no attempt: maxAttempts = 1 still ends Ok.
// Mutant: the node filter ignores notBefore.
TEST_F(BulkTest, Request429HonorsRetryAfterPerNode)
{
    const auto a = startNode();
    const auto b = startNode();
    a.bulk->push(BulkScript::throttled("2"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}));
    auto c = client("c", {fastBucket("b", 1, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();

    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    const auto throttledAt = std::chrono::steady_clock::now();
    const auto first = results->result(0);
    EXPECT_EQ(first->status, ic::Status::Ok) << describe(first) << " (a 429 costs no attempt)";
    ASSERT_EQ(a.bulk->answered(), 1u) << "round robin starts at A";
    EXPECT_EQ(b.bulk->answered(), 1u) << "the throttled batch went on to B";
    ASSERT_TRUE(senderNode(0).notBefore.has_value());
    EXPECT_FALSE(senderNode(1).notBefore.has_value()) << "per node";

    ASSERT_TRUE(probeNowAndWait());
    ASSERT_EQ(nodeState(0), NodeState::Available) << "the probe cleared the passive Throttled";
    for (std::uint64_t k = 1; k <= 8; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(9));
    const auto during = std::chrono::steady_clock::now() - throttledAt;
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 9u);
    EXPECT_EQ(a.bulk->answered(), 1u) << "nothing to A while its notBefore is in force";
    EXPECT_EQ(b.bulk->answered(), 9u);
    ASSERT_LT(during, 1500ms) << "the window check must end well before Retry-After";

    ASSERT_FALSE(eventually([] { return senderNode(0).notBefore.has_value() == false; },
                            std::chrono::duration_cast<std::chrono::milliseconds>(1500ms - during)))
        << "A's notBefore ended early";
    ASSERT_TRUE(eventually([] { return !senderNode(0).notBefore.has_value(); }, 3s));
    EXPECT_GE(std::chrono::steady_clock::now() - throttledAt, 1500ms);
    for (std::uint64_t k = 9; k <= 16; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(17));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 17u);
    EXPECT_GT(a.bulk->answered(), 1u) << "A takes traffic again once notBefore has passed";
}

// A 429 without Retry-After makes the node wait `pace` (paceInitial), doubled by a 429 whose request left
// after that wait was set. A 2xx keeps the pace: only paceRelaxAfter (here 2) clean sends halve it, and a pace below
// paceInitial becomes 0; meanwhile every send is spaced by the pace (nextSendAt). PACE is 500 ms so that a stalled poll
// on a slow CI cannot see both 429s in its first sample.
TEST_F(BulkTest, Request429Paces)
{
    constexpr auto PACE = 500ms;
    const auto a = startNode();
    a.bulk->push(BulkScript::throttled());
    a.bulk->push(BulkScript::throttled());
    ASSERT_NO_FATAL_FAILURE(
        startOn({a.url()}, std::chrono::hours(1), {{"pace_initial_ms", "500"}, {"pace_relax_after", "2"}}));
    auto c = client("c", {fastBucket("b", 1, 1)});
    auto results = Results::create();
    const auto submitted = std::chrono::steady_clock::now();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);

    wr::SenderStats snapshot;
    ASSERT_TRUE(eventually(
        [&]
        {
            snapshot = wr::senderStats();
            return snapshot.throttled >= 1;
        },
        5s));
    ASSERT_EQ(snapshot.throttled, 1u) << "the second 429 cannot come before the first pace";
    EXPECT_EQ(snapshot.nodes.at(0).pace, ic::Duration {PACE}) << "paceInitial";
    EXPECT_TRUE(snapshot.nodes.at(0).notBefore.has_value());
    ASSERT_TRUE(eventually(
        [&]
        {
            snapshot = wr::senderStats();
            return snapshot.throttled >= 2;
        },
        5s));
    EXPECT_EQ(snapshot.nodes.at(0).pace, ic::Duration {2 * PACE}) << "doubled by a 429 sent after the first wait";
    ASSERT_TRUE(results->waitTotal(1));
    const auto elapsed = std::chrono::steady_clock::now() - submitted;
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    EXPECT_GE(elapsed, 3 * PACE - 20ms) << "waited pace, then twice pace";
    const auto afterOk = senderNode(0);
    EXPECT_EQ(afterOk.pace, ic::Duration {2 * PACE}) << "one clean send keeps the pace";
    EXPECT_EQ(afterOk.paceRelaxed, 0u);
    // No assertion on nextSendAt here: it is in force only for 2 x PACE after the send, and the response may come
    // later than that; the spacing below measures it by the clock.
    EXPECT_EQ(a.bulk->answered(), 3u);

    // The second clean send, itself spaced by 2 × PACE from the third request, halves the pace to PACE.
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2));
    EXPECT_EQ(results->result(1)->status, ic::Status::Ok);
    EXPECT_GE(std::chrono::steady_clock::now() - submitted, 5 * PACE - 20ms) << "nextSendAt spaced the fourth send";
    const auto relaxed = senderNode(0);
    EXPECT_EQ(relaxed.pace, ic::Duration {PACE}) << "paceRelaxAfter clean sends halve the pace";
    EXPECT_EQ(relaxed.paceRelaxed, 1u);

    // Two more clean sends: PACE / 2 is below paceInitial, so the pace ends at 0.
    for (std::uint64_t k = 2; k <= 3; ++k)
    {
        ASSERT_TRUE(c->writer("b")->submit(indexOp(id(k)), results->callback(k)).accepted);
        ASSERT_TRUE(results->waitTotal(k + 1));
        EXPECT_EQ(results->result(k)->status, ic::Status::Ok);
    }
    // A relaxation never shortens a nextSendAt in force: the fifth send waits the 2 × PACE set by the fourth, the
    // sixth waits PACE.
    EXPECT_GE(std::chrono::steady_clock::now() - submitted, 8 * PACE - 20ms) << "the sends were not spaced";
    const auto cleared = senderNode(0);
    EXPECT_EQ(cleared.pace, ic::Duration {0}) << "a pace below paceInitial becomes 0";
    EXPECT_EQ(cleared.paceRelaxed, 2u);
    EXPECT_EQ(a.bulk->answered(), 6u);
}

// A 2xx that completes while a 429's notBefore is in force never shortens that notBefore, and, its request
// having left before the notBefore was set, is no clean send: the pace is kept.
TEST_F(BulkTest, NotBeforeNeverShortenedBy2xx)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::items().held());
    a.bulk->push(BulkScript::throttled("2"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 1)});
    auto writer = c->writer("b");
    auto results = Results::create();

    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([&] { return a.bulk->answered() == 1 && a.fake->heldNow() == 1; }, 5s));
    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(eventually([] { return wr::senderStats().throttled == 1; }, 5s));
    // The same 429 sets the sender's notBefore and, through NodeSet::report and the hook, mirrors the NodeSet's
    // a few microseconds later: read it once the mirror has landed, so the comparison below can be exact.
    ASSERT_TRUE(eventually(
        []
        {
            const auto mirrored = senderNode(0).notBefore;
            return mirrored && *mirrored >= indexer_client::detail::runtimeNodeSet()->notBefore(0);
        },
        5s))
        << "the sender never mirrored the NodeSet's notBefore";
    const auto throttled = senderNode(0);
    ASSERT_TRUE(throttled.notBefore.has_value());
    EXPECT_GT(throttled.pace, ic::Duration {0});

    a.fake->releaseHeld();
    ASSERT_TRUE(eventually([&] { return results->count(0) == 1; }, 5s));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok);
    const auto afterOk = senderNode(0);
    EXPECT_EQ(afterOk.pace, throttled.pace) << "a 2xx sent before the notBefore was set relaxed the pace";
    EXPECT_EQ(afterOk.paceRelaxed, 0u);
    ASSERT_TRUE(afterOk.notBefore.has_value()) << "the 2xx cleared the notBefore";
    EXPECT_EQ(*afterOk.notBefore, *throttled.notBefore) << "the 2xx moved the notBefore";
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 2; },
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                *throttled.notBefore - std::chrono::steady_clock::now() - 200ms)))
        << "the throttled op left before its notBefore";
    ASSERT_TRUE(results->waitTotal(2));
    EXPECT_GE(std::chrono::steady_clock::now(), *throttled.notBefore);
    EXPECT_EQ(results->result(1)->status, ic::Status::Ok);
}

// A request-level 400 fails the whole batch with Client4xx, never retried.
TEST_F(BulkTest, Client4xxFailsBatch)
{
    const auto a = startNode();
    a.bulk->push(
        BulkScript::request(400,
                            R"({"error":{"root_cause":[{"type":"illegal_argument_exception","reason":"bad bulk"}],)"
                            R"("type":"illegal_argument_exception","reason":"bad bulk"},"status":400})"));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 3, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(k)), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(3));
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        const auto result = results->result(k);
        EXPECT_EQ(result->status, ic::Status::Failed) << describe(result);
        EXPECT_EQ(result->cause, ic::Cause::Client4xx);
        EXPECT_EQ(result->httpStatus, 400);
    }
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1; }, 200ms)) << "never retried";
    EXPECT_EQ(nodeState(0), NodeState::Available);
}

// A 401 on `_bulk` is retried with an attempt, not dropped; the node is not reported.
TEST_F(BulkTest, CredentialsErrorRetries)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::unauthorized());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 2, 3), fastBucket("one", 1, 1)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    EXPECT_EQ(a.bulk->answered(), 2u);
    EXPECT_EQ(wr::senderStats().retries, 1u);
    EXPECT_EQ(nodeState(0), NodeState::Available) << "a 401 on _bulk is not a passive Down";

    // With one attempt allowed, the 401 is the op's last error.
    a.bulk->push(BulkScript::unauthorized());
    ASSERT_TRUE(c->writer("one")->submit(indexOp(id(2)), results->callback(2)).accepted);
    ASSERT_TRUE(results->waitTotal(3));
    const auto exhausted = results->result(2);
    EXPECT_EQ(exhausted->status, ic::Status::Failed) << describe(exhausted);
    EXPECT_EQ(exhausted->cause, ic::Cause::RetryExhausted);
    EXPECT_EQ(exhausted->httpStatus, 401);
    EXPECT_THAT(exhausted->reason, HasSubstr(ic::toString(ic::Cause::Client4xx)));
}

// A 200 whose body is unreadable, then one with an item missing ⇒ both retried; once exhausted, the op's last
// error carries the reason.
TEST_F(BulkTest, UnreadableBodyRetries)
{
    BulkScript missingItem;
    missingItem.itemDelta = -1;
    const auto a = startNode();
    a.bulk->push(BulkScript::unreadable());
    a.bulk->push(missingItem);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("retry", 1, 5), fastBucket("two", 1, 2)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("retry")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << describe(results->result(0));
    EXPECT_EQ(a.bulk->answered(), 3u) << "unreadable, an item short, then Ok";
    EXPECT_EQ(wr::senderStats().retries, 2u);

    a.bulk->push(BulkScript::unreadable());
    a.bulk->push(missingItem);
    ASSERT_TRUE(c->writer("two")->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2));
    const auto exhausted = results->result(1);
    EXPECT_EQ(exhausted->status, ic::Status::Failed) << describe(exhausted);
    EXPECT_EQ(exhausted->cause, ic::Cause::RetryExhausted);
    EXPECT_EQ(exhausted->httpStatus, 200);
    EXPECT_THAT(exhausted->reason, HasSubstr("items: got 0, expected 1"));
    EXPECT_EQ(a.bulk->answered(), 5u);
}

// A request-level 429 is reported to the NodeSet: the node shows Throttled in health() until the next probe
// round; the batch still ends Ok.
TEST_F(BulkTest, PassiveReport429Throttled)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::throttled());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 1)});
    ASSERT_EQ(c->health().nodes.at(0).state, NodeState::Available);
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(indexOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(eventually([&] { return c->health().nodes.at(0).state == NodeState::Throttled; }, 5s));
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->result(0)->status, ic::Status::Ok) << "a Throttled node still takes the retry";
    EXPECT_EQ(c->health().nodes.at(0).state, NodeState::Throttled) << "a passive success never promotes";
    ASSERT_TRUE(probeNowAndWait());
    EXPECT_EQ(c->health().nodes.at(0).state, NodeState::Available);
}
