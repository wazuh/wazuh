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

// The per-operation conflict policy and ReplacePreserving end to end: the
// effective policy (the op's onConflict, else the bucket's) on the wire and in the verdict of a 409 item, and the
// frozen ReplacePreserving vectors as the fake receives them. Every case runs the production sink over the real
// transport against a fake node (bulkFixture.hpp); every wait is bounded; every case ends with the charge and the
// retained ops at 0 (TearDown).

#include <cstdint>
#include <cstdio>
#include <optional>
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

// The frozen vectors of writeEncoding_test.cpp (defined there, one copy for both suites).
namespace preserving_vectors
{
    std::string indexVector(bool retry);
    std::string versionedVector(bool retry);
    ic::Op op(bool versioned);
} // namespace preserving_vectors

namespace
{
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    ic::ConflictPolicy retryPolicy(std::uint32_t n)
    {
        ic::ConflictPolicy policy;
        policy.kind = ic::ConflictPolicy::Kind::Retry;
        policy.retryOnConflict = n;
        return policy;
    }

    ic::Op versionedOp(std::string docId, std::string version = "3")
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexVersionedScript;
        op.index = "wazuh-states-test";
        op.id = std::move(docId);
        op.body = R"({"agent":{"id":"001"}})";
        op.version = std::move(version);
        return op;
    }

    /// A bucket of `maxDocs`-op batches (no age-based batch) with a fast retry: 5 ms, capped at 20 ms, no jitter,
    /// `maxAttempts` (nullopt: unlimited), no maxDuration, and `onConflict`.
    ic::BucketSpec fastBucket(std::string name,
                              std::size_t maxDocs,
                              std::optional<std::uint32_t> maxAttempts,
                              ic::ConflictPolicy onConflict = {})
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = maxAttempts;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        spec.onConflict = onConflict;
        return spec;
    }

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

    /// The bodies of the `_bulk` requests the fake recorded (the probe's GETs left out).
    std::vector<std::string> bulkBodies(const bulk_component::Node& node)
    {
        std::vector<std::string> out;
        for (auto& request : node.fake->requests())
        {
            if (request.method == "POST")
            {
                out.push_back(std::move(request.body));
            }
        }
        return out;
    }

    bulk_component::FakeIndexerOptions recording()
    {
        bulk_component::FakeIndexerOptions options;
        options.recordBodies = true;
        return options;
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

// A bucket with Success and an op with its own Retry{3}: the line carries retry_on_conflict 3, the 409 goes
// back to the lane and the second send's 200 resolves it Ok (two sends, one result). Mutant: the 409 treated with the
// bucket's policy (OpState::conflictRetry ignored).
TEST_F(BulkTest, ConflictRetryThenOk)
{
    const auto a = startNode(BulkScript::items(), "green", recording());
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5)});
    auto results = Results::create();
    auto op = versionedOp(id(0));
    op.onConflict = retryPolicy(3);
    ASSERT_TRUE(c->writer("b")->submit(op, results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));

    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::None);
    EXPECT_EQ(result->httpStatus, 200) << describe(result);
    EXPECT_EQ(result->outcome, ic::ItemOutcome::Updated) << describe(result);
    EXPECT_EQ(result->itemErrorType, "");
    EXPECT_EQ(a.bulk->answered(), 2u) << "the 409, then the 200";
    EXPECT_EQ(receivedWithId(a, id(0)), 2u);
    const auto bodies = bulkBodies(a);
    ASSERT_EQ(bodies.size(), 2u);
    const std::string line =
        R"({"update":{"_index":"wazuh-states-test","_id":")" + id(0) + R"(","retry_on_conflict":3}})";
    for (const auto& body : bodies)
    {
        EXPECT_EQ(body.substr(0, line.size()), line) << body;
    }
    EXPECT_EQ(results->count(0), 1);
    expectInvariants(stats("b"));
}

// Success keeps the 409: Ok with httpStatus 409 and the item's type after one send, for a Success bucket without
// onConflict and for an op whose own Success overrides a Retry bucket. Mutant: Success requeued like Retry.
TEST_F(BulkTest, ConflictSuccessKeeps409)
{
    const auto a = startNode(BulkScript::items(), "green", recording());
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5), fastBucket("r", 1, 5, retryPolicy(4))});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(versionedOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    auto overriding = versionedOp(id(1));
    overriding.onConflict = ic::ConflictPolicy {};
    ASSERT_TRUE(c->writer("r")->submit(overriding, results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2));

    for (std::uint64_t k = 0; k < 2; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = results->result(k);
        EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
        EXPECT_EQ(result->cause, ic::Cause::None);
        EXPECT_EQ(result->httpStatus, 409) << describe(result);
        EXPECT_EQ(result->itemErrorType, "version_conflict_engine_exception");
        EXPECT_EQ(receivedWithId(a, id(k)), 1u) << "one send";
        EXPECT_EQ(results->count(k), 1);
    }
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 2; }, 200ms)) << "nothing sent again";
    const auto bodies = bulkBodies(a);
    ASSERT_EQ(bodies.size(), 2u);
    EXPECT_EQ(bodies[1].find("retry_on_conflict"), std::string::npos)
        << "the op's Success: the plain line, without retry_on_conflict";
    expectInvariants(stats("b"));
    expectInvariants(stats("r"));
}

// Retry with maxAttempts = 2 against a node that always answers 409 ⇒ Failed(RetryExhausted) after two sends,
// with the 409 and its type as the last error.
TEST_F(BulkTest, ConflictRetryExhausts)
{
    const auto a = startNode(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 2)});
    auto results = Results::create();
    auto op = versionedOp(id(0));
    op.onConflict = retryPolicy(2);
    ASSERT_TRUE(c->writer("b")->submit(op, results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1)) << "requests so far: " << a.bulk->answered();

    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Failed) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::RetryExhausted);
    EXPECT_EQ(result->httpStatus, 409);
    EXPECT_EQ(result->itemErrorType, "version_conflict_engine_exception");
    EXPECT_THAT(result->reason, HasSubstr(ic::toString(ic::Cause::VersionConflict))) << describe(result);
    EXPECT_EQ(a.bulk->answered(), 2u) << "maxAttempts = 2: two sends";
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 2; }, 200ms)) << "nothing after the exhaustion";
    EXPECT_EQ(results->count(0), 1);
    EXPECT_EQ(wr::senderStats().exhausted, 1u);
    expectInvariants(stats("b"));
}

// A bucket with Retry{4} and an IndexVersionedScript without onConflict: the line carries retry_on_conflict 4;
// 409 and then 200 ⇒ Ok after two sends. Mutant: the effective policy ignores the bucket's.
TEST_F(BulkTest, BucketRetryOnWire)
{
    const auto a = startNode(BulkScript::items(), "green", recording());
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5, retryPolicy(4))});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(versionedOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1));

    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
    EXPECT_EQ(result->httpStatus, 200) << describe(result);
    EXPECT_EQ(result->outcome, ic::ItemOutcome::Updated);
    EXPECT_EQ(a.bulk->answered(), 2u) << "the 409, then the 200";
    const auto bodies = bulkBodies(a);
    ASSERT_EQ(bodies.size(), 2u);
    const std::string line =
        R"({"update":{"_index":"wazuh-states-test","_id":")" + id(0) + R"(","retry_on_conflict":4}})";
    for (const auto& body : bodies)
    {
        EXPECT_EQ(body.substr(0, line.size()), line) << body;
    }
    expectInvariants(stats("b"));
}

// ConflictPolicy::Retry in a BucketSpec registers (1 and MAX_RETRY_ON_CONFLICT) and its writer accepts ops; 101
// is refused, naming the field. An ordered bucket with Retry registers too and writes.
TEST_F(BulkTest, BucketRetryPolicyRegisters)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client(
        "c",
        {fastBucket("one", 1, 5, retryPolicy(1)), fastBucket("hundred", 1, 5, retryPolicy(wr::MAX_RETRY_ON_CONFLICT))});
    ASSERT_NE(c, nullptr);
    auto results = Results::create();
    ASSERT_TRUE(c->writer("one")->submit(versionedOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(c->writer("hundred")->submit(versionedOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);

    auto above = m_ref.client("above", {fastBucket("b", 1, 5, retryPolicy(wr::MAX_RETRY_ON_CONFLICT + 1))});
    EXPECT_EQ(above.cause, ic::Cause::InvalidArgument);
    EXPECT_THAT(above.reason, HasSubstr("onConflict.retryOnConflict must be <= 100")) << above.reason;
    EXPECT_EQ(m_ref.snapshot().clients, 1u) << "the refused client took no consumer name";
    // An ordered bucket with Retry registers too, and its op ends Ok.
    auto orderedSpec = fastBucket("b", 1, 5, retryPolicy(4));
    orderedSpec.ordered = true;
    auto ordered = m_ref.client("ordered", {orderedSpec});
    ASSERT_TRUE(ordered.ok()) << ic::toString(ordered.cause) << ": " << ordered.reason;
    ASSERT_TRUE(ordered.value->writer("b")->submit(versionedOp(id(2)), results->callback(2)).accepted);
    ASSERT_TRUE(results->waitTotal(3));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 3u);
    EXPECT_EQ(m_ref.snapshot().clients, 2u);
    expectInvariants(stats("one"));
    expectInvariants(stats("hundred"));
    expectInvariants(stats("b", "ordered"));
}

// The fake receives the frozen ReplacePreserving vectors (one batch, in submit order) and each op gets its
// item's outcome: updated, noop, created, and a 409 kept by Success; a second round with `errors:false` reads the
// items all the same.
TEST_F(BulkTest, PreservingOutcomes)
{
    const auto a = startNode(BulkScript::items(), "green", recording());
    a.bulk->push(BulkScript::items({{0, BulkItem::ok(200, "updated")},
                                    {1, BulkItem::ok(200, "noop")},
                                    {2, BulkItem::ok(201, "created")},
                                    {3, BulkItem::conflict()}}));
    auto quiet = BulkScript::items({{0, BulkItem::ok(200, "updated")},
                                    {1, BulkItem::ok(200, "noop")},
                                    {2, BulkItem::ok(201, "created")},
                                    {3, BulkItem::ok(200, "noop")}});
    quiet.errors = false;
    a.bulk->push(quiet);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 4, 5)});
    auto writer = c->writer("b");

    const std::vector<bool> versioned {false, true, false, true};
    std::string expectedBody;
    for (const bool v : versioned)
    {
        expectedBody += v ? preserving_vectors::versionedVector(false) : preserving_vectors::indexVector(false);
    }
    struct Expected final
    {
        ic::ItemOutcome outcome;
        int status;
    };
    const std::vector<std::vector<Expected>> rounds {
        {{ic::ItemOutcome::Updated, 200},
         {ic::ItemOutcome::Noop, 200},
         {ic::ItemOutcome::Created, 201},
         {ic::ItemOutcome::None, 409}},
        {{ic::ItemOutcome::Updated, 200},
         {ic::ItemOutcome::Noop, 200},
         {ic::ItemOutcome::Created, 201},
         {ic::ItemOutcome::Noop, 200}},
    };
    for (std::size_t round = 0; round < rounds.size(); ++round)
    {
        SCOPED_TRACE("round " + std::to_string(round));
        auto results = Results::create();
        for (std::uint64_t k = 0; k < versioned.size(); ++k)
        {
            const auto submit = writer->submit(preserving_vectors::op(versioned[k]), results->callback(k));
            ASSERT_TRUE(submit.accepted) << ic::toString(submit.cause) << ": " << submit.reason;
        }
        ASSERT_TRUE(results->waitTotal(versioned.size()));
        for (std::uint64_t k = 0; k < versioned.size(); ++k)
        {
            SCOPED_TRACE(k);
            const auto result = results->result(k);
            ASSERT_TRUE(result.has_value());
            EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
            EXPECT_EQ(result->cause, ic::Cause::None);
            EXPECT_EQ(result->outcome, rounds[round][k].outcome) << describe(result);
            EXPECT_EQ(result->httpStatus, rounds[round][k].status) << describe(result);
            EXPECT_EQ(results->count(k), 1);
        }
        const auto bodies = bulkBodies(a);
        ASSERT_EQ(bodies.size(), round + 1) << "four ops, maxDocs 4: one batch per round";
        EXPECT_EQ(bodies[round], expectedBody) << "the frozen vectors, in submit order";
        const auto received = a.bulk->received();
        ASSERT_EQ(received.size(), round + 1);
        ASSERT_EQ(received[round].size(), versioned.size());
        for (const auto& op : received[round])
        {
            EXPECT_EQ(op.action, "update");
            EXPECT_EQ(op.index, "wazuh-states-a");
            EXPECT_EQ(op.id, std::optional<std::string>("001\"x")) << "the escaped _id, parsed back";
        }
    }
    EXPECT_EQ(a.bulk->opCount(), 8u) << "nothing sent again";
    expectInvariants(stats("b"));
}
