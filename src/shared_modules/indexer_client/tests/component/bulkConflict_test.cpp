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
// retained ops at 0 (TearDown). The 409 of an IndexDataStream with an `_id` counted `deduplicated` on every
// resolution path, its WARN rate-limited per bucket, and the resend of such an op byte for byte.

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "bulkFixture.hpp"
#include "logSink.hpp"
#include "testTimeScale.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;
using indexer_client::testing::scaled;
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

    /// An IndexDataStream op, with `docId` as its `_id` when not empty.
    ic::Op streamOp(std::string docId)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexDataStream;
        op.index = "wazuh-events-test";
        op.id = std::move(docId);
        op.body = R"({"event":{"original":"x"}})";
        return op;
    }

    /// The public counter `deduplicated` of `bucket` (Client::metrics()).
    std::uint64_t publicDeduplicated(const ic::Client& c, const std::string& bucket)
    {
        for (const auto& b : c.metrics().buckets)
        {
            if (b.bucket == bucket)
            {
                return b.deduplicated;
            }
        }
        ADD_FAILURE() << "no bucket " << bucket << " in the client's metrics";
        return 0;
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

// ---- IndexDataStream with an `_id`, its 409 deduplicated.

/// BulkTest plus the log sink, installed before the runtime starts (startOn) and removed once it is down.
class BulkLogTest : public BulkTest
{
protected:
    /// loggerHelper.h's LOGLEVEL_WARNING, as the library passes it to the log function.
    static constexpr int WARN = 2;
    /// The fixed part of the dedup WARN (bucket.cpp); the periodic summary also warns, so lines are told by this text.
    static constexpr const char* DEDUP = "the indexer already had ";

    log_component::Sink m_logs;

    void SetUp() override
    {
        BulkTest::SetUp();
        indexer_client::setLogFunction(m_logs.function());
    }

    void TearDown() override
    {
        BulkTest::TearDown();
        indexer_client::setLogFunction({}); // The runtime is down: valid again.
    }

    /// The dedup WARN lines so far.
    std::vector<log_component::Line> dedupWarns() const
    {
        std::vector<log_component::Line> out;
        for (auto& line : m_logs.atLeast(WARN, DEDUP))
        {
            if (line.level == WARN)
            {
                out.push_back(std::move(line));
            }
        }
        return out;
    }

    /// Waits (bounded) for at least one dedup WARN, then checks that no other one follows within a short window.
    std::vector<log_component::Line> settledDedupWarns(std::size_t expected)
    {
        EXPECT_TRUE(eventually([&] { return dedupWarns().size() >= expected; }, scaled(5s))) << m_logs.dump();
        EXPECT_FALSE(eventually([&] { return dedupWarns().size() > expected; }, scaled(200ms))) << m_logs.dump();
        return dedupWarns();
    }
};

namespace
{
    enum class DedupPath
    {
        Submit,
        Post,
        Group
    };
} // namespace

class BulkDedupPathTest
    : public BulkLogTest
    , public ::testing::WithParamInterface<DedupPath>
{
};

// A Success bucket; four IndexDataStream ops with an `_id` in one bulk, three answered 409
// version_conflict and one 400 mapper_parsing_exception ⇒ three Ok keeping the 409 (through submit + callback and the
// group's ticket; through post, by the counters), one Failed(ItemPermanent); `deduplicated` = 3 on every path (bucket
// stats and Client::metrics()); one dedup WARN naming the bucket and the number. Mutant (b2): counted only in
// settleBulk (the submit and group paths see 0).
TEST_P(BulkDedupPathTest, DataStreamIdConflictCountsDeduplicated)
{
    constexpr std::uint64_t OPS = 4;
    constexpr std::size_t PERMANENT = 3; // Position of the 400 in the bulk.
    constexpr std::size_t CREATED = 2;   // Position of a plain 201 (a 2xx of an op with `_id` must not count, on
                                         // every path).
    auto script = BulkScript::all(BulkItem::conflict());
    script.at[PERMANENT] = BulkItem::failed(400, "mapper_parsing_exception", "failed to parse field [event]");
    script.at[CREATED] = BulkItem::ok();
    const auto a = startNode();
    a.bulk->push(script);
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", OPS, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    std::vector<std::optional<ic::OpResult>> byKey(OPS);

    switch (GetParam())
    {
        case DedupPath::Submit:
            for (std::uint64_t k = 0; k < OPS; ++k)
            {
                ASSERT_TRUE(writer->submit(streamOp(id(k)), results->callback(k)).accepted);
            }
            ASSERT_TRUE(results->waitTotal(OPS, scaled(5s))) << results->total();
            for (std::uint64_t k = 0; k < OPS; ++k)
            {
                byKey[k] = results->result(k);
            }
            break;
        case DedupPath::Post:
            for (std::uint64_t k = 0; k < OPS; ++k)
            {
                ASSERT_TRUE(writer->post(streamOp(id(k))).accepted);
            }
            break;
        case DedupPath::Group:
        {
            auto group = writer->group();
            for (std::uint64_t k = 0; k < OPS; ++k)
            {
                ASSERT_EQ(group.add(streamOp(id(k))), ic::Cause::None) << group.lastAddReason();
            }
            const auto ticket = group.commit();
            const auto outcome = ticket.wait(std::chrono::steady_clock::now() + scaled(5s));
            ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
            ASSERT_EQ(outcome.value.size(), OPS);
            for (std::uint64_t k = 0; k < OPS; ++k)
            {
                byKey[k] = outcome.value[k]; // Add order.
            }
            break;
        }
    }
    ASSERT_TRUE(eventually(
        [&]
        {
            const auto s = stats("b");
            return s.resolvedOk + s.resolvedFailed == OPS;
        },
        scaled(5s)))
        << describe(stats("b"));

    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 1u) << "one bulk of four";
    ASSERT_EQ(received[0].size(), OPS);
    for (const auto& op : received[0])
    {
        EXPECT_EQ(op.action, "create");
        ASSERT_TRUE(op.id.has_value()) << "the _id is on the wire";
    }
    const std::string permanentId = *received[0][PERMANENT].id;
    const std::string createdId = *received[0][CREATED].id;
    if (GetParam() != DedupPath::Post)
    {
        for (std::uint64_t k = 0; k < OPS; ++k)
        {
            SCOPED_TRACE(k);
            const auto& result = byKey[k];
            ASSERT_TRUE(result.has_value());
            if (id(k) == permanentId)
            {
                EXPECT_EQ(result->status, ic::Status::Failed) << describe(result);
                EXPECT_EQ(result->cause, ic::Cause::ItemPermanent) << describe(result);
                EXPECT_EQ(result->httpStatus, 400) << describe(result);
                EXPECT_EQ(result->itemErrorType, "mapper_parsing_exception");
            }
            else if (id(k) == createdId)
            {
                EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
                EXPECT_EQ(result->httpStatus, 201) << describe(result);
            }
            else
            {
                EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
                EXPECT_EQ(result->cause, ic::Cause::None);
                EXPECT_EQ(result->httpStatus, 409) << "the 409 kept" << describe(result);
                EXPECT_EQ(result->itemErrorType, "version_conflict_engine_exception");
            }
        }
    }
    const auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, 3u) << describe(s);
    EXPECT_EQ(s.resolvedFailed, 1u) << describe(s);
    EXPECT_EQ(s.failed[static_cast<std::size_t>(ic::FailCause::ItemPermanent)], 1u);
    EXPECT_EQ(s.deduplicated, 2u) << "every applied 409 of an IndexDataStream with an _id, not its 201";
    EXPECT_EQ(publicDeduplicated(*c, "b"), 2u);
    EXPECT_EQ(a.bulk->answered(), 1u) << "nothing sent again";

    const auto warns = settledDedupWarns(1);
    ASSERT_EQ(warns.size(), 1u) << m_logs.dump();
    EXPECT_NE(warns.front().text.find("Indexer client bucket 'c/b': the indexer already had 2 document(s)"),
              std::string::npos)
        << warns.front().text;
    expectInvariants(s);
}

INSTANTIATE_TEST_SUITE_P(Dedup,
                         BulkDedupPathTest,
                         ::testing::Values(DedupPath::Submit, DedupPath::Post, DedupPath::Group),
                         [](const ::testing::TestParamInfo<DedupPath>& info)
                         {
                             switch (info.param)
                             {
                                 case DedupPath::Submit: return std::string("Submit");
                                 case DedupPath::Post: return std::string("Post");
                                 case DedupPath::Group: return std::string("Group");
                             }
                             return std::string("Unknown");
                         });

// Nothing else is deduplicated. In a Success bucket: a 409 version_conflict on an IndexDataStream without
// `_id` and on an Index (both Ok keeping the 409, as today) and a 409 of another type on an IndexDataStream with an
// `_id` (Failed(ItemPermanent), as today); in a Retry bucket a 409 version_conflict on an IndexDataStream with an `_id`
// (resent, then Ok 200). `deduplicated` = 0 in both buckets and no dedup WARN. Mutant (b): every 409 resolved Ok
// counted, without OpState::dedupOnConflict.
TEST_F(BulkLogTest, ConflictNotDeduplicatedWithoutDataStreamId)
{
    const auto a = startNode();
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    a.bulk->push(BulkScript::all(BulkItem::failed(409, "resource_already_exists_exception", "already exists")));
    a.bulk->push(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("s", 1, 5), fastBucket("r", 1, 5, retryPolicy(3))});
    auto results = Results::create();

    // One op at a time: each takes the next scripted answer.
    ASSERT_TRUE(c->writer("s")->submit(streamOp(""), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, scaled(5s)));
    ASSERT_TRUE(c->writer("s")->submit(indexOp(id(1)), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(2, scaled(5s)));
    ASSERT_TRUE(c->writer("s")->submit(streamOp(id(2)), results->callback(2)).accepted);
    ASSERT_TRUE(results->waitTotal(3, scaled(5s)));
    ASSERT_TRUE(c->writer("r")->submit(streamOp(id(3)), results->callback(3)).accepted);
    ASSERT_TRUE(results->waitTotal(4, scaled(5s)));

    for (std::uint64_t k = 0; k < 2; ++k)
    {
        SCOPED_TRACE(k);
        const auto result = results->result(k);
        EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
        EXPECT_EQ(result->httpStatus, 409) << describe(result);
        EXPECT_EQ(result->itemErrorType, "version_conflict_engine_exception");
    }
    const auto other = results->result(2);
    EXPECT_EQ(other->status, ic::Status::Failed) << describe(other);
    EXPECT_EQ(other->cause, ic::Cause::ItemPermanent) << describe(other);
    EXPECT_EQ(other->httpStatus, 409) << describe(other);
    EXPECT_EQ(other->itemErrorType, "resource_already_exists_exception");
    const auto retried = results->result(3);
    EXPECT_EQ(retried->status, ic::Status::Ok) << describe(retried);
    EXPECT_EQ(retried->httpStatus, 201) << "the resend's create" << describe(retried);
    EXPECT_EQ(receivedWithId(a, id(3)), 2u) << "the Retry policy resent it";
    EXPECT_EQ(a.bulk->answered(), 5u);

    EXPECT_EQ(stats("s").deduplicated, 0u) << describe(stats("s"));
    EXPECT_EQ(stats("r").deduplicated, 0u) << describe(stats("r"));
    EXPECT_EQ(publicDeduplicated(*c, "s"), 0u);
    EXPECT_EQ(publicDeduplicated(*c, "r"), 0u);
    EXPECT_FALSE(eventually([&] { return !dedupWarns().empty(); }, scaled(200ms))) << m_logs.dump();
    expectInvariants(stats("s"));
    expectInvariants(stats("r"));
}

// The resend of an IndexDataStream with an `_id` after a bulk that timed out once sent: node A
// records (applies) the bulk and never answers (request_timeout_ms 300), the op fails over to B, which answers 409
// version_conflict ⇒ Ok keeping the 409, `deduplicated` = 1, one dedup WARN; B received byte for byte the body A
// received, with the same `_id`. Mutant (d): the `_id` left out of the line.
TEST_F(BulkLogTest, DataStreamIdResendIsDeduplicated)
{
    const auto a = startNode(BulkScript::items().held(), "green", recording());
    const auto b = startNode(BulkScript::all(BulkItem::conflict()), "green", recording());
    ASSERT_NO_FATAL_FAILURE(startOn({a.url(), b.url()}, std::chrono::hours(1), {{"request_timeout_ms", "300"}}));
    auto c = client("c", {fastBucket("b", 1, 5)});
    auto results = Results::create();
    ASSERT_TRUE(c->writer("b")->submit(streamOp(id(0)), results->callback(0)).accepted);
    ASSERT_TRUE(results->waitTotal(1, scaled(10s)))
        << "requests: A " << bulkBodies(a).size() << ", B " << b.bulk->answered();

    const auto result = results->result(0);
    EXPECT_EQ(result->status, ic::Status::Ok) << describe(result);
    EXPECT_EQ(result->cause, ic::Cause::None);
    EXPECT_EQ(result->httpStatus, 409) << describe(result);
    EXPECT_EQ(result->itemErrorType, "version_conflict_engine_exception");
    EXPECT_EQ(results->count(0), 1);

    const auto sentA = bulkBodies(a);
    const auto sentB = bulkBodies(b);
    ASSERT_EQ(sentA.size(), 1u) << "A got (and applied) the first send";
    ASSERT_EQ(sentB.size(), 1u) << "B got the resend";
    const std::string expected =
        R"({"create":{"_index":"wazuh-events-test","_id":")" + id(0) + "\"}}\n" + streamOp("").body + "\n";
    EXPECT_EQ(sentA[0], expected);
    EXPECT_EQ(sentB[0], sentA[0]) << "the resend carries the same bytes, the same _id";

    ASSERT_TRUE(eventually([&] { return stats("b").deduplicated == 1; }, scaled(5s))) << describe(stats("b"));
    EXPECT_EQ(publicDeduplicated(*c, "b"), 1u);
    const auto warns = settledDedupWarns(1);
    ASSERT_EQ(warns.size(), 1u) << m_logs.dump();
    EXPECT_NE(warns.front().text.find("the indexer already had 1 document(s)"), std::string::npos)
        << warns.front().text;
    a.fake->releaseHeld();
    expectInvariants(stats("b"));
}

// With the default log_summary_interval_ms (60 000 ms), three `_bulk` in a row each with a 409
// version_conflict on an IndexDataStream with an `_id`: one dedup WARN for the run and `deduplicated` = 3. The interval
// itself is pinned by the deterministic DedupWarnRateLimitedByInterval (writeLocalBatch_test.cpp). Mutant (c): a WARN
// on every response.
TEST_F(BulkLogTest, DeduplicatedWarnsOnceForARun)
{
    constexpr std::uint64_t BULKS = 3;
    const auto a = startNode(BulkScript::all(BulkItem::conflict()));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1, 5)});
    auto writer = c->writer("b");
    auto results = Results::create();
    for (std::uint64_t k = 0; k < BULKS; ++k)
    {
        ASSERT_TRUE(writer->submit(streamOp(id(k)), results->callback(k)).accepted);
        ASSERT_TRUE(results->waitTotal(k + 1, scaled(5s))) << k;
        EXPECT_EQ(results->result(k)->httpStatus, 409) << describe(results->result(k));
    }
    EXPECT_EQ(a.bulk->answered(), BULKS) << "one _bulk per op";
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), BULKS);
    ASSERT_TRUE(eventually([&] { return stats("b").deduplicated == BULKS; }, scaled(5s))) << describe(stats("b"));
    EXPECT_EQ(publicDeduplicated(*c, "b"), BULKS);

    const auto warns = settledDedupWarns(1);
    ASSERT_EQ(warns.size(), 1u) << "one WARN for the run" << m_logs.dump();
    EXPECT_NE(warns.front().text.find("the indexer already had 1 document(s)"), std::string::npos)
        << warns.front().text;
    expectInvariants(stats("b"));
}
