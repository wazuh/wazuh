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

#include <chrono>
#include <future>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "bulkResponder.hpp"
#include "fakeIndexer.hpp"
#include "healthRules.hpp"
#include "indexer_client/runtime.hpp"
#include "write/bucket.hpp"
#include "write/encoding.hpp"

using namespace indexer_client;

namespace
{
    /// Test-owned configuration source: defaults for every internal option, one indexer host.
    class DefaultsSource final : public IConfigSource
    {
    public:
        explicit DefaultsSource(std::string host = "http://127.0.0.1:1")
            : m_host(std::move(host))
        {
        }

        std::optional<std::string> raw(std::string_view /*key*/) const override
        {
            return std::nullopt;
        }

        std::vector<std::string> keysWithPrefix(std::string_view /*prefix*/) const override
        {
            return {};
        }

        std::string indexerSectionJson() const override
        {
            return R"({"hosts":[")" + m_host + R"("]})";
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }

    private:
        std::string m_host;
    };
} // namespace

class BucketSpecTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        auto started = RuntimeOwner::start(ProcessId::Analysisd, DefaultsSource {});
        ASSERT_TRUE(started.ok()) << started.reason;
        m_ref = started.value;
    }

    void TearDown() override
    {
        RuntimeOwner::shutdown();
    }

    static BucketSpec valid(std::string name = "events")
    {
        BucketSpec spec;
        spec.name = std::move(name);
        return spec;
    }

    /// The reason prefix of a field of `buckets[index]` named `name`.
    static std::string field(const std::string& rest, std::size_t index = 0, const std::string& name = "events")
    {
        return "buckets[" + std::to_string(index) + "] ('" + name + "')." + rest;
    }

    /// Asserts that `buckets` is rejected with InvalidArgument and exactly `reason` (the full message of the rule, so
    /// that a different rule rejecting the same spec does not keep the case green).
    void expectRejected(std::vector<BucketSpec> buckets, const std::string& reason, std::string consumer = "consumer")
    {
        auto result = m_ref.client(consumer, std::move(buckets));
        EXPECT_EQ(result.cause, Cause::InvalidArgument) << result.reason;
        EXPECT_EQ(result.reason, reason);
        EXPECT_EQ(result.value, nullptr);
        EXPECT_EQ(m_ref.snapshot().clients, 0u) << "a rejected client must not take the consumer name";
    }

    RuntimeRef m_ref;
};

TEST_F(BucketSpecTest, InvalidEmptyConsumer)
{
    expectRejected({valid()}, "consumer name must not be empty", "");
}

TEST_F(BucketSpecTest, InvalidDuplicateConsumer)
{
    auto first = m_ref.client("dup", {valid()});
    ASSERT_TRUE(first.ok());
    auto second = m_ref.client("dup", {valid()});
    EXPECT_EQ(second.cause, Cause::InvalidArgument);
    EXPECT_EQ(second.reason, "consumer 'dup' already has a live client");

    // Once the first client is gone the name is free again.
    first.value.reset();
    EXPECT_TRUE(m_ref.client("dup", {valid()}).ok());
}

TEST_F(BucketSpecTest, InvalidEmptyBucketName)
{
    expectRejected({valid("")}, "buckets[0].name must not be empty");
}

TEST_F(BucketSpecTest, InvalidDuplicateBucketName)
{
    expectRejected({valid("a"), valid("b"), valid("a")}, "buckets[2].name 'a' is duplicated");
}

TEST_F(BucketSpecTest, InvalidZeroWeight)
{
    auto spec = valid();
    spec.weight = 0;
    expectRejected({spec}, field("weight must be > 0"));
}

TEST_F(BucketSpecTest, InvalidZeroQuotaBytes)
{
    auto spec = valid();
    spec.quotaBytes = 0;
    expectRejected({spec}, field("quotaBytes must be > 0"));
}

TEST_F(BucketSpecTest, InvalidZeroBulkMaxBytes)
{
    auto spec = valid();
    spec.bulk.maxBytes = 0;
    expectRejected({spec}, field("bulk.maxBytes must be > 0"));
}

TEST_F(BucketSpecTest, InvalidZeroBulkMaxDocs)
{
    auto spec = valid();
    spec.bulk.maxDocs = 0;
    expectRejected({spec}, field("bulk.maxDocs must be > 0"));
}

TEST_F(BucketSpecTest, InvalidNonPositiveBulkMaxAge)
{
    auto spec = valid();
    spec.bulk.maxAge = Duration {0};
    expectRejected({spec}, field("bulk.maxAge must be > 0"));
    spec.bulk.maxAge = Duration {-5};
    expectRejected({spec}, field("bulk.maxAge must be > 0"));
}

TEST_F(BucketSpecTest, InvalidBulkMaxBytesAboveQuota)
{
    auto spec = valid();
    spec.quotaBytes = 1024;
    spec.bulk.maxBytes = 1025;
    expectRejected({spec}, field("bulk.maxBytes must be <= quotaBytes"));
}

TEST_F(BucketSpecTest, InvalidBulkMaxBytesPlusReserveAboveQuota)
{
    // I62: the largest admissible op (a whole bulk) plus its result reserve must fit in the quota.
    const auto reserve = std::to_string(detail::write::RESULT_RESERVE);
    auto spec = valid();
    spec.quotaBytes = 4096;
    spec.bulk.maxBytes = 4096; // maxBytes == quotaBytes: no room for the reserve.
    expectRejected({spec}, field("bulk.maxBytes + RESULT_RESERVE (" + reserve + ") must be <= quotaBytes"));
    spec.bulk.maxBytes = 4096 - detail::write::RESULT_RESERVE + 1; // One byte short.
    expectRejected({spec}, field("bulk.maxBytes + RESULT_RESERVE (" + reserve + ") must be <= quotaBytes"));
    spec.bulk.maxBytes = 4096 - detail::write::RESULT_RESERVE; // Exactly fits.
    EXPECT_TRUE(m_ref.client("consumer", {spec}).ok());
}

TEST_F(BucketSpecTest, InvalidRetryBaseAboveCap)
{
    auto spec = valid();
    spec.retry.base = Duration {2000};
    spec.retry.cap = Duration {1000};
    expectRejected({spec}, field("retry.base must be <= retry.cap"));
}

TEST_F(BucketSpecTest, InvalidQuotaAboveGlobalQuota)
{
    auto spec = valid();
    spec.quotaBytes = RuntimeConfig {}.globalQuotaBytes + 1; // The runtime runs with the default global quota.
    spec.bulk.maxBytes = 1024;
    expectRejected({spec},
                   field("quotaBytes must be <= the runtime's global_quota_bytes (" +
                         std::to_string(RuntimeConfig {}.globalQuotaBytes) + ")"));
}

TEST_F(BucketSpecTest, InvalidNonPositiveRetryBase)
{
    auto spec = valid();
    spec.retry.base = Duration {0};
    expectRejected({spec}, field("retry.base must be > 0"));
    spec.retry.base = Duration {-1};
    expectRejected({spec}, field("retry.base must be > 0"));
}

TEST_F(BucketSpecTest, InvalidNonPositiveRetryCap)
{
    auto spec = valid();
    spec.retry.cap = Duration {0};
    expectRejected({spec}, field("retry.cap must be > 0"));
    spec.retry.cap = Duration {-1};
    expectRejected({spec}, field("retry.cap must be > 0"));
}

TEST_F(BucketSpecTest, InvalidJitterOutOfRange)
{
    for (const double jitter : {-0.01, 1.01, std::numeric_limits<double>::quiet_NaN()})
    {
        SCOPED_TRACE(jitter);
        auto spec = valid();
        spec.retry.jitter = jitter;
        expectRejected({spec}, field("retry.jitter must be in [0, 1]"));
    }
}

TEST_F(BucketSpecTest, InvalidZeroMaxAttempts)
{
    auto spec = valid();
    spec.retry.maxAttempts = 0u;
    expectRejected({spec}, field("retry.maxAttempts must be > 0 (or unset for unlimited)"));
}

TEST_F(BucketSpecTest, InvalidNonPositiveMaxDuration)
{
    auto spec = valid();
    spec.retry.maxDuration = Duration {0};
    expectRejected({spec}, field("retry.maxDuration must be > 0 (or unset for unlimited)"));
    spec.retry.maxDuration = Duration {-1};
    expectRejected({spec}, field("retry.maxDuration must be > 0 (or unset for unlimited)"));
}

TEST_F(BucketSpecTest, InvalidZeroRetryOnConflict)
{
    auto spec = valid();
    spec.onConflict.kind = ConflictPolicy::Kind::Retry;
    spec.onConflict.retryOnConflict = 0;
    expectRejected({spec}, field("onConflict.retryOnConflict must be > 0 with ConflictPolicy::Retry"));
}

// E3c-1 I73: ConflictPolicy::Retry registers with retryOnConflict in [1, MAX_RETRY_ON_CONFLICT] (both bounds; 0 is
// InvalidZeroRetryOnConflict) and 101 is refused naming the field. Mutant: the cap check removed.
TEST_F(BucketSpecTest, RetryConflictPolicyRegisters)
{
    auto one = valid("one");
    one.onConflict.kind = ConflictPolicy::Kind::Retry;
    one.onConflict.retryOnConflict = 1;
    auto hundred = valid("hundred");
    hundred.onConflict.kind = ConflictPolicy::Kind::Retry;
    hundred.onConflict.retryOnConflict = detail::write::MAX_RETRY_ON_CONFLICT;
    auto result = m_ref.client("retry", {one, hundred});
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_NE(result.value, nullptr);
    EXPECT_EQ(m_ref.snapshot().clients, 1u);

    auto spec = valid();
    spec.onConflict.kind = ConflictPolicy::Kind::Retry;
    spec.onConflict.retryOnConflict = detail::write::MAX_RETRY_ON_CONFLICT + 1;
    auto refused = m_ref.client("consumer", {spec});
    EXPECT_EQ(refused.cause, Cause::InvalidArgument) << refused.reason;
    EXPECT_EQ(refused.reason, field("onConflict.retryOnConflict must be <= 100 with ConflictPolicy::Retry"));
    EXPECT_EQ(refused.value, nullptr);
}

// E3c-2 (I79): the bulk sender honours `ordered`, so the refusal of E3b-2 (G-diff obj. 2) is lifted: an ordered bucket
// registers and gets its writer, and every other rule still applies to it (an ordered spec with a bad field is
// refused naming that field, and takes no consumer name).
TEST_F(BucketSpecTest, OrderedRegisters)
{
    auto bad = valid();
    bad.ordered = true;
    bad.weight = 0;
    expectRejected({bad}, field("weight must be > 0"));

    auto spec = valid();
    spec.ordered = true;
    auto result = m_ref.client("ordered", {spec});
    ASSERT_TRUE(result.ok()) << result.reason;
    ASSERT_NE(result.value, nullptr);
    EXPECT_TRUE(result.value->valid());
    EXPECT_NE(result.value->writer("events"), nullptr);
    EXPECT_EQ(m_ref.snapshot().clients, 1u);
}

TEST_F(BucketSpecTest, InvalidBlockWithoutTimeout)
{
    auto spec = valid();
    spec.overflow.kind = Overflow::Kind::Block;
    spec.overflow.blockTimeout = Duration {0};
    expectRejected({spec}, field("overflow.blockTimeout must be > 0 with Overflow::Block"));
}

TEST_F(BucketSpecTest, InvalidSecondBucketNamesItsIndex)
{
    auto bad = valid("second");
    bad.weight = 0;
    expectRejected({valid("first"), bad}, field("weight must be > 0", 1, "second"));
}

TEST_F(BucketSpecTest, ValidSpecAccepted)
{
    auto blocking = valid("blocking");
    blocking.overflow.kind = Overflow::Kind::Block;
    blocking.overflow.blockTimeout = Duration {100};
    blocking.weight = 7;
    auto edge = valid("edge");
    edge.quotaBytes = 4096 + detail::write::RESULT_RESERVE;
    edge.bulk.maxBytes = 4096; // maxBytes + RESULT_RESERVE == quotaBytes is allowed.
    edge.retry.base = Duration {500};
    edge.retry.cap = Duration {500};
    edge.retry.maxAttempts = std::nullopt;
    edge.retry.maxDuration = std::nullopt;
    edge.retry.jitter = 1.0; // Both ends of [0, 1] are allowed.
    blocking.retry.jitter = 0.0;
    blocking.retry.maxAttempts = 1u;
    blocking.quotaBytes = RuntimeConfig {}.globalQuotaBytes; // quotaBytes == global_quota_bytes is allowed.
    blocking.retry.maxDuration = Duration {1};               // The smallest positive maxDuration is allowed.
    // ordered = true registers (OrderedRegisters); Retry registers (RetryConflictPolicyRegisters).
    edge.onConflict.kind = ConflictPolicy::Kind::Success;
    edge.onConflict.retryOnConflict = 0;                             // retryOnConflict is ignored without Retry.
    EXPECT_EQ(BucketSpec {}.onAmbiguous5xx, AmbiguousPolicy::Retry); // I105: the default keeps resending.
    edge.onAmbiguous5xx = AmbiguousPolicy::Fail;

    auto result = m_ref.client("valid", {valid(), blocking, edge});
    ASSERT_TRUE(result.ok()) << result.reason;
    ASSERT_NE(result.value, nullptr);
    EXPECT_TRUE(result.value->valid());
    EXPECT_EQ(m_ref.snapshot().clients, 1u);

    auto queryOnly = m_ref.client("query-only", {});
    EXPECT_TRUE(queryOnly.ok()) << "a consumer without buckets is a query-only client";
    EXPECT_EQ(m_ref.snapshot().clients, 2u);
}

TEST_F(BucketSpecTest, WriterSubmitResolvesThroughTheSender)
{
    // E3b-2: the production sink is the bulk sender. A fake indexer (green health, every `_bulk` op created) replaces
    // the fixture's unreachable host.
    auto bulk = std::make_shared<indexer_client::testing::BulkResponder>();
    indexer_client::testing::FakeIndexer fake;
    fake.addRule(indexer_client::testing::healthRule("green"));
    fake.addRule(indexer_client::testing::bulkRule(bulk));
    fake.start();
    RuntimeOwner::shutdown();
    auto started = RuntimeOwner::start(ProcessId::Analysisd, DefaultsSource {fake.baseUrl()});
    ASSERT_TRUE(started.ok()) << started.reason;
    m_ref = started.value;

    auto spec = valid("events");
    spec.bulk.maxDocs = 1; // One op is a batch: no wait for maxAge.
    auto client = m_ref.client("writer", {spec});
    ASSERT_TRUE(client.ok()) << client.reason;

    EXPECT_EQ(client.value->writer("missing"), nullptr) << "an unknown bucket has no writer";
    auto writer = client.value->writer("events");
    ASSERT_NE(writer, nullptr);

    Op op;
    op.index = "wazuh-states-test";
    op.id = "1";
    op.body = R"({"a":1})";
    // submit admits the op; the sender writes it (once the probe has the node up) and the ticket and the callback
    // both get the item's result.
    auto callbackResult = std::make_shared<std::promise<OpResult>>();
    auto callbackFuture = callbackResult->get_future();
    const auto submit =
        writer->submit(op, [callbackResult](const OpResult& result) { callbackResult->set_value(result); });
    ASSERT_TRUE(submit.accepted) << toString(submit.cause);
    EXPECT_EQ(submit.cause, Cause::None);
    const auto result = submit.ticket.wait(std::chrono::steady_clock::now() + std::chrono::seconds(5));
    ASSERT_TRUE(result.ok()) << toString(result.cause);
    EXPECT_EQ(result.value.status, Status::Ok);
    EXPECT_EQ(result.value.cause, Cause::None);
    EXPECT_EQ(result.value.outcome, ItemOutcome::Created);
    EXPECT_EQ(result.value.httpStatus, 201);
    ASSERT_EQ(callbackFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto called = callbackFuture.get();
    EXPECT_EQ(called.status, Status::Ok);
    EXPECT_EQ(called.outcome, ItemOutcome::Created);
    ASSERT_EQ(bulk->received().size(), 1u);
    ASSERT_EQ(bulk->received()[0].size(), 1u);
    EXPECT_EQ(bulk->received()[0][0].id, "1");

    // E3c-1: a group's op goes through the same sender; its ticket completes with the item's result. E3c-2:
    // cancel(tag) reaches the bucket (nothing of the tag left: a ready success; the empty tag: InvalidArgument).
    auto group = writer->group();
    op.id = "2";
    EXPECT_EQ(group.add(op), Cause::None) << group.lastAddReason();
    const auto groupTicket = group.commit();
    const auto groupResult = groupTicket.wait(std::chrono::steady_clock::now() + std::chrono::seconds(5));
    ASSERT_TRUE(groupResult.ok()) << toString(groupResult.cause);
    ASSERT_EQ(groupResult.value.size(), 1u);
    EXPECT_EQ(groupResult.value[0].status, Status::Ok);
    EXPECT_EQ(groupResult.value[0].outcome, ItemOutcome::Created);
    ASSERT_EQ(bulk->received().size(), 2u);
    ASSERT_EQ(bulk->received()[1].size(), 1u);
    EXPECT_EQ(bulk->received()[1][0].id, "2");

    const auto cancel = writer->cancel("agent-001");
    EXPECT_TRUE(cancel.ready());
    EXPECT_TRUE(cancel.wait(std::chrono::steady_clock::now()).ok());
    const auto refused = writer->cancel("");
    EXPECT_TRUE(refused.ready());
    EXPECT_EQ(refused.wait(std::chrono::steady_clock::now()).cause, Cause::InvalidArgument);
    RuntimeOwner::shutdown(); // Before the fake goes away.
}
