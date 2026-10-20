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
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"

using namespace indexer_client;

namespace
{
    /// Test-owned configuration source: defaults for every internal option, one indexer host.
    class DefaultsSource final : public IConfigSource
    {
    public:
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
            return R"({"hosts":["http://127.0.0.1:9200"]})";
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }
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
    edge.quotaBytes = 4096;
    edge.bulk.maxBytes = 4096; // maxBytes == quotaBytes is allowed.
    edge.retry.base = Duration {500};
    edge.retry.cap = Duration {500};
    edge.retry.maxAttempts = std::nullopt;
    edge.retry.maxDuration = std::nullopt;
    edge.retry.jitter = 1.0; // Both ends of [0, 1] are allowed.
    blocking.retry.jitter = 0.0;
    blocking.retry.maxAttempts = 1u;
    blocking.quotaBytes = RuntimeConfig {}.globalQuotaBytes; // quotaBytes == global_quota_bytes is allowed.
    blocking.retry.maxDuration = Duration {1};               // The smallest positive maxDuration is allowed.
    blocking.onConflict.kind = ConflictPolicy::Kind::Retry;
    blocking.onConflict.retryOnConflict = 1; // The smallest retryOnConflict with Retry is allowed.
    edge.onConflict.kind = ConflictPolicy::Kind::Success;
    edge.onConflict.retryOnConflict = 0; // retryOnConflict is ignored without Retry.
    edge.ordered = true;

    auto result = m_ref.client("valid", {valid(), blocking, edge});
    ASSERT_TRUE(result.ok()) << result.reason;
    ASSERT_NE(result.value, nullptr);
    EXPECT_TRUE(result.value->valid());
    EXPECT_EQ(m_ref.snapshot().clients, 1u);

    auto queryOnly = m_ref.client("query-only", {});
    EXPECT_TRUE(queryOnly.ok()) << "a consumer without buckets is a query-only client";
    EXPECT_EQ(m_ref.snapshot().clients, 2u);
}

TEST_F(BucketSpecTest, WriterStubReturnsUnavailable)
{
    auto client = m_ref.client("writer", {valid("events")});
    ASSERT_TRUE(client.ok()) << client.reason;

    EXPECT_EQ(client.value->writer("missing"), nullptr) << "an unknown bucket has no writer";
    auto writer = client.value->writer("events");
    ASSERT_NE(writer, nullptr);

    Op op;
    op.index = "wazuh-states-test";
    op.id = "1";
    op.body = R"({"a":1})";
    const auto submit = writer->submit(op, [](const OpResult&) { FAIL() << "a rejected submit has no callback"; });
    EXPECT_FALSE(submit.accepted);
    EXPECT_EQ(submit.cause, Cause::Unavailable);
    EXPECT_FALSE(submit.ticket.ready());

    auto group = writer->group();
    EXPECT_EQ(group.add(op), Cause::Unavailable);
    const auto groupTicket = group.commit();
    EXPECT_TRUE(groupTicket.ready());
    EXPECT_EQ(groupTicket.wait(std::chrono::steady_clock::now()).cause, Cause::Unavailable);

    const auto cancel = writer->cancel("agent-001");
    EXPECT_TRUE(cancel.ready());
    EXPECT_EQ(cancel.wait(std::chrono::steady_clock::now()).cause, Cause::Unavailable);
}
