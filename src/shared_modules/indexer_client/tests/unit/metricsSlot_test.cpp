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

// CA-E11b-2 (D95): the pull-metrics slot invsync and VD share (indexer_client/metricsSlot.hpp). One Client::metrics()
// per TTL, buckets at 0 once the Client is released, the runtime's values without a Client, repoint() and the prefix
// filter. Mutants: the TTL check dropped or inverted, a strong reference kept, the runtime read only with a Client, the
// filter ignored, repoint() leaving the snapshot fresh.

#include <chrono>
#include <memory>
#include <string>
#include <tuple>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "indexer_client/metricsSlot.hpp"
#include "mockIndexerClient.hpp"

using namespace indexer_client;
using namespace std::chrono_literals;
using ::testing::Return;

namespace
{
    constexpr auto BULK_REQUESTS {"indexer_client.bucket.c.b.bulk_requests"};
    constexpr auto CALLBACKS_SKIPPED {"indexer_client.client.c.callbacks_skipped"};
    constexpr auto NETWORK_THREADS {"indexer_client.runtime.network_threads"};

    ClientMetrics metricsWith(std::uint64_t bulkRequests)
    {
        ClientMetrics metrics;
        metrics.consumer = "c";
        metrics.callbacksSkipped = 3;
        metrics.buckets.emplace_back();
        metrics.buckets.back().consumer = "c";
        metrics.buckets.back().bucket = "b";
        metrics.buckets.back().bulkRequests = bulkRequests;
        return metrics;
    }
} // namespace

TEST(MetricsSlotTest, OneSnapshotPerTtl)
{
    auto client = std::make_shared<MockClient>();
    EXPECT_CALL(*client, metrics()).Times(1).WillOnce(Return(metricsWith(7)));

    MetricsSlot slot {1h};
    slot.repoint(client);
    EXPECT_EQ(7.0, slot.value(BULK_REQUESTS));
    EXPECT_EQ(3.0, slot.value(CALLBACKS_SKIPPED)) << "the second read is served from the same snapshot";
}

TEST(MetricsSlotTest, RefreshesOnceTheTtlExpired)
{
    auto client = std::make_shared<MockClient>();
    EXPECT_CALL(*client, metrics()).Times(2).WillOnce(Return(metricsWith(7))).WillOnce(Return(metricsWith(9)));

    MetricsSlot slot {0ms};
    slot.repoint(client);
    EXPECT_EQ(7.0, slot.value(BULK_REQUESTS));
    EXPECT_EQ(9.0, slot.value(BULK_REQUESTS));
}

TEST(MetricsSlotTest, ReleasedClientReadsZero)
{
    auto client = std::make_shared<MockClient>();
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metricsWith(7)));

    MetricsSlot slot {0ms};
    slot.repoint(client);
    EXPECT_EQ(7.0, slot.value(BULK_REQUESTS));

    std::weak_ptr<MockClient> watch = client;
    client.reset();
    EXPECT_TRUE(watch.expired()) << "the slot keeps no strong reference";
    EXPECT_EQ(0.0, slot.value(BULK_REQUESTS));
    EXPECT_FALSE(slot.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.client.has_value(); }));
}

TEST(MetricsSlotTest, RuntimeWithoutClient)
{
    MetricsSlot slot {0ms};
    slot.repoint({}, RuntimeRef {});
    const auto [hasRuntime, hasValue, bulk] = slot.read(
        [](const MetricsSlotSnapshot& snapshot)
        {
            return std::make_tuple(snapshot.runtime.has_value(),
                                   snapshot.values.count(NETWORK_THREADS) == 1,
                                   snapshot.value(BULK_REQUESTS));
        });
    EXPECT_TRUE(hasRuntime) << "the runtime is read without a Client (I168)";
    EXPECT_TRUE(hasValue) << "its names are published";
    EXPECT_EQ(0.0, bulk);

    MetricsSlot withoutRuntime {0ms};
    withoutRuntime.repoint({});
    EXPECT_FALSE(withoutRuntime.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.runtime.has_value(); }));
    EXPECT_EQ(0U, withoutRuntime.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.values.size(); }));
}

TEST(MetricsSlotTest, RuntimeAndClientTogether)
{
    auto client = std::make_shared<MockClient>();
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metricsWith(5)));

    MetricsSlot slot {1h};
    slot.repoint(client, RuntimeRef {});
    EXPECT_EQ(5.0, slot.value(BULK_REQUESTS));
    EXPECT_EQ(1U,
              slot.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.values.count(NETWORK_THREADS); }));
}

TEST(MetricsSlotTest, RepointRefreshesWithinTheTtl)
{
    auto first = std::make_shared<MockClient>();
    auto second = std::make_shared<MockClient>();
    EXPECT_CALL(*first, metrics()).WillOnce(Return(metricsWith(1)));
    EXPECT_CALL(*second, metrics()).WillOnce(Return(metricsWith(2)));

    MetricsSlot slot {1h};
    slot.repoint(first);
    EXPECT_EQ(1.0, slot.value(BULK_REQUESTS));
    slot.repoint(second);
    EXPECT_EQ(2.0, slot.value(BULK_REQUESTS)) << "a restart's Client is read at once";
}

TEST(MetricsSlotTest, PrefixFilter)
{
    auto client = std::make_shared<MockClient>();
    EXPECT_CALL(*client, metrics()).WillOnce(Return(metricsWith(7)));

    MetricsSlot slot {1h, {"indexer_client.bucket.c.b."}};
    slot.repoint(client, RuntimeRef {});
    EXPECT_EQ(7.0, slot.value(BULK_REQUESTS));
    EXPECT_EQ(0.0, slot.value(CALLBACKS_SKIPPED)) << "outside the prefix";
    EXPECT_EQ(0U,
              slot.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.values.count(NETWORK_THREADS); }));
    EXPECT_TRUE(slot.read([](const MetricsSlotSnapshot& snapshot) { return snapshot.runtime.has_value(); }))
        << "the raw snapshots are kept whatever the filter";
}
