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

// Threads and the spread of transfers over the K loops (plan-E2a-1 §Tests, lot A: CA-1, T1, I22c).

#include <algorithm>
#include <iterator>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;
namespace hooks = indexer_client::testing_hooks;

// CA-1/T1: K + M threads and not one more, sampled while min(64, 8·K) requests are held open by the fake (8 = the
// per-host connection cap of each multi) and the rest wait inside curl. Numeric hosts: no resolver thread.
TEST_F(TransportTest, ThreadsStayKPlusM)
{
    constexpr std::uint32_t M = 2;
    constexpr std::size_t SENT = 64;
    for (const std::uint32_t k : {1u, 3u})
    {
        SCOPED_TRACE("K=" + std::to_string(k));
        FakeIndexerOptions options;
        options.threads = 64;
        FakeIndexer fake(options);
        Rule hold;
        hold.hold = true;
        fake.addRule(hold);
        fake.start();

        const auto base = settledTasks(); // The fake's threads included.
        hooks::clearRuntimeThreads();
        auto transport = startRuntime(k, M);
        ASSERT_NE(transport, nullptr);

        auto collector = Collector::create();
        for (std::size_t i = 0; i < SENT; ++i)
        {
            ASSERT_TRUE(submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/threads"))
                            .admission.admitted);
        }
        const std::size_t expectedHeld = std::min<std::size_t>(SENT, 8 * k);
        ASSERT_TRUE(fake.waitHeld(expectedHeld, 10s)) << "held " << fake.heldNow();

        const auto sample = settledTasks();
        EXPECT_EQ(fake.heldNow(), expectedHeld) << "the per-host cap is 8 connections per loop";
        std::set<std::string> delta;
        std::set_difference(
            sample.begin(), sample.end(), base.begin(), base.end(), std::inserter(delta, delta.begin()));
        EXPECT_EQ(delta.size(), k + M) << "threads over the stable base while " << expectedHeld << " are held";

        ASSERT_TRUE(eventually([&] { return hooks::runtimeThreads().size() >= k + M; }, 5s));
        const auto own = hooks::runtimeThreads();
        EXPECT_EQ(own.size(), k + M) << "own TIDs";
        std::set<std::string> ownSet;
        for (const auto tid : own)
        {
            ownSet.insert(std::to_string(tid));
        }
        EXPECT_EQ(ownSet, delta) << "every new task is one of the runtime's own threads";

        fake.releaseHeld();
        ASSERT_TRUE(collector->waitTotal(SENT, 30s)) << collector->total() << " of " << SENT;
        for (std::uint64_t key = 0; key < SENT; ++key)
        {
            EXPECT_EQ(collector->count(key), 1);
            EXPECT_EQ(collector->result(key)->status, 200);
        }
        ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    }
}

namespace
{
    /// One fake worker per keep-alive connection: 3 loops × 8 connections must all be served at once.
    FakeIndexerOptions wideFake()
    {
        FakeIndexerOptions options;
        options.threads = 64;
        return options;
    }

    /// Sends `count` GETs alternating over `urls` on a K = 3 runtime and checks that every loop completed some.
    void
    spreadOver(const std::shared_ptr<Transport>& transport, const std::vector<std::string>& urls, std::size_t count)
    {
        auto collector = Collector::create();
        for (std::size_t i = 0; i < count; ++i)
        {
            ASSERT_TRUE(submitTo(*transport, collector, request(HttpMethod::Get, urls[i % urls.size()] + "/spread"))
                            .admission.admitted);
        }
        ASSERT_TRUE(collector->waitTotal(count, 30s));
        const auto stats = transport->stats();
        ASSERT_EQ(stats.completedPerLoop.size(), 3u);
        for (std::size_t loop = 0; loop < 3; ++loop)
        {
            EXPECT_GT(stats.completedPerLoop[loop], 0u) << "loop " << loop << " completed nothing";
        }
        EXPECT_EQ(sumOf(stats.completedPerLoop), count);
    }
} // namespace

TEST_F(TransportTest, SpreadsTransfersOneNode)
{
    FakeIndexer fake(wideFake());
    fake.start();
    auto transport = startRuntime(3, 2);
    ASSERT_NE(transport, nullptr);
    spreadOver(transport, {fake.baseUrl()}, 60);
}

TEST_F(TransportTest, SpreadsTransfersTwoNodes)
{
    FakeIndexer first(wideFake());
    FakeIndexer second(wideFake());
    first.start();
    second.start();
    auto transport = startRuntime(3, 2);
    ASSERT_NE(transport, nullptr);
    spreadOver(transport, {first.baseUrl(), second.baseUrl()}, 60);
    EXPECT_EQ(first.requestCount(), 30u);
    EXPECT_EQ(second.requestCount(), 30u);
}
