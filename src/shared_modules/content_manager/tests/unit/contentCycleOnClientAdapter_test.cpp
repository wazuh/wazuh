/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The content cycle (PitSession -> PitPaginator -> ContentCycle) on the indexer_client adapter, over a real runtime
// and the library's fake indexer (content side and consumer side).

#include "components/contentCycle.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "fakes/realIndexerFixture.hpp"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using cmtest::RealIndexer;
using cmtest::RealIndexerOptions;
using cmtest::waitUntil;
using content_manager::CycleStatus;
using fakes::MemoryTokenStore;
using fakes::RecordingSink;
using indexer_client::testing::PitCall;
using indexer_client::testing::PitRequestView;
using indexer_client::testing::PitResponder;
using indexer_client::testing::Rule;

namespace
{
    constexpr auto TOPIC = "test.topic";

    /// A cursor-mode cycle over 300 synthetic documents, 50 per page, with no consumer document to validate.
    struct CycleOnAdapter
    {
        RealIndexer env;
        std::shared_ptr<content_manager::IContentIndexer> adapter;
        std::shared_ptr<RecordingSink> sink {std::make_shared<RecordingSink>()};
        std::shared_ptr<MemoryTokenStore> tokens {std::make_shared<MemoryTokenStore>()};
        std::atomic<bool> stop {false};
        ContentCycle::Config config;

        CycleOnAdapter()
        {
            config.topic = TOPIC;
            config.pit.dataIndices = {"idx"};
            config.pit.consumerStatusIndex = "";
            config.fetchTemplate.sort = nlohmann::json::array({nlohmann::json {{"n", "asc"}}});
            config.fetchTemplate.pageSize = 50;
            // Every page is durable: the token follows the pages, as it does for a sink that commits per page.
            sink->pageStatus = content_manager::PageStatus::Durable;
        }

        /// Starts the runtime (after the test scripted the fake) and builds the adapter.
        void start()
        {
            env.startRuntime();
            ASSERT_TRUE(env.makeClient()) << env.startError;
            adapter = env.adapter();
        }

        std::unique_ptr<ContentCycle> build()
        {
            ConsumerGate::resetCache();
            return std::make_unique<ContentCycle>(
                config, adapter, std::make_unique<OffsetCursorDetector>("n"), sink, tokens, stop);
        }

        /// The queries of the PIT searches received, in arrival order.
        std::vector<nlohmann::json> searchQueries() const
        {
            std::vector<nlohmann::json> queries;
            for (const auto& request : env.searchRequests())
            {
                queries.push_back(RealIndexer::bodyOf(request).at("query"));
            }
            return queries;
        }
    };

    /// Answers the @p ordinal-th PIT search and the following ones with @p status and @p body.
    void failFrom(RealIndexer& env, std::size_t ordinal, int status, std::string body)
    {
        env.pits->intercept(
            [ordinal, status, body = std::move(body)](const PitRequestView& view, Rule& reply)
            {
                if (view.call != PitCall::Search || view.ordinal < ordinal)
                {
                    return false;
                }
                reply.status = status;
                reply.body = body;
                return true;
            });
    }

    /// A 400 is final for the library; a 500 would be retried.
    constexpr auto BAD_REQUEST = R"({"error":{"type":"parsing_exception","reason":"bad request"},"status":400})";

    nlohmann::json rangeAfter(std::uint64_t token)
    {
        return nlohmann::json {{"range", {{"n", {{"gt", token}}}}}};
    }
} // namespace

// ---------------------------------------------------------------- Content side

TEST(ContentCycleOnClientAdapter, FullDownload)
{
    CycleOnAdapter harness;
    ASSERT_NO_FATAL_FAILURE(harness.start());

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Updated) << outcome.detail;
    EXPECT_EQ(outcome.documentsDelivered, 300U);
    EXPECT_EQ(outcome.token, "300");
    EXPECT_EQ(harness.sink->documentCount(), 300U);
    ASSERT_EQ(harness.sink->sessions.size(), 1U);
    EXPECT_EQ(harness.sink->sessions.front().kind, content_manager::SessionKind::FullReload);
    ASSERT_EQ(harness.sink->commits.size(), 1U);
    EXPECT_EQ(harness.sink->commits.front().finalToken, "300");
    EXPECT_EQ(harness.tokens->token, "300");

    ASSERT_TRUE(harness.env.waitDeletes(1)) << "the session's PIT must be deleted";
    EXPECT_EQ(harness.env.pits->created(), 1U);
    EXPECT_EQ(harness.env.pits->requests(PitCall::Delete), harness.env.pits->created());
}

// A page over the query cap on the real library is asked again with half the hits on the same PIT and cursor:
// the cycle completes, every document once, and the page sizes follow the cut and the regrowth.
TEST(ContentCycleOnClientAdapter, TooLargePagesAreHalved)
{
    CycleOnAdapter harness;
    // Content pages are capped by max_response_bytes itself: any page asking for more than 12 hits gets a
    // 100000-byte body, over the 80000 of max_response_bytes.
    const std::string padded = R"({"took":1,"hits":{"hits":[]},"pad":")" + std::string(100000, 'x') + R"("})";
    harness.env.pits->intercept(
        [padded](const PitRequestView& view, Rule& reply)
        {
            if (view.call != PitCall::Search || view.body.value("size", 0) <= 12)
            {
                return false;
            }
            reply.status = 200;
            reply.body = padded;
            return true;
        });
    harness.env.startRuntime("wazuh_modules.indexer_client_max_response_bytes=80000\n");
    ASSERT_TRUE(harness.env.makeClient()) << harness.env.startError;
    harness.adapter = harness.env.adapter();

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Updated) << outcome.detail;
    EXPECT_EQ(outcome.documentsDelivered, 300U);
    EXPECT_EQ(outcome.token, "300");
    std::vector<std::int64_t> delivered;
    for (const auto& page : harness.sink->pages)
    {
        for (const auto& hit : page)
        {
            delivered.push_back(hit.at("_source").at("n").get<std::int64_t>());
        }
    }
    ASSERT_EQ(delivered.size(), 300U);
    for (std::size_t i = 0; i < delivered.size(); ++i)
    {
        ASSERT_EQ(delivered[i], static_cast<std::int64_t>(i + 1)) << "document " << i + 1 << " lost or repeated";
    }

    // 50 (too large), 25 (too large), 12 x 4, 24 (too large), 12 x 4, ...: one PIT, the same cursor on each retry.
    const auto searches = harness.env.searchRequests();
    ASSERT_GE(searches.size(), 4U);
    EXPECT_EQ(RealIndexer::bodyOf(searches[0]).at("size"), 50);
    EXPECT_EQ(RealIndexer::bodyOf(searches[1]).at("size"), 25);
    EXPECT_EQ(RealIndexer::bodyOf(searches[2]).at("size"), 12);
    EXPECT_FALSE(RealIndexer::bodyOf(searches[1]).contains("search_after"));
    EXPECT_FALSE(RealIndexer::bodyOf(searches[2]).contains("search_after"));
    EXPECT_EQ(RealIndexer::bodyOf(searches[3]).at("search_after"), nlohmann::json::array({12}));
    EXPECT_EQ(harness.env.pits->created(), 1U);
}

TEST(ContentCycleOnClientAdapter, AbortMidway)
{
    CycleOnAdapter harness;
    failFrom(harness.env, 4, 400, BAD_REQUEST);
    ASSERT_NO_FATAL_FAILURE(harness.start());

    const auto failed = harness.build()->run({});

    EXPECT_EQ(failed.status, CycleStatus::FailedTransport) << failed.detail;
    EXPECT_NE(failed.detail.find("client_4xx"), std::string::npos) << failed.detail;
    EXPECT_EQ(harness.sink->documentCount(), 150U) << "three pages were delivered before the 400";
    EXPECT_TRUE(harness.sink->commits.empty());
    ASSERT_EQ(harness.sink->aborts.size(), 1U);
    EXPECT_EQ(harness.tokens->token, "150") << "the token of the last confirmed batch";
    EXPECT_EQ(failed.token, "150");
    ASSERT_TRUE(harness.env.waitDeletes(1));
    EXPECT_EQ(harness.env.pits->created(), 1U);

    // The next cycle resumes from that token and ends at 300 (the fake serves its documents whatever the query:
    // the resume is read on the wire).
    harness.env.pits->intercept(nullptr);
    harness.env.fake->clearRequests();
    harness.sink->aborts.clear();
    const auto resumed = harness.build()->run({});

    EXPECT_EQ(resumed.status, CycleStatus::Updated) << resumed.detail;
    EXPECT_EQ(resumed.token, "300");
    ASSERT_EQ(harness.sink->sessions.size(), 2U);
    EXPECT_EQ(harness.sink->sessions.back().kind, content_manager::SessionKind::Incremental);
    const auto queries = harness.searchQueries();
    ASSERT_FALSE(queries.empty());
    EXPECT_EQ(queries.front(), rangeAfter(150));
    ASSERT_TRUE(harness.env.waitDeletes(2));
    EXPECT_EQ(harness.env.pits->created(), 2U);
    EXPECT_EQ(harness.env.pits->requests(PitCall::Delete), harness.env.pits->created());
}

TEST(ContentCycleOnClientAdapter, RestartFromToken)
{
    CycleOnAdapter harness;
    harness.tokens->token = "150";
    ASSERT_NO_FATAL_FAILURE(harness.start());

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Updated) << outcome.detail;
    EXPECT_EQ(outcome.token, "300");
    ASSERT_EQ(harness.sink->sessions.size(), 1U);
    EXPECT_EQ(harness.sink->sessions.front().kind, content_manager::SessionKind::Incremental);
    const auto queries = harness.searchQueries();
    ASSERT_FALSE(queries.empty());
    EXPECT_EQ(queries.front(), rangeAfter(150)) << "the first page must ask for what follows the stored token";
    ASSERT_TRUE(harness.env.waitDeletes(1));
    EXPECT_EQ(harness.env.pits->created(), 1U);
    EXPECT_EQ(harness.env.pits->requests(PitCall::Delete), 1U);
}

// ---------------------------------------------------------------- Consumer side

TEST(ContentCycleOnClientAdapter, ExpiredMidwayResumes)
{
    CycleOnAdapter harness;
    // The fake expires the PIT after the third page (once): the fourth search finds no context.
    harness.env.pits->intercept(
        [pits = harness.env.pits.get()](const PitRequestView& view, Rule&)
        {
            if (view.call == PitCall::Search && view.ordinal == 4)
            {
                pits->expireAll();
            }
            return false;
        });
    ASSERT_NO_FATAL_FAILURE(harness.start());

    const auto failed = harness.build()->run({});

    EXPECT_EQ(failed.status, CycleStatus::FailedTransport) << failed.detail;
    EXPECT_NE(failed.detail.find("pit_expired"), std::string::npos) << failed.detail;
    EXPECT_EQ(harness.tokens->token, "150");
    EXPECT_EQ(harness.env.pits->created(), 1U);

    // The next cycle opens a NEW PIT and resumes from the token.
    harness.env.fake->clearRequests();
    const auto resumed = harness.build()->run({});

    EXPECT_EQ(resumed.status, CycleStatus::Updated) << resumed.detail;
    EXPECT_EQ(resumed.token, "300");
    EXPECT_EQ(harness.env.pits->created(), 2U);
    EXPECT_EQ(harness.env.createRequests().size(), 1U) << "one creation in the second cycle";
    const auto queries = harness.searchQueries();
    ASSERT_FALSE(queries.empty());
    EXPECT_EQ(queries.front(), rangeAfter(150));
}

TEST(ContentCycleOnClientAdapter, SlicedExpiryAdvancesNothing)
{
    CycleOnAdapter harness;
    harness.config.fullSlices = 2;
    // Slice 0 reads its three pages and the empty fourth one. Slice 1's second page finds the PIT expired, but only
    // once slice 0 is done: one slice finished, the other failed with PitExpired.
    auto sliceZeroSearches = std::make_shared<std::atomic<int>>(0);
    harness.env.pits->intercept(
        [pits = harness.env.pits.get(), sliceZeroSearches](const PitRequestView& view, Rule&)
        {
            if (view.call != PitCall::Search || !view.body.contains("slice"))
            {
                return false;
            }
            const auto sliceId = view.body.at("slice").at("id").get<int>();
            if (sliceId == 0)
            {
                ++*sliceZeroSearches;
                return false;
            }
            if (view.body.contains("search_after"))
            {
                EXPECT_TRUE(waitUntil([&] { return sliceZeroSearches->load() >= 4; }, 5s)) << "slice 0 never finished";
                std::this_thread::sleep_for(200ms);
                pits->expireAll();
            }
            return false;
        });
    ASSERT_NO_FATAL_FAILURE(harness.start());

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedTransport) << outcome.detail;
    EXPECT_NE(outcome.detail.find("pit_expired"), std::string::npos) << outcome.detail;
    EXPECT_TRUE(harness.tokens->writes.empty()) << "a sliced download advances no token";
    EXPECT_EQ(outcome.token, "");
    EXPECT_TRUE(harness.sink->commits.empty());
    ASSERT_TRUE(harness.env.waitDeletes(1)) << "the expired PIT is still deleted (the 404 counts as confirmed)";
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(harness.env.pits->created(), 1U);
    EXPECT_EQ(harness.env.pits->requests(PitCall::Delete), 1U);
}
