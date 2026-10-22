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

// CA-23 against a real OpenSearch (D52): the bodies of an expired PIT, the delete at the end and slices sharing a PIT.

#include <algorithm>
#include <iostream>
#include <set>
#include <thread>

#include "openSearchSupport.hpp"

using namespace indexer_client;
using namespace indexer_client::opensearch;
using namespace std::chrono_literals;

namespace
{
    // CursorQuery's default query ({}) is refused by OpenSearch 3.6 (400 "query malformed, empty clause found"): the
    // cursors name match_all explicitly.
    const nlohmann::json MATCH_ALL = {{"match_all", nlohmann::json::object()}};

    /// Indexes `count` documents (raw bulk, refresh=true) with ids d0000…
    void seed(const std::string& index, int count)
    {
        std::string body;
        for (int i = 0; i < count; ++i)
        {
            char id[16];
            std::snprintf(id, sizeof(id), "d%04d", i);
            body += nlohmann::json {{"index", {{"_index", index}, {"_id", id}}}}.dump() + "\n";
            body += nlohmann::json {{"n", i}}.dump() + "\n";
        }
        const auto response = raw("POST", "/_bulk?refresh=true", body, "application/x-ndjson");
        ASSERT_EQ(response.status, 200) << response.body.substr(0, 512);
        ASSERT_FALSE(nlohmann::json::parse(response.body).at("errors").get<bool>());
    }

    /// The PIT ids present now and absent from `before`.
    std::vector<std::string> newPits(const std::vector<std::string>& before)
    {
        std::vector<std::string> fresh;
        for (const auto& id : listPits())
        {
            if (std::find(before.begin(), before.end(), id) == before.end())
            {
                fresh.push_back(id);
            }
        }
        return fresh;
    }

    /// The raw body of a search on `pitId` (what the library classified).
    RawResponse rawPitSearch(const std::string& pitId)
    {
        const nlohmann::json body = {{"size", 0}, {"pit", {{"id", pitId}}}};
        return raw("POST", "/_search?allow_partial_search_results=false", body.dump());
    }

    PitMetrics pitMetrics(const RuntimeRef& ref)
    {
        return ref.snapshot().pit;
    }
} // namespace

class OpenSearchPit : public OpenSearchTest
{
};

TEST_F(OpenSearchPit, ExpiredPitReturnsPitExpired)
{
    ASSERT_NO_FATAL_FAILURE(seed(m_index, 10));
    auto client = makeClient("os-pit-expired", {quickBucket("unused")});
    ASSERT_NE(client, nullptr);
    auto query = client->query();
    const nlohmann::json search = {{"size", 1}, {"query", {{"match_all", nlohmann::json::object()}}}};

    // (a) keep_alive = 1 s and nothing renews it: the cluster's reaper (search.keep_alive_interval) frees it.
    {
        const auto before = listPits();
        PitOptions options;
        options.keepAlive = Duration {1000};
        auto pit = query->pit({m_index}, options, QueryOptions {}, after(indexer_client::testing::scaled(30s)));
        ASSERT_TRUE(pit.ok()) << toString(pit.cause) << ": " << pit.reason;
        const auto ids = newPits(before);
        ASSERT_EQ(ids.size(), 1U);
        std::this_thread::sleep_for(indexer_client::testing::scaled(4s));
        const auto result = pit.value.search(search, after(indexer_client::testing::scaled(30s)));
        const auto body = rawPitSearch(ids[0]);
        std::cout << "E6B-BODY pit.expired.a library=" << toString(result.cause) << " http=" << result.httpStatus
                  << " reason=" << result.reason << "\n";
        std::cout << "E6B-BODY pit.expired.a raw http=" << body.status << " body=" << body.body << "\n";
        EXPECT_EQ(result.cause, Cause::PitExpired) << result.reason;
        // Every later call answers PitExpired without a request.
        EXPECT_EQ(pit.value.search(search, after(indexer_client::testing::scaled(5s))).cause, Cause::PitExpired);
    }

    // (b) a PIT deleted out of band, then a search.
    {
        const auto before = listPits();
        auto pit = query->pit({m_index}, PitOptions {}, QueryOptions {}, after(indexer_client::testing::scaled(30s)));
        ASSERT_TRUE(pit.ok()) << toString(pit.cause) << ": " << pit.reason;
        const auto ids = newPits(before);
        ASSERT_EQ(ids.size(), 1U);
        const auto alive = pit.value.search(search, after(indexer_client::testing::scaled(30s)));
        ASSERT_TRUE(alive.ok()) << toString(alive.cause) << ": " << alive.reason;

        const auto deleted = raw(
            "DELETE", "/_search/point_in_time", nlohmann::json {{"pit_id", nlohmann::json::array({ids[0]})}}.dump());
        std::cout << "E6B-BODY pit.expired.b delete http=" << deleted.status << " body=" << deleted.body << "\n";
        ASSERT_EQ(deleted.status, 200) << deleted.body;

        const auto result = pit.value.search(search, after(indexer_client::testing::scaled(30s)));
        const auto body = rawPitSearch(ids[0]);
        std::cout << "E6B-BODY pit.expired.b library=" << toString(result.cause) << " http=" << result.httpStatus
                  << " reason=" << result.reason << "\n";
        std::cout << "E6B-BODY pit.expired.b raw http=" << body.status << " body=" << body.body << "\n";
        EXPECT_EQ(result.cause, Cause::PitExpired) << result.reason;
    }
}

TEST_F(OpenSearchPit, PitDeletedAtEnd)
{
    ASSERT_NO_FATAL_FAILURE(seed(m_index, 25));
    auto client = makeClient("os-pit-delete", {quickBucket("unused")});
    ASSERT_NE(client, nullptr);
    auto query = client->query();
    const auto start = pitMetrics(m_ref);
    const auto before = listPits();
    std::vector<std::string> ids;
    std::size_t hits = 0;
    {
        auto pit = query->pit({m_index}, PitOptions {}, QueryOptions {}, after(indexer_client::testing::scaled(30s)));
        ASSERT_TRUE(pit.ok()) << toString(pit.cause) << ": " << pit.reason;
        ids = newPits(before);
        CursorQuery cursorQuery;
        cursorQuery.query = MATCH_ALL;
        cursorQuery.pageSize = 10;
        auto cursor = pit.value.cursor(cursorQuery);
        std::optional<std::uint64_t> total;
        while (!cursor.exhausted())
        {
            auto page = cursor.next(after(indexer_client::testing::scaled(30s)));
            ASSERT_TRUE(page.ok()) << toString(page.cause) << ": " << page.reason;
            if (page.value.total)
            {
                total = page.value.total;
            }
            hits += page.value.hits.size();
        }
        EXPECT_EQ(total.value_or(0), 25U);
        EXPECT_EQ(pitMetrics(m_ref).open, 1U);
    }
    ASSERT_EQ(ids.size(), 1U);
    EXPECT_EQ(hits, 25U);

    // The last handle is gone: the library deletes the PIT and the cluster confirms it.
    const auto end = after(indexer_client::testing::scaled(30s));
    while (pitMetrics(m_ref).deletesConfirmed == start.deletesConfirmed && std::chrono::steady_clock::now() < end)
    {
        std::this_thread::sleep_for(20ms);
    }
    const auto done = pitMetrics(m_ref);
    std::cout << MEASURE << "pit.delete created=" << (done.created - start.created)
              << " deletes_confirmed=" << (done.deletesConfirmed - start.deletesConfirmed)
              << " deletes_expired=" << (done.deletesExpired - start.deletesExpired) << " open=" << done.open << "\n";
    EXPECT_EQ(done.created - start.created, 1U);
    EXPECT_EQ(done.deletesConfirmed - start.deletesConfirmed, 1U);
    EXPECT_EQ(done.deletesExpired - start.deletesExpired, 0U);
    EXPECT_EQ(done.open, 0U);
    const auto remaining = listPits();
    EXPECT_EQ(std::count(remaining.begin(), remaining.end(), ids[0]), 0) << "the cluster still holds the PIT";
}

TEST_F(OpenSearchPit, SlicesShareId)
{
    constexpr int DOCS = 40;
    ASSERT_NO_FATAL_FAILURE(seed(m_index, DOCS));
    auto client = makeClient("os-pit-slices", {quickBucket("unused")});
    ASSERT_NE(client, nullptr);
    auto query = client->query();
    const auto start = pitMetrics(m_ref);
    const auto before = listPits();

    auto pit = query->pit({m_index}, PitOptions {}, QueryOptions {}, after(indexer_client::testing::scaled(30s)));
    ASSERT_TRUE(pit.ok()) << toString(pit.cause) << ": " << pit.reason;
    CursorQuery cursorQuery;
    cursorQuery.query = MATCH_ALL;
    cursorQuery.pageSize = 7;
    auto slice0 = pit.value.cursor(cursorQuery, Slice {0, 2});
    auto slice1 = pit.value.cursor(cursorQuery, Slice {1, 2});

    std::set<std::string> ids0;
    std::set<std::string> ids1;
    std::size_t total0 = 0;
    std::size_t total1 = 0;
    // Interleaved pages: both slices are open on the cluster at the same time.
    while (!slice0.exhausted() || !slice1.exhausted())
    {
        for (auto [cursor, ids, count] : {std::tuple {&slice0, &ids0, &total0}, std::tuple {&slice1, &ids1, &total1}})
        {
            if (cursor->exhausted())
            {
                continue;
            }
            auto page = cursor->next(after(indexer_client::testing::scaled(30s)));
            ASSERT_TRUE(page.ok()) << toString(page.cause) << ": " << page.reason;
            for (const auto& hit : page.value.hits)
            {
                ids->insert(hit.at("_id").get<std::string>());
                ++*count;
            }
        }
    }
    const auto open = newPits(before);
    const auto middle = pitMetrics(m_ref);
    std::cout << MEASURE << "pit.slices slice0=" << total0 << " slice1=" << total1
              << " cluster_pits_opened=" << open.size() << " created=" << (middle.created - start.created) << "\n";
    EXPECT_EQ(open.size(), 1U) << "two slices of one Pit must address a single PIT id on the cluster";
    EXPECT_EQ(middle.created - start.created, 1U);
    EXPECT_GT(total0, 0U);
    EXPECT_GT(total1, 0U);
    EXPECT_EQ(total0 + total1, static_cast<std::size_t>(DOCS));
    std::vector<std::string> both;
    std::set_intersection(ids0.begin(), ids0.end(), ids1.begin(), ids1.end(), std::back_inserter(both));
    EXPECT_TRUE(both.empty()) << "the slices overlap";
    EXPECT_EQ(ids0.size() + ids1.size(), static_cast<std::size_t>(DOCS));
}
