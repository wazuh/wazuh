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

#include "components/pitPaginator.hpp"
#include "contentSink.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <numeric>
#include <set>
#include <thread>

using fakes::FakeIndexerQueryPort;
using fakes::RecordingSink;

namespace
{

    PitSession::Config pitConfig()
    {
        PitSession::Config config;
        config.dataIndices = {"data-index"};
        config.consumerStatusIndex = ".consumers";
        config.consumerStatusId = "consumer:1";
        return config;
    }

    FetchSpec specOf(std::size_t pageSize, std::size_t slices = 1)
    {
        FetchSpec spec;
        spec.query = nlohmann::json {{"match_all", nlohmann::json::object()}};
        spec.sort = nlohmann::json::array({nlohmann::json {{"offset", "asc"}}});
        spec.pageTokenPointer = "/_source/offset";
        spec.pageSize = pageSize;
        spec.slices = slices;
        return spec;
    }

} // namespace

TEST(PitPaginatorTest, ThreadsSearchAfterAndStopsOnAShortPage)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call == 0)
        {
            return FakeIndexerQueryPort::hitsOf(
                nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1), FakeIndexerQueryPort::hit("CVE-2", 2)}));
        }
        // Short page: fewer hits than pageSize means the data is exhausted, so there is no extra
        // round trip to discover an empty page.
        return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-3", 3)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(2), sink, "topic");

    EXPECT_EQ(outcome.documentsDelivered, 3U);
    EXPECT_EQ(outcome.highestPageToken, "3");
    EXPECT_FALSE(outcome.interrupted);
    EXPECT_TRUE(outcome.error.empty());

    // Two data searches: the readiness probe was not run in this test.
    ASSERT_EQ(port.state()->searches.size(), 2U);
    EXPECT_FALSE(port.state()->searches[0].searchAfter.has_value());
    ASSERT_TRUE(port.state()->searches[1].searchAfter.has_value());
    EXPECT_EQ(*port.state()->searches[1].searchAfter, nlohmann::json::array({2, "CVE-2"}));
}

TEST(PitPaginatorTest, DropsConsumerDocumentsBeforeTheSinkSeesThem)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        return FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
            {FakeIndexerQueryPort::hit("CVE-1", 1),
             nlohmann::json {{"_id", "consumer:1"}, {"_index", ".consumers"}, {"_source", {{"status", "ready"}}}},
             FakeIndexerQueryPort::hit("CVE-2", 2)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(10), sink, "topic");

    // The hit-side drop is the second of two independent defences; the query-side must_not is the
    // first. They fail differently, which is why both exist.
    EXPECT_EQ(outcome.documentsDelivered, 2U);
    ASSERT_EQ(sink.pages.size(), 1U);
    for (const auto& hit : sink.pages.front())
    {
        EXPECT_NE(hit.at("_index"), ".consumers");
    }
}

TEST(PitPaginatorTest, DurableAckAdvancesTheResumePoint)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-9", 9)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};

    RecordingSink sink;
    sink.pageStatus = content_manager::PageStatus::Durable;

    std::vector<std::string> durable;
    const auto outcome =
        paginator.run(specOf(10), sink, "topic", [&durable](const std::string& token) { durable.push_back(token); });

    EXPECT_EQ(outcome.highestPageToken, "9");
    EXPECT_EQ(durable, (std::vector<std::string> {"9"}));
}

TEST(PitPaginatorTest, APageOfConsumerDocumentsOnlyIsNotADurablePoint)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call == 0)
        {
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1)}));
        }
        if (call == 1)
        {
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
                {nlohmann::json {{"_id", "consumer:1"}, {"_index", ".consumers"}, {"_source", {{"offset", 2}}}}}));
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};

    RecordingSink sink;
    sink.pageStatus = content_manager::PageStatus::Durable;

    std::vector<std::string> durable;
    paginator.run(specOf(1), sink, "topic", [&durable](const std::string& token) { durable.push_back(token); });

    // The second page reached no sink, so nothing acknowledged its token.
    EXPECT_EQ(durable, (std::vector<std::string> {"1"}));
}

TEST(PitPaginatorTest, AcceptedAckDoesNotAdvanceTheResumePoint)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-9", 9)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink; // defaults to Accepted

    std::vector<std::string> durable;
    const auto outcome =
        paginator.run(specOf(10), sink, "topic", [&durable](const std::string& token) { durable.push_back(token); });

    // Buffered is not durable: resuming from here after a crash would skip whatever the sink still
    // held in memory.
    EXPECT_TRUE(durable.empty());
    EXPECT_EQ(outcome.highestPageToken, "9");
}

TEST(PitPaginatorTest, RejectAbortsTheFetchImmediately)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) -> nlohmann::json
    {
        return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};

    RecordingSink sink;
    sink.pageStatus = content_manager::PageStatus::Reject;

    const auto outcome = paginator.run(specOf(1), sink, "topic");

    EXPECT_TRUE(outcome.sinkRejected);
    EXPECT_EQ(outcome.error, "recorded");
    EXPECT_EQ(sink.pages.size(), 1U);
    EXPECT_EQ(port.state()->searches.size(), 1U);
}

TEST(PitPaginatorTest, StopRequestEndsTheFetch)
{
    std::atomic<bool> stop {true};

    FakeIndexerQueryPort port;
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(10), sink, "topic");

    EXPECT_TRUE(outcome.interrupted);
    EXPECT_TRUE(port.state()->searches.empty());
}

TEST(PitPaginatorTest, TransportErrorIsReportedNotThrown)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) -> nlohmann::json
    {
        throw std::runtime_error("indexer exploded");
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(10), sink, "topic");

    EXPECT_EQ(outcome.error, "indexer exploded");
    EXPECT_EQ(outcome.documentsDelivered, 0U);
}

TEST(PitPaginatorTest, SlicedFetchRunsEverySliceOnTheOneIndexerAtOnce)
{
    FakeIndexerQueryPort port;

    // Each slice's first search waits (bounded) until all three are in flight together, which can
    // only happen if the workers really share the one instance concurrently (D1) rather than
    // queueing on it or on copies of it.
    std::mutex gateMutex;
    std::condition_variable gate;
    std::size_t arrived = 0;
    port.state()->onSearch = [&](const FakeIndexerQueryPort::SearchCall& call, std::size_t ordinal) -> nlohmann::json
    {
        EXPECT_TRUE(call.slice.has_value());
        if (ordinal > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        {
            std::unique_lock<std::mutex> lock {gateMutex};
            ++arrived;
            gate.notify_all();
            gate.wait_for(lock, std::chrono::seconds {5}, [&arrived] { return arrived >= 3; });
        }
        const auto sliceId = call.slice->at("id").get<std::size_t>();
        return FakeIndexerQueryPort::hitsOf(
            nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-" + std::to_string(sliceId), sliceId + 1)}));
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;
    sink.pageStatus = content_manager::PageStatus::Durable;

    std::vector<std::string> durable;
    const auto outcome =
        paginator.run(specOf(10, 3), sink, "topic", [&durable](const std::string& token) { durable.push_back(token); });

    EXPECT_EQ(outcome.documentsDelivered, 3U);
    EXPECT_EQ(port.state()->maxConcurrentSearches, 3U);

    // A per-slice token is not a resume point: the other slices may be far behind.
    EXPECT_TRUE(durable.empty());

    std::set<std::size_t> sliceIds;
    for (const auto& call : port.state()->searches)
    {
        ASSERT_TRUE(call.slice.has_value());
        EXPECT_EQ(call.slice->at("max").get<std::size_t>(), 3U);
        sliceIds.insert(call.slice->at("id").get<std::size_t>());
    }
    EXPECT_EQ(sliceIds, (std::set<std::size_t> {0, 1, 2}));
}

TEST(PitPaginatorTest, SlicedFetchSerialisesSinkCalls)
{
    FakeIndexerQueryPort port;
    // Spelled out rather than `const auto&`: an `auto` parameter makes this a generic lambda, which
    // makes `call` a dependent type, which makes `.get<std::size_t>()` below need a `template`
    // disambiguator to parse at all. Naming the type is the fix that does not need explaining at
    // every call site.
    port.state()->onSearch = [](const FakeIndexerQueryPort::SearchCall& call, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        const auto sliceId = call.slice->at("id").get<std::size_t>();
        return FakeIndexerQueryPort::hitsOf(
            nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-" + std::to_string(sliceId), sliceId + 1)}));
    };

    /// Fails loudly if two slice workers are ever inside acceptPage at once — the guarantee that
    /// lets a sink be written as if it were single-threaded.
    class ExclusivitySink final : public content_manager::IContentSink
    {
    public:
        std::atomic<int> concurrent {0};
        std::atomic<bool> overlapped {false};
        std::atomic<int> calls {0};

        content_manager::SessionDecision beginSession(const content_manager::SessionInfo&) noexcept override
        {
            return content_manager::SessionDecision::Proceed;
        }

        content_manager::PageAck acceptPage(const content_manager::ContentPage&) noexcept override
        {
            if (concurrent.fetch_add(1) != 0)
            {
                overlapped = true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {2});
            ++calls;
            concurrent.fetch_sub(1);
            return content_manager::PageAck {};
        }

        content_manager::CommitResult commit(const content_manager::CommitInfo&) noexcept override
        {
            return content_manager::CommitResult {};
        }

        void abort(content_manager::AbortReason, const std::string&) noexcept override {}
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    ExclusivitySink sink;

    paginator.run(specOf(10, 4), sink, "topic");

    EXPECT_FALSE(sink.overlapped.load());
    EXPECT_EQ(sink.calls.load(), 4);
}

TEST(PitPaginatorTest, TokenOrderingIsNumericForIntegersAndLexicographicOtherwise)
{
    EXPECT_TRUE(PitPaginator::tokenLess("9", "10"));
    EXPECT_FALSE(PitPaginator::tokenLess("10", "9"));
    EXPECT_TRUE(PitPaginator::tokenLess("abc", "abd"));
    EXPECT_TRUE(PitPaginator::tokenLess("", "anything"));
    EXPECT_FALSE(PitPaginator::tokenLess("anything", ""));
}

namespace
{
    /**
     * @brief A data set behind the fake port whose responses are "too large" over a byte budget.
     *
     * Documents 1..N, sliced as OpenSearch does here ((k - 1) % max == id), each with a weight; a
     * search answers the next `size` documents of its slice after `search_after[0]`, or throws
     * ResponseTooLargeError when their weights add up to more than @p cap.
     */
    struct WeightedData
    {
        std::vector<std::size_t> weights; ///< weights[k - 1] is document k's.
        std::size_t cap {0};

        nlohmann::json answer(const FakeIndexerQueryPort::SearchCall& call) const
        {
            std::size_t sliceId = 0;
            std::size_t sliceMax = 1;
            if (call.slice.has_value())
            {
                sliceId = call.slice->at("id").get<std::size_t>();
                sliceMax = call.slice->at("max").get<std::size_t>();
            }
            std::uint64_t after = 0;
            if (call.searchAfter.has_value())
            {
                after = call.searchAfter->at(0).get<std::uint64_t>();
            }
            auto hits = nlohmann::json::array();
            std::size_t bytes = 0;
            for (std::uint64_t k = after + 1; k <= weights.size() && hits.size() < call.size; ++k)
            {
                if ((k - 1) % sliceMax != sliceId)
                {
                    continue;
                }
                bytes += weights[k - 1];
                hits.push_back(FakeIndexerQueryPort::hit("CVE-" + std::to_string(k), k));
            }
            if (bytes > cap)
            {
                throw content_manager::ResponseTooLargeError {"PIT search failed: item_permanent: response too large"};
            }
            return FakeIndexerQueryPort::hitsOf(std::move(hits));
        }
    };

    /// The `_source.offset` of every delivered document, in delivery order.
    std::vector<std::uint64_t> deliveredOffsets(const RecordingSink& sink)
    {
        std::vector<std::uint64_t> offsets;
        for (const auto& page : sink.pages)
        {
            for (const auto& hit : page)
            {
                offsets.push_back(hit.at("_source").at("offset").get<std::uint64_t>());
            }
        }
        return offsets;
    }
} // namespace

// A page over the size cap is asked again, same cursor, with half the hits until it fits; the pages
// that follow keep the reduced size, then grow back. Nothing is lost or repeated, and a page cut
// down for size is not mistaken for the end of the data.
TEST(PitPaginatorTest, TooLargePageIsHalvedOnTheSameCursorAndGrowsBack)
{
    WeightedData data;
    data.weights.assign(200, 1);
    for (std::size_t k = 41; k <= 50; ++k)
    {
        data.weights[k - 1] = 30; // Documents 41..50: at most 3 of them fit in a page.
    }
    data.cap = 100;

    FakeIndexerQueryPort port;
    port.state()->onSearch = [&data](const FakeIndexerQueryPort::SearchCall& call, std::size_t) -> nlohmann::json
    {
        return data.answer(call);
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(20), sink, "topic");

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 200U);
    EXPECT_EQ(outcome.highestPageToken, "200");
    std::vector<std::uint64_t> expected(200);
    std::iota(expected.begin(), expected.end(), 1);
    EXPECT_EQ(deliveredOffsets(sink), expected) << "every document once, in order";

    const auto& searches = port.state()->searches;
    std::vector<std::size_t> sizes;
    for (std::size_t i = 0; i < searches.size(); ++i)
    {
        sizes.push_back(searches[i].size);
    }
    // 1-20, 21-40, then 41-60 is too large: 10 (41-50, too large), 5 (41-45, too large), 2 (41-42) fits.
    // From there pages of 2 until four fit in a row (41-48), then 4, 8, 16 and 20 again.
    ASSERT_GE(sizes.size(), 14U);
    EXPECT_EQ((std::vector<std::size_t> {sizes.begin(), sizes.begin() + 14}),
              (std::vector<std::size_t> {20, 20, 20, 10, 5, 2, 2, 2, 2, 4, 4, 4, 4, 8}));
    // The retries repeat the failed page's cursor.
    EXPECT_EQ(*searches[2].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    EXPECT_EQ(*searches[3].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    EXPECT_EQ(*searches[4].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    EXPECT_EQ(*searches[5].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    // Past the heavy stretch the size is back to 20, and the last page (short against 20) ends the fetch.
    EXPECT_EQ(sizes.back(), 20U);
    EXPECT_EQ(std::count(sizes.begin(), sizes.end(), 1U), 0) << "never cut further than needed";
}

// Every slice halves on its own; their union is the whole data set, each document exactly once.
TEST(PitPaginatorTest, SlicedFetchHalvesPerSliceWithoutLosingDocuments)
{
    WeightedData data;
    data.weights.assign(301, 1);
    for (std::size_t k = 100; k <= 160; ++k)
    {
        data.weights[k - 1] = 7;
    }
    data.cap = 40;

    FakeIndexerQueryPort port;
    port.state()->onSearch = [&data](const FakeIndexerQueryPort::SearchCall& call, std::size_t) -> nlohmann::json
    {
        return data.answer(call);
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(32, 2), sink, "topic");

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 301U);
    auto offsets = deliveredOffsets(sink);
    std::sort(offsets.begin(), offsets.end());
    std::vector<std::uint64_t> expected(301);
    std::iota(expected.begin(), expected.end(), 1);
    EXPECT_EQ(offsets, expected);
}

// One document that does not fit on its own is the error it was before: the fetch fails, with the
// documents before it delivered and the size cut down to one hit first.
TEST(PitPaginatorTest, OneDocumentTooLargeOnItsOwnFailsTheFetch)
{
    WeightedData data;
    data.weights.assign(30, 1);
    data.weights[12 - 1] = 1000;
    data.cap = 100;

    FakeIndexerQueryPort port;
    port.state()->onSearch = [&data](const FakeIndexerQueryPort::SearchCall& call, std::size_t) -> nlohmann::json
    {
        return data.answer(call);
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(8), sink, "topic");

    EXPECT_NE(outcome.error.find("response too large"), std::string::npos) << outcome.error;
    EXPECT_EQ(deliveredOffsets(sink), (std::vector<std::uint64_t> {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}));
    const auto& searches = port.state()->searches;
    ASSERT_FALSE(searches.empty());
    EXPECT_EQ(searches.back().size, 1U);
    EXPECT_EQ(*searches.back().searchAfter, nlohmann::json::array({11, "CVE-11"}));
}

// Any other failure is not retried with a smaller page.
TEST(PitPaginatorTest, OtherFailuresAreNotHalved)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) -> nlohmann::json
    {
        throw std::runtime_error("PIT search failed: client_4xx: 400 parsing_exception");
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(16), sink, "topic");

    EXPECT_EQ(outcome.error, "PIT search failed: client_4xx: 400 parsing_exception");
    ASSERT_EQ(port.state()->searches.size(), 1U);
    EXPECT_EQ(port.state()->searches.front().size, 16U);
}
