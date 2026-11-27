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
#include "fakes/slicedData.hpp"
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
using fakes::SlicedData;
using fakes::TurnGate;

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
    // One below the page's token: a document sharing it may still be on the next page.
    EXPECT_EQ(durable, (std::vector<std::string> {"8"}));
}

TEST(PitPaginatorTest, APageOfConsumerDocumentsOnlyIsNotADurablePoint)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    {
        if (call == 0)
        {
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-5", 5)}));
        }
        if (call == 1)
        {
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
                {nlohmann::json {{"_id", "consumer:1"}, {"_index", ".consumers"}, {"_source", {{"offset", 6}}}}}));
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

    // The second page reached no sink, so nothing acknowledged its token: the only resume point is the
    // first page's (one below its token).
    EXPECT_EQ(durable, (std::vector<std::string> {"4"}));
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
    // only happen if the workers really share the one instance concurrently rather than
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

    // A per-slice token is not a resume point: whatever is reported is below every slice still
    // running, and only moves forward (which values, if any, depends on the order the slices end in).
    for (std::size_t i = 1; i < durable.size(); ++i)
    {
        EXPECT_TRUE(PitPaginator::tokenLess(durable[i - 1], durable[i])) << durable[i - 1] << " then " << durable[i];
    }
    for (const auto& token : durable)
    {
        EXPECT_TRUE(PitPaginator::tokenLess(token, "3")) << token;
    }

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

// A page the indexer throttled is asked again on the same cursor with half the hits; once it arrives the
// fetch goes on, nothing lost or repeated, and the retry count starts over for the next page.
TEST(PitPaginatorTest, ThrottledPageIsAskedAgainOnTheSameCursor)
{
    WeightedData data;
    data.weights.assign(100, 1);
    data.cap = 1000;

    FakeIndexerQueryPort port;
    // The third and fourth searches (the page after document 40) and three of a later page are throttled.
    port.state()->onSearch = [&data](const FakeIndexerQueryPort::SearchCall& call,
                                     std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 2 || ordinal == 3 || (ordinal >= 7 && ordinal <= 9))
        {
            throw content_manager::ThrottledError {"PIT search failed: unavailable: page deadline expired, last cause: "
                                                   "throttled: HTTP 429"};
        }
        return data.answer(call);
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(20), sink, "topic");

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 100U);
    std::vector<std::uint64_t> expected(100);
    std::iota(expected.begin(), expected.end(), 1);
    EXPECT_EQ(deliveredOffsets(sink), expected) << "every document once, in order";

    const auto& searches = port.state()->searches;
    ASSERT_GE(searches.size(), 11U);
    // 1-20, 21-40, then 41-60 throttled twice: 20 (429), 10 (429), 5 arrives.
    EXPECT_EQ(searches[2].size, 20U);
    EXPECT_EQ(searches[3].size, 10U);
    EXPECT_EQ(searches[4].size, 5U);
    EXPECT_EQ(*searches[2].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    EXPECT_EQ(*searches[3].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    EXPECT_EQ(*searches[4].searchAfter, nlohmann::json::array({40, "CVE-40"}));
    // Three more in a row on a later page are still within the limit, because the count started over.
    EXPECT_EQ(*searches[8].searchAfter, *searches[7].searchAfter);
    EXPECT_EQ(*searches[9].searchAfter, *searches[7].searchAfter);
    EXPECT_EQ(*searches[10].searchAfter, *searches[7].searchAfter);
}

// A page throttled more than MAX_THROTTLED_RETRIES times in a row fails the fetch with the indexer's reason,
// with the documents before it delivered; at one hit the page is asked again at the same size.
TEST(PitPaginatorTest, PageThrottledPastTheLimitFailsTheFetch)
{
    WeightedData data;
    data.weights.assign(10, 1);
    data.cap = 1000;

    FakeIndexerQueryPort port;
    port.state()->onSearch = [&data](const FakeIndexerQueryPort::SearchCall& call,
                                     std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal >= 1)
        {
            throw content_manager::ThrottledError {"PIT search failed: retry_exhausted: HTTP 429"};
        }
        return data.answer(call);
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(2), sink, "topic");

    EXPECT_EQ(outcome.error, "PIT search failed: retry_exhausted: HTTP 429");
    EXPECT_EQ(deliveredOffsets(sink), (std::vector<std::uint64_t> {1, 2}));
    const auto& searches = port.state()->searches;
    // One page that arrived, then the throttled one: asked once and MAX_THROTTLED_RETRIES times more.
    ASSERT_EQ(searches.size(), 2U + PitPaginator::MAX_THROTTLED_RETRIES);
    EXPECT_EQ(searches[1].size, 2U);
    EXPECT_EQ(searches[2].size, 1U);
    EXPECT_EQ(searches.back().size, 1U);
    EXPECT_EQ(*searches.back().searchAfter, nlohmann::json::array({2, "CVE-2"}));
}

namespace
{
    using content_manager::PageStatus;

    /**
     * @brief A sliced fetch whose searches and sink answers follow a script.
     *
     * Searches go through the TurnGate in `order`; the sink answers its n-th page with `script[n]`
     * (`Accepted` past the end) and gives the turn on. `atTurn`, when set, runs inside the search that
     * has that turn, before its answer: it may wait for the other slice, or advance the gate and throw.
     */
    struct SlicedRun
    {
        SlicedData data;
        TurnGate gate;
        FakeIndexerQueryPort port;
        RecordingSink sink;
        std::vector<PageStatus> script;
        std::function<void(std::size_t turn)> atTurn;
        std::vector<std::string> durable;

        explicit SlicedRun(std::vector<std::size_t> order)
            : gate {std::move(order)}
        {
            port.state()->onSearch = [this](const FakeIndexerQueryPort::SearchCall& call, std::size_t) -> nlohmann::json
            {
                if (!call.slice.has_value())
                {
                    return data.answer(call);
                }
                const auto turn = gate.enter(call.slice->at("id").get<std::size_t>());
                if (atTurn)
                {
                    atTurn(turn);
                }
                auto answer = data.answer(call);
                if (answer.at("hits").empty())
                {
                    gate.advance(); // No page will reach the sink for this turn.
                }
                return answer;
            };
            sink.onPage = [this](const content_manager::ContentPage&, std::size_t call)
            {
                const auto status = call < script.size() ? script[call] : PageStatus::Accepted;
                gate.advance();
                return content_manager::PageAck {status, status == PageStatus::Reject ? "boom" : ""};
            };
        }

        FetchOutcome run(FetchSpec spec)
        {
            std::atomic<bool> stop {false};
            PitSession session {port, pitConfig()};
            PitPaginator paginator {port, session, stop};
            return paginator.run(spec, sink, "topic", [this](const std::string& token) { durable.push_back(token); });
        }

        /// What a cycle resuming from the last reported point fetches: unsliced, offsets over it.
        FetchOutcome resume()
        {
            auto spec = specOf(2);
            spec.query = nlohmann::json {{"range", {{"offset", {{"gt", std::stoull(durable.back())}}}}}};
            return run(spec);
        }
    };
} // namespace

// The resume point of a sliced fetch is one below the lowest token among its slices, taken when the
// sink answers Durable (here once in a while, as a real sink does): never the token of the slice ahead,
// and never twice the same.
TEST(PitPaginatorTest, SlicedDurableStoresTheLowWatermark)
{
    SlicedRun fetch {{0, 0, 1, 0, 1}};
    fetch.data.add(0, {10, 20, 30, 40, 50, 60});
    fetch.data.add(1, {11, 21, 31, 41});
    fetch.script = {
        PageStatus::Accepted, PageStatus::Accepted, PageStatus::Durable, PageStatus::Durable, PageStatus::Durable};

    const auto outcome = fetch.run(specOf(2, 2));

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 10U);
    EXPECT_EQ(outcome.highestPageToken, "60");
    // Slice 0 at 40 and slice 1 at 21: below 21. Slice 0 at 60, slice 1 still at 21: nothing new.
    // Slice 1 at 41: below 41.
    EXPECT_EQ(fetch.durable, (std::vector<std::string> {"20", "40"}));
}

// No resume point while a slice has not delivered a page: nothing is known about what it holds.
TEST(PitPaginatorTest, SlicedWatermarkWaitsForEverySlice)
{
    SlicedRun fetch {{0, 0, 1}};
    fetch.data.add(0, {10, 20, 30, 40});
    fetch.data.add(1, {11, 21, 31, 41});
    fetch.script = {PageStatus::Durable, PageStatus::Durable};

    const auto outcome = fetch.run(specOf(2, 2));

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 8U);
    EXPECT_TRUE(fetch.durable.empty());
}

// A slice that read its last page no longer holds the mark back: it follows the slice still running.
TEST(PitPaginatorTest, SlicedWatermarkIgnoresAFinishedSlice)
{
    SlicedRun fetch {{1, 0, 0, 1, 1}};
    fetch.data.add(0, {10, 20});
    fetch.data.add(1, {11, 21, 31, 41, 51, 61});
    fetch.script = {PageStatus::Accepted, PageStatus::Accepted, PageStatus::Durable, PageStatus::Durable};

    const auto outcome = fetch.run(specOf(2, 2));

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    // Slice 0 ends, in its own thread, right after its empty search: if slice 1's next page beats that
    // by a hair the first point is below slice 0's last token (19) instead of slice 1's (40). Both are
    // safe; what must hold is that the mark ends up past everything slice 0 ever had.
    ASSERT_FALSE(fetch.durable.empty());
    EXPECT_EQ(fetch.durable.back(), "60");
    EXPECT_TRUE(fetch.durable.front() == "40" || fetch.durable.front() == "19") << fetch.durable.front();
    for (std::size_t i = 1; i < fetch.durable.size(); ++i)
    {
        EXPECT_TRUE(PitPaginator::tokenLess(fetch.durable[i - 1], fetch.durable[i]));
    }
}

// A slice that failed is not a finished one: what it had left was never delivered, so its last token
// keeps holding the mark back, also for a page its sibling delivers after the failure.
TEST(PitPaginatorTest, SlicedFailureKeepsTheWatermark)
{
    SlicedRun fetch {{0, 1, 0, 1}};
    fetch.data.add(0, {10, 20, 30, 40});
    fetch.data.add(1, {11, 21, 31, 41});
    fetch.script = {PageStatus::Accepted, PageStatus::Durable, PageStatus::Durable};
    fetch.atTurn = [&fetch](std::size_t turn)
    {
        if (turn == 2)
        {
            fetch.gate.waitEntered(1, 2); // Slice 1 is inside its second search: its page will arrive.
            fetch.gate.advance();
            throw std::runtime_error("indexer exploded");
        }
    };

    const auto outcome = fetch.run(specOf(2, 2));

    EXPECT_NE(outcome.error.find("indexer exploded"), std::string::npos) << outcome.error;
    ASSERT_EQ(fetch.sink.pages.size(), 3U) << "slice 1's second page reached the sink after the failure";
    EXPECT_EQ(fetch.durable, (std::vector<std::string> {"19"}));
}

// After a rejection the session is dead: the sibling's page in flight does not reach the sink (which
// may have dropped what it had staged and would vouch for it as durable), nothing is reported, and the
// fetch fails with the reason of the rejection.
TEST(PitPaginatorTest, RejectedSessionEmitsNoWatermark)
{
    SlicedRun fetch {{0, 1, 0, 1}};
    fetch.data.add(0, {10, 20, 30, 40});
    fetch.data.add(1, {11, 21, 31, 41});
    fetch.script = {PageStatus::Accepted, PageStatus::Accepted, PageStatus::Reject, PageStatus::Durable};
    fetch.atTurn = [&fetch](std::size_t turn)
    {
        if (turn == 2)
        {
            fetch.gate.waitEntered(1, 2);
        }
    };

    const auto outcome = fetch.run(specOf(2, 2));

    EXPECT_TRUE(outcome.sinkRejected);
    EXPECT_EQ(outcome.error, "boom");
    EXPECT_EQ(fetch.sink.pages.size(), 3U) << "the sink was called again after it rejected a page";
    EXPECT_TRUE(fetch.durable.empty());
    EXPECT_EQ(outcome.documentsDelivered, 6U) << "the page that never reached the sink is not counted";
}

// Offsets may repeat, across slices and across the pages of one slice, and the next cycle asks for
// offsets strictly over the stored one: the mark is one below the lowest token, so the document that
// shares it and was still on the failed slice's next page is fetched again, not lost.
TEST(PitPaginatorTest, WatermarkIsBelowTheLowestTokenForTies)
{
    SlicedRun fetch {{0, 1, 0}};
    fetch.data.add(0, {10, 20, 20, 30}); // Pages (10, 20) and (20, 30).
    fetch.data.add(1, {20, 25, 40, 50});
    fetch.script = {PageStatus::Accepted, PageStatus::Durable};
    fetch.atTurn = [&fetch](std::size_t turn)
    {
        if (turn == 2)
        {
            fetch.gate.advance();
            throw std::runtime_error("indexer exploded");
        }
    };

    const auto failed = fetch.run(specOf(2, 2));

    EXPECT_FALSE(failed.error.empty());
    ASSERT_EQ(fetch.durable, (std::vector<std::string> {"19"}));
    EXPECT_NE(fakes::deliveredIds(fetch.sink), fetch.data.ids()) << "the failed fetch left documents behind";

    fetch.atTurn = nullptr;
    const auto resumed = fetch.resume();

    EXPECT_TRUE(resumed.error.empty()) << resumed.error;
    EXPECT_EQ(fakes::deliveredIds(fetch.sink), fetch.data.ids()) << "a document sharing the token was lost";
}

// The same on an unsliced fetch: the resume point of a durable page is one below its token.
TEST(PitPaginatorTest, UnslicedResumePointIsBelowThePageTokenForTies)
{
    SlicedRun fetch {{}};
    fetch.data.add(0, {10, 20, 20, 30});
    fetch.script = {PageStatus::Durable};
    auto answer = fetch.port.state()->onSearch;
    fetch.port.state()->onSearch =
        [answer, failing = std::make_shared<std::atomic<bool>>(true)](const FakeIndexerQueryPort::SearchCall& call,
                                                                      std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 1 && failing->exchange(false))
        {
            throw std::runtime_error("indexer exploded");
        }
        return answer(call, ordinal);
    };

    const auto failed = fetch.run(specOf(2));

    EXPECT_FALSE(failed.error.empty());
    ASSERT_EQ(fetch.durable, (std::vector<std::string> {"19"}));

    const auto resumed = fetch.resume();

    EXPECT_TRUE(resumed.error.empty()) << resumed.error;
    EXPECT_EQ(fakes::deliveredIds(fetch.sink), fetch.data.ids()) << "a document sharing the token was lost";
}

// Pages without a token give no resume point, sliced or not.
TEST(PitPaginatorTest, SlicedFetchWithoutTokensReportsNoResumePoint)
{
    SlicedRun fetch {{}};
    fetch.data.add(0, {10, 20, 30, 40});
    fetch.data.add(1, {11, 21, 31, 41});
    fetch.script.assign(8, PageStatus::Durable);

    auto spec = specOf(2, 2);
    spec.pageTokenPointer.clear();
    const auto outcome = fetch.run(spec);

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 8U);
    EXPECT_TRUE(fetch.durable.empty());
}

// Documents without the cursor sort first (the cursor sort asks for it), so a slice delivers them before any page
// with a token. Their pages carry no token and so hold every resume point back: when one is finally stored, the
// documents a resumed range fetch can never return are already delivered, and durable with the page that stored it.
TEST(PitPaginatorTest, NoResumePointBeforeTheCursorlessDocumentsAreDelivered)
{
    const auto cursorless = [](const std::string& id)
    {
        return nlohmann::json {{"_id", id},
                               {"_index", "data-index"},
                               {"_source", {{"type", "CVE"}}},
                               {"sort", nlohmann::json::array({0, id})}};
    };

    FakeIndexerQueryPort port;
    port.state()->onSearch = [&](const FakeIndexerQueryPort::SearchCall& call, std::size_t ordinal) -> nlohmann::json
    {
        const auto slice = call.slice->at("id").get<std::size_t>();
        if (slice == 0)
        {
            // Only documents with a cursor.
            return ordinal == 0 ? FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
                                      {FakeIndexerQueryPort::hit("a-10", 10), FakeIndexerQueryPort::hit("a-20", 20)}))
                                : FakeIndexerQueryPort::emptyHits();
        }
        // Two documents without a cursor first, then two with one.
        if (ordinal == 0)
        {
            // Let slice 0 get ahead: its token alone must not become a resume point.
            std::this_thread::sleep_for(std::chrono::milliseconds {100});
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({cursorless("nc-1"), cursorless("nc-2")}));
        }
        return ordinal == 1 ? FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
                                  {FakeIndexerQueryPort::hit("b-11", 11), FakeIndexerQueryPort::hit("b-21", 21)}))
                            : FakeIndexerQueryPort::emptyHits();
    };

    std::atomic<bool> stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;
    sink.onPage = [](const content_manager::ContentPage&, std::size_t)
    {
        return content_manager::PageAck {PageStatus::Durable, {}};
    };

    std::vector<std::string> resumePoints;
    std::vector<std::set<std::string>> deliveredAtResumePoint;
    const auto outcome = paginator.run(specOf(2, 2),
                                       sink,
                                       "topic",
                                       [&](const std::string& token)
                                       {
                                           resumePoints.push_back(token);
                                           deliveredAtResumePoint.push_back(fakes::deliveredIds(sink));
                                       });

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    EXPECT_EQ(outcome.documentsDelivered, 6U);
    ASSERT_FALSE(resumePoints.empty()) << "slice 1 reaches a token after its cursorless documents";
    for (const auto& delivered : deliveredAtResumePoint)
    {
        EXPECT_EQ(delivered.count("nc-1"), 1U);
        EXPECT_EQ(delivered.count("nc-2"), 1U);
    }
}

// A throttled page is not asked again when the retry could not end inside the PIT's lease: only a
// search that succeeds renews it, so the retry would end as an expired PIT instead of the throttling.
TEST(PitPaginatorTest, ThrottledPageIsNotRetriedPastThePitLease)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const FakeIndexerQueryPort::SearchCall&, std::size_t) -> nlohmann::json
    {
        // A read that spent most of the lease on 429s.
        std::this_thread::sleep_for(std::chrono::milliseconds {600});
        throw content_manager::ThrottledError {"PIT search failed: unavailable: page deadline expired, HTTP 429"};
    };

    auto config = pitConfig();
    config.keepAlive = "1s";
    std::atomic<bool> stop {false};
    PitSession session {port, config};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(8), sink, "topic");

    EXPECT_NE(outcome.error.find("HTTP 429"), std::string::npos) << outcome.error;
    EXPECT_EQ(port.state()->searches.size(), 1U) << "600 ms spent and 600 ms more to come do not fit in 1 s";
}

// Every read is bound by the end of the PIT's lease, counted from the PIT's opening and then from the last page that
// arrived. The retry of a throttled page gets the same bound as the read that failed: a retry that turns out longer
// than the failed read cannot run past the lease.
TEST(PitPaginatorTest, ThrottledRetryDeadlineIsCappedByTheLease)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const FakeIndexerQueryPort::SearchCall&, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 0)
        {
            // A quick failure: the prediction (a retry as long as this read) lets the retry go.
            throw content_manager::ThrottledError {"PIT search failed: unavailable: HTTP 429"};
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    auto config = pitConfig();
    config.keepAlive = "2s";
    std::atomic<bool> stop {false};
    PitSession session {port, config};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(8), sink, "topic");

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    const auto bounds = port.state()->searchBounds;
    ASSERT_EQ(bounds.size(), 2U);
    const auto expiry = session.leaseRenewed() + std::chrono::seconds {2};
    EXPECT_EQ(bounds[0], expiry) << "the lease is counted from the PIT's opening";
    EXPECT_EQ(bounds[1], expiry) << "a failed read renews nothing: the retry keeps the same bound";
}

// A page that arrives renews the lease, so the next read's bound moves on.
TEST(PitPaginatorTest, LeaseBoundMovesWithEachPageThatArrives)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const FakeIndexerQueryPort::SearchCall&, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds {50});
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1)}));
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    auto config = pitConfig();
    config.keepAlive = "2s";
    std::atomic<bool> stop {false};
    PitSession session {port, config};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(1), sink, "topic");

    EXPECT_TRUE(outcome.error.empty()) << outcome.error;
    const auto bounds = port.state()->searchBounds;
    ASSERT_EQ(bounds.size(), 2U);
    EXPECT_EQ(bounds[0], session.leaseRenewed() + std::chrono::seconds {2});
    EXPECT_GE(bounds[1], bounds[0] + std::chrono::milliseconds {50});
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
