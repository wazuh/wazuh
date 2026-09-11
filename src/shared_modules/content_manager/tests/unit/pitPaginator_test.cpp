/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/pitPaginator.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
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

    ConditionSync stop {false};
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

    ConditionSync stop {false};
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

    ConditionSync stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};

    RecordingSink sink;
    sink.pageStatus = content_manager::PageStatus::Durable;

    std::vector<std::string> durable;
    const auto outcome =
        paginator.run(specOf(10), sink, "topic", [&durable](const std::string& token) { durable.push_back(token); });

    EXPECT_EQ(outcome.durableToken, "9");
    EXPECT_EQ(durable, (std::vector<std::string> {"9"}));
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

    ConditionSync stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink; // defaults to Accepted

    const auto outcome = paginator.run(specOf(10), sink, "topic");

    // Buffered is not durable: resuming from here after a crash would skip whatever the sink still
    // held in memory.
    EXPECT_TRUE(outcome.durableToken.empty());
    EXPECT_EQ(outcome.highestPageToken, "9");
}

TEST(PitPaginatorTest, RejectAbortsTheFetchImmediately)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) -> nlohmann::json
    { return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1)})); };

    ConditionSync stop {false};
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
    ConditionSync stop {true};

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
    { throw std::runtime_error("indexer exploded"); };

    ConditionSync stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(10), sink, "topic");

    EXPECT_EQ(outcome.error, "indexer exploded");
    EXPECT_EQ(outcome.documentsDelivered, 0U);
}

TEST(PitPaginatorTest, SlicedFetchGivesEachWorkerItsOwnPortAndReleasesThem)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const FakeIndexerQueryPort::SearchCall& call, std::size_t ordinal) -> nlohmann::json
    {
        EXPECT_TRUE(call.slice.has_value());
        if (ordinal > 0)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        const auto sliceId = call.slice->at("id").get<std::size_t>();
        return FakeIndexerQueryPort::hitsOf(
            nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-" + std::to_string(sliceId), sliceId + 1)}));
    };

    ConditionSync stop {false};
    PitSession session {port, pitConfig()};
    PitPaginator paginator {port, session, stop};
    RecordingSink sink;

    const auto outcome = paginator.run(specOf(10, 3), sink, "topic");

    EXPECT_EQ(outcome.documentsDelivered, 3U);
    EXPECT_EQ(port.state()->clones, 3U);
    // HTTP state is not shareable across threads, so each worker gets its own port — and none of
    // them outlives the fetch.
    EXPECT_EQ(port.state()->liveClones, 0U);

    // A per-slice token is not a resume point: the other slices may be far behind.
    EXPECT_TRUE(outcome.durableToken.empty());

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
    port.state()->onSearch = [](const auto& call, std::size_t ordinal) -> nlohmann::json
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

    ConditionSync stop {false};
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
