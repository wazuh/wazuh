/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The page loop and page-request retry IndexerDownloader runs for every slice of a sliced initial
 * load and for a sequential download. Driven by fake searches, since the downloader itself only
 * runs against a live indexer.
 */

#include "indexerPageWalk.hpp"

#include "gtest/gtest.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr std::size_t PAGE_SIZE {2};

    // Immediate retries: the tests check the decisions, not the waiting.
    const IndexerPageWalk::RetryPolicy FAST_POLICY {5, std::chrono::milliseconds {1}, std::chrono::milliseconds {4}};

    /**
     * @brief One slice of a fake index: `docCount` documents, served PAGE_SIZE at a time. The page
     *        a request asks for is derived from its search_after, as the indexer does, so a restart
     *        from the beginning is visible as a second request without search_after.
     */
    class FakeSlice
    {
    public:
        FakeSlice(std::size_t sliceId, std::size_t docCount)
            : m_sliceId(sliceId)
            , m_docCount(docCount)
        {
        }

        /// The next `count` requests made from `searchAfterPage` (page index, -1 = first) throw.
        void failAt(long searchAfterPage, std::size_t count, std::string reason)
        {
            m_failPage = searchAfterPage;
            m_failuresLeft = count;
            m_failReason = std::move(reason);
        }

        nlohmann::json search(const std::optional<nlohmann::json>& searchAfter)
        {
            const long fromPage = searchAfter.has_value() ? searchAfter->at(0).get<long>() : -1;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_requests.push_back(fromPage);
                if (fromPage == m_failPage && m_failuresLeft > 0)
                {
                    --m_failuresLeft;
                    throw std::runtime_error(m_failReason);
                }
            }

            const std::size_t page = static_cast<std::size_t>(fromPage + 1);
            nlohmann::json hits = nlohmann::json::array();
            for (std::size_t i = page * PAGE_SIZE; i < std::min(m_docCount, (page + 1) * PAGE_SIZE); ++i)
            {
                hits.push_back({{"_id", "s" + std::to_string(m_sliceId) + "-doc" + std::to_string(i)},
                                {"_source", {{"offset", m_sliceId * 1000 + i + 1}}},
                                {"sort", nlohmann::json::array({page})}});
            }
            return nlohmann::json {{"hits", hits}};
        }

        std::vector<long> requests()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_requests;
        }

    private:
        std::size_t m_sliceId;
        std::size_t m_docCount;
        std::mutex m_mutex;
        std::vector<long> m_requests;
        long m_failPage {-2};
        std::size_t m_failuresLeft {0};
        std::string m_failReason;
    };

    /// Records every processed document id, across slices, and how many times it was seen.
    class FakeConsumer
    {
    public:
        void onPage(const nlohmann::json& hits)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& hit : hits)
            {
                ++m_seen[hit.at("_id").get<std::string>()];
            }
        }

        std::map<std::string, int> seen()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_seen;
        }

    private:
        std::mutex m_mutex;
        std::map<std::string, int> m_seen;
    };

    struct LogLine
    {
        int level;
        std::string text;
    };

    /// Captures the lines written through the module's global log function while alive.
    class ScopedLogCapture
    {
    public:
        ScopedLogCapture()
            : m_previous(Log::GLOBAL_LOG_FUNCTION)
        {
            Log::GLOBAL_LOG_FUNCTION =
                [this](
                    const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                char buffer[2048];
                va_list copy;
                va_copy(copy, args);
                vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_lines.push_back({level, buffer});
            };
        }

        ~ScopedLogCapture()
        {
            Log::GLOBAL_LOG_FUNCTION = m_previous;
        }

        ScopedLogCapture(const ScopedLogCapture&) = delete;
        ScopedLogCapture& operator=(const ScopedLogCapture&) = delete;

        std::vector<LogLine> lines()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lines;
        }

    private:
        std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
            m_previous;
        std::mutex m_mutex;
        std::vector<LogLine> m_lines;
    };

    IndexerPageWalk::WalkResult walkSlice(FakeSlice& slice,
                                          FakeConsumer& consumer,
                                          const std::string& label,
                                          const IndexerPageWalk::RetryPolicy& policy = FAST_POLICY,
                                          std::vector<std::chrono::milliseconds>* waits = nullptr,
                                          bool stopOnWait = false)
    {
        return IndexerPageWalk::walkPages(
            label,
            PAGE_SIZE,
            "",
            [&slice](const std::optional<nlohmann::json>& searchAfter) { return slice.search(searchAfter); },
            [&consumer](const nlohmann::json& hits, const std::string&, std::size_t) { consumer.onPage(hits); },
            []() { return false; },
            [waits, stopOnWait](const std::chrono::milliseconds delay)
            {
                if (waits)
                {
                    waits->push_back(delay);
                }
                return stopOnWait;
            },
            policy);
    }
} // namespace

// The finding this guards: one slice failing under indexer back-pressure (HTTP 429) used to throw
// the whole sliced load away, the slices that had finished included, and restart it from offset 0.
// Now the failed slice repeats only its failed page, and the other slice is never asked twice.
TEST(IndexerPageWalkTest, OneSliceFailingTransientlyDoesNotRestartTheOthers)
{
    FakeSlice slice0 {0, 7};                                                 // pages 0..3
    FakeSlice slice1 {1, 5};                                                 // pages 0..2
    slice0.failAt(1, 2, "Search request retry budget exhausted (HTTP 429)"); // the request for page 2
    FakeConsumer consumer;

    IndexerPageWalk::WalkResult result0;
    IndexerPageWalk::WalkResult result1;
    std::thread t0 {[&] { result0 = walkSlice(slice0, consumer, "Slice 0 (1/2)"); }};
    std::thread t1 {[&] { result1 = walkSlice(slice1, consumer, "Slice 1 (2/2)"); }};
    t0.join();
    t1.join();

    EXPECT_FALSE(result0.interrupted);
    EXPECT_FALSE(result1.interrupted);
    EXPECT_EQ(result0.processed, 7u);
    EXPECT_EQ(result1.processed, 5u);
    EXPECT_EQ(result0.cursor, "7");
    EXPECT_EQ(result1.cursor, "1005");

    // The failed request was repeated from the same position; nothing restarted from the beginning.
    EXPECT_EQ(slice0.requests(), (std::vector<long> {-1, 0, 1, 1, 1, 2}));
    EXPECT_EQ(slice1.requests(), (std::vector<long> {-1, 0, 1}));

    // Every document reached the consumer exactly once.
    const auto seen = consumer.seen();
    EXPECT_EQ(seen.size(), 12u);
    EXPECT_TRUE(std::all_of(seen.begin(), seen.end(), [](const auto& entry) { return entry.second == 1; }));
}

TEST(IndexerPageWalkTest, TheFailureReasonIsLoggedAtWarning)
{
    ScopedLogCapture capture;
    FakeSlice slice {0, 3};
    slice.failAt(0, 1, "Search request failed with status 429: circuit_breaking_exception");
    FakeConsumer consumer;

    const auto result = walkSlice(slice, consumer, "Slice 0 (1/2)");
    EXPECT_EQ(result.processed, 3u);

    const auto lines = capture.lines();
    const auto warning = std::find_if(lines.begin(),
                                      lines.end(),
                                      [](const LogLine& line)
                                      { return line.text.find("circuit_breaking_exception") != std::string::npos; });
    ASSERT_NE(warning, lines.end()) << "the reason of the first failure must reach the log";
    EXPECT_EQ(warning->level, Log::LOGLEVEL_WARNING);
    EXPECT_NE(warning->text.find("Slice 0 (1/2) page request failed"), std::string::npos) << warning->text;
    EXPECT_NE(warning->text.find("retry 1/5"), std::string::npos) << warning->text;
}

TEST(IndexerPageWalkTest, ExhaustedRetriesRethrowTheLastFailure)
{
    FakeSlice slice {0, 7};
    slice.failAt(0, 100, "indexer down");
    FakeConsumer consumer;

    EXPECT_THROW(walkSlice(slice, consumer, "Slice 0 (1/1)"), std::runtime_error);

    // The first page is kept by the consumer; the second was asked for once plus maxRetries times.
    EXPECT_EQ(consumer.seen().size(), 2u);
    EXPECT_EQ(slice.requests(), (std::vector<long> {-1, 0, 0, 0, 0, 0, 0}));
}

TEST(IndexerPageWalkTest, RetryWaitsBackOffUpToTheCap)
{
    FakeSlice slice {0, 1};
    slice.failAt(-1, 4, "429");
    FakeConsumer consumer;
    std::vector<std::chrono::milliseconds> waits;

    const IndexerPageWalk::RetryPolicy policy {4, std::chrono::milliseconds {10}, std::chrono::milliseconds {25}};
    const auto result = walkSlice(slice, consumer, "Download", policy, &waits);

    EXPECT_EQ(result.processed, 1u);
    EXPECT_EQ(waits,
              (std::vector<std::chrono::milliseconds> {std::chrono::milliseconds {10},
                                                       std::chrono::milliseconds {20},
                                                       std::chrono::milliseconds {25},
                                                       std::chrono::milliseconds {25}}));
}

TEST(IndexerPageWalkTest, DefaultRetryWindowStaysInsideThePitKeepAlive)
{
    const IndexerPageWalk::RetryPolicy policy {};
    auto delay = policy.initialDelay;
    std::chrono::milliseconds total {0};
    for (std::size_t i = 0; i < policy.maxRetries; ++i)
    {
        total += delay;
        delay = std::min(delay * 2, policy.maxDelay);
    }
    // Half the 5-minute keep-alive: room for the connector's own per-request retries on top.
    EXPECT_LE(total, std::chrono::milliseconds {std::chrono::minutes {5}} / 2);
}

TEST(IndexerPageWalkTest, AStopDuringTheRetryWaitInterruptsWithoutThrowing)
{
    FakeSlice slice {0, 7};
    slice.failAt(0, 1, "429");
    FakeConsumer consumer;

    IndexerPageWalk::WalkResult result;
    EXPECT_NO_THROW(result = walkSlice(slice, consumer, "Slice 0 (1/2)", FAST_POLICY, nullptr, true));

    EXPECT_TRUE(result.interrupted);
    EXPECT_EQ(result.processed, 2u);
    EXPECT_EQ(result.cursor, "2");
    EXPECT_EQ(slice.requests(), (std::vector<long> {-1, 0}));
}

TEST(IndexerPageWalkTest, AStopBeforeAPageInterruptsTheWalk)
{
    FakeSlice slice {0, 7};
    FakeConsumer consumer;
    std::size_t checks = 0;

    const auto result = IndexerPageWalk::walkPages(
        "Slice 0 (1/2)",
        PAGE_SIZE,
        "",
        [&slice](const std::optional<nlohmann::json>& searchAfter) { return slice.search(searchAfter); },
        [&consumer](const nlohmann::json& hits, const std::string&, std::size_t) { consumer.onPage(hits); },
        [&checks]() { return ++checks > 2; },
        [](std::chrono::milliseconds) { return false; },
        FAST_POLICY);

    EXPECT_TRUE(result.interrupted);
    EXPECT_EQ(result.processed, 4u);
    EXPECT_EQ(slice.requests(), (std::vector<long> {-1, 0}));
}

TEST(IndexerPageWalkTest, AConsumerFailureIsNotRetried)
{
    FakeSlice slice {0, 7};
    std::size_t pages = 0;

    EXPECT_THROW(IndexerPageWalk::walkPages(
                     "Download",
                     PAGE_SIZE,
                     "",
                     [&slice](const std::optional<nlohmann::json>& searchAfter) { return slice.search(searchAfter); },
                     [&pages](const nlohmann::json&, const std::string&, std::size_t)
                     {
                         ++pages;
                         throw std::runtime_error("fileProcessingCallback returned failure");
                     },
                     []() { return false; },
                     [](std::chrono::milliseconds) { return false; },
                     FAST_POLICY),
                 std::runtime_error);

    EXPECT_EQ(pages, 1u);
    EXPECT_EQ(slice.requests(), (std::vector<long> {-1}));
}

TEST(IndexerPageWalkTest, AnEmptyIndexEndsTheWalkWithTheStartCursor)
{
    FakeSlice slice {0, 0};
    FakeConsumer consumer;

    const auto result = IndexerPageWalk::walkPages(
        "Download",
        PAGE_SIZE,
        "41",
        [&slice](const std::optional<nlohmann::json>& searchAfter) { return slice.search(searchAfter); },
        [&consumer](const nlohmann::json& hits, const std::string&, std::size_t) { consumer.onPage(hits); },
        []() { return false; },
        [](std::chrono::milliseconds) { return false; },
        FAST_POLICY);

    EXPECT_FALSE(result.interrupted);
    EXPECT_EQ(result.processed, 0u);
    EXPECT_EQ(result.cursor, "41");
}
