/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * IndexerDownloader's load paths against an in-memory index: what each mode delivers, what it
 * persists, and how a failed page, a stop request or an empty index are handled.
 */
#include "IndexerDownloader.hpp"
#include "componentsHelper.hpp"
#include "conditionSync.hpp"
#include "fakeIndexerSearchClient.hpp"
#include "updaterContext.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include "gtest/gtest.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace
{
    constexpr size_t GLOBAL_DOCS {3};
    constexpr size_t CVE_DOCS {1000};
    constexpr uint64_t FIRST_CVE_OFFSET {1001};
    constexpr size_t PAGE_SIZE {100};
    constexpr auto RETRY_INTERVAL {std::chrono::milliseconds {10}};

    /// What the consumer saw: every delivered id, the pages, the completion signal.
    struct Delivered
    {
        std::mutex mutex;
        std::vector<std::string> ids;
        size_t pages {0};
        size_t flushEvery {3};
        size_t completions {0};
        bool lastChanged {false};
        std::string lastCompletionCursor;
    };
} // namespace

class IndexerDownloaderTest : public ::testing::Test
{
protected:
    std::filesystem::path m_dbPath;
    std::shared_ptr<FakeIndex> m_index {std::make_shared<FakeIndex>()};
    std::shared_ptr<ConditionSync> m_stop {std::make_shared<ConditionSync>(false)};
    std::shared_ptr<Delivered> m_delivered {std::make_shared<Delivered>()};
    std::shared_ptr<UpdaterBaseContext> m_base;
    std::shared_ptr<UpdaterContext> m_context;

    void SetUp() override
    {
        m_dbPath =
            std::filesystem::temp_directory_path() / ("indexerDownloader_utest_" + std::to_string(::getpid()) + "_" +
                                                      ::testing::UnitTest::GetInstance()->current_test_info()->name());
        std::filesystem::remove_all(m_dbPath);

        m_index->add("FEED-GLOBAL", 1, "FEED");
        m_index->add("OSCPE-GLOBAL", 2, "OSCPE");
        m_index->add("CNA-MAPPING-GLOBAL", 3, "CNA");
        for (size_t i = 0; i < CVE_DOCS; ++i)
        {
            char id[32];
            snprintf(id, sizeof(id), "CVE-2026-%04zu", i);
            m_index->add(id, FIRST_CVE_OFFSET + i, "CVE");
        }
        m_index->stopCondition = m_stop;

        auto delivered = m_delivered;
        m_base = std::make_shared<UpdaterBaseContext>(
            m_stop,
            [delivered](nlohmann::json message) -> FileProcessingResult
            {
                std::lock_guard<std::mutex> lock(delivered->mutex);
                if (message.at("type") == "indexer_complete")
                {
                    ++delivered->completions;
                    delivered->lastChanged = message.value("changed", false);
                    delivered->lastCompletionCursor = message.value("cursor", std::string {});
                    return {0, "indexer_complete", true};
                }
                for (const auto& resource : message.at("data"))
                {
                    delivered->ids.push_back(resource.at("resource").get<std::string>());
                }
                ++delivered->pages;
                const bool flushed = (delivered->pages % delivered->flushEvery) == 0;
                return {0, flushed ? "flushed" : "", true};
            });
        m_base->spRocksDB = std::make_unique<Utils::RocksDBWrapper>(m_dbPath.string());
        m_base->spRocksDB->createColumn(Components::Columns::CURRENT_OFFSET);
        m_base->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);

        m_context = std::make_shared<UpdaterContext>();
        m_context->spUpdaterBaseContext = m_base;
    }

    void TearDown() override
    {
        m_base->spRocksDB.reset();
        std::filesystem::remove_all(m_dbPath);
    }

    static nlohmann::json config(size_t numSlices)
    {
        return {{"indexer", {{"index", "feed"}, {"pageSize", PAGE_SIZE}, {"numSlices", numSlices}}}};
    }

    IndexerSearchClientFactory factory()
    {
        auto index = m_index;
        return [index](const nlohmann::json&)
        {
            return std::make_unique<FakeIndexerSearchClient>(index);
        };
    }

    void run(size_t numSlices)
    {
        IndexerDownloader downloader(config(numSlices), factory(), RETRY_INTERVAL);
        downloader.handleRequest(m_context);
    }

    std::string storedCursor() const
    {
        return m_base->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    }

    std::set<std::string> deliveredSet() const
    {
        return {m_delivered->ids.begin(), m_delivered->ids.end()};
    }

    /// The first PIT search issued with the given PIT (one PIT per attempt).
    const FakeIndex::SearchRecord& firstSearchOf(const std::string& pitId) const
    {
        const auto it = std::find_if(m_index->searches.begin(),
                                     m_index->searches.end(),
                                     [&pitId](const FakeIndex::SearchRecord& r) { return r.pitId == pitId; });
        if (it == m_index->searches.end())
        {
            throw std::runtime_error("no search with pit " + pitId);
        }
        return *it;
    }
};

TEST_F(IndexerDownloaderTest, SequentialLoadDeliversEveryDocumentAndPersistsTheCursor)
{
    run(1);

    EXPECT_EQ(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_TRUE(m_delivered->lastChanged);
    // 1003 documents = 11 pages; flushes after pages 3, 6 and 9: the persisted cursor is page 9's last
    // offset (the 897th CVE), the context carries the final one.
    EXPECT_EQ(storedCursor(), std::to_string(FIRST_CVE_OFFSET + 896));
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(m_index->pitsCreated, 1u);
    EXPECT_EQ(m_index->pitsDeleted, 1u);
}

TEST_F(IndexerDownloaderTest, SlicedLoadDeliversEveryDocumentOnce)
{
    run(2);

    EXPECT_EQ(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(storedCursor(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(m_index->pitsCreated, 1u);
}

TEST_F(IndexerDownloaderTest, FailedPageResumesFromTheLastSafeCursorSliced)
{
    // Pages 1-6 are delivered (flushes after pages 3 and 6), request 7 fails: the surviving slice
    // finishes its half, the attempt is discarded, and the retry must start after the lowest offset
    // both slices had delivered when the consumer last answered "flushed".
    m_index->failAtRequest = 7;

    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS) << "nothing is lost";
    EXPECT_EQ(m_index->pitsCreated, 2u) << "one PIT per attempt";
    const auto& retry = firstSearchOf("pit-2");
    ASSERT_TRUE(retry.query.contains("range")) << retry.query.dump();
    const auto resumeOffset = retry.query.at("range").at("offset").at("gt").get<uint64_t>();
    EXPECT_GT(resumeOffset, 0u);
    EXPECT_LT(resumeOffset, FIRST_CVE_OFFSET + CVE_DOCS - 1);
    EXPECT_FALSE(retry.hasSearchAfter);
    EXPECT_LT(m_delivered->ids.size(), 2 * (GLOBAL_DOCS + CVE_DOCS)) << "re-reads are bounded by the flush";
    EXPECT_EQ(storedCursor(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
}

TEST_F(IndexerDownloaderTest, FailedPageResumesFromTheLastFlushedCursorSequential)
{
    // Pages 1-6 delivered, flushed after page 6 (its last document is the 597th CVE), request 7
    // fails: the retry reads only what follows, so every document is delivered exactly once.
    m_index->failAtRequest = 7;

    run(1);

    EXPECT_EQ(m_delivered->completions, 1u);
    const auto& retry = firstSearchOf("pit-2");
    ASSERT_TRUE(retry.query.contains("range")) << retry.query.dump();
    EXPECT_EQ(retry.query.at("range").at("offset").at("gt").get<uint64_t>(), FIRST_CVE_OFFSET + 596);
    EXPECT_FALSE(retry.hasSearchAfter);
    EXPECT_EQ(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    // Sequential mode persists on flushes only (page 9 here); the final cursor travels in the context
    // for UpdateIndexerCursor, which is not part of this chain.
    EXPECT_EQ(storedCursor(), std::to_string(FIRST_CVE_OFFSET + 896));
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
}

TEST_F(IndexerDownloaderTest, StopDuringSlicedLoadKeepsTheLastSafeCursor)
{
    // Four pages delivered (one flush after page 3) before the stop: the safe cursor of that flush
    // stays persisted, nothing is completed.
    m_index->stopAtRequest = 5;

    run(2);

    EXPECT_TRUE(m_stop->check());
    EXPECT_EQ(m_delivered->completions, 0u);
    EXPECT_NE(storedCursor(), "0");
    EXPECT_LE(std::stoull(storedCursor()), FIRST_CVE_OFFSET + CVE_DOCS - 1);
    EXPECT_LT(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
}

TEST_F(IndexerDownloaderTest, ZeroDocumentsMeansIndexNotReadyAndRetries)
{
    m_index->emptyUntilRequest = 2; // both slices' first page of attempt 1

    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_index->pitsCreated, 2u) << "attempt 1 saw an empty index, attempt 2 loaded it";
}
