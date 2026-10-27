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
#include <sched.h>
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

    /// What the consumer saw: every delivered id, the pages, the completion signal. A delivered id is
    /// durable once a later "flushed" answer or the completion covers it; what a crash would lose is
    /// the rest. `violations` counts the times the stored cursor covered a document that was not durable.
    struct Delivered
    {
        std::mutex mutex;
        std::vector<std::string> ids;
        size_t pages {0};
        size_t flushEvery {3};
        size_t completions {0};
        bool lastChanged {false};
        std::string lastCompletionCursor;
        std::set<std::string> durable;
        std::vector<std::string> unflushed;
        size_t violations {0};
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
            [this, delivered](nlohmann::json message) -> FileProcessingResult
            {
                std::lock_guard<std::mutex> lock(delivered->mutex);
                checkStoredCursorIsDurable(*delivered);
                if (message.at("type") == "indexer_complete")
                {
                    ++delivered->completions;
                    delivered->lastChanged = message.value("changed", false);
                    delivered->lastCompletionCursor = message.value("cursor", std::string {});
                    makeDurable(*delivered);
                    return {0, "indexer_complete", true};
                }
                for (const auto& resource : message.at("data"))
                {
                    delivered->ids.push_back(resource.at("resource").get<std::string>());
                    delivered->unflushed.push_back(resource.at("resource").get<std::string>());
                }
                ++delivered->pages;
                const bool flushed = (delivered->pages % delivered->flushEvery) == 0;
                if (flushed)
                {
                    makeDurable(*delivered);
                }
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

    static nlohmann::json config(size_t numSlices, size_t pageSize = PAGE_SIZE)
    {
        return {{"indexer", {{"index", "feed"}, {"pageSize", pageSize}, {"numSlices", numSlices}}}};
    }

    static void makeDurable(Delivered& delivered)
    {
        delivered.durable.insert(delivered.unflushed.begin(), delivered.unflushed.end());
        delivered.unflushed.clear();
    }

    /// A crash now must not lose a document at or below the stored cursor: a resume reads `offset > cursor`.
    void checkStoredCursorIsDurable(Delivered& delivered) const
    {
        const auto cursor = std::stoull(storedCursor());
        for (const auto& doc : m_index->docs)
        {
            if (doc.offset <= cursor && delivered.durable.count(doc.id) == 0)
            {
                ++delivered.violations;
                return;
            }
        }
    }

    size_t durabilityViolations()
    {
        std::lock_guard<std::mutex> lock(m_delivered->mutex);
        checkStoredCursorIsDurable(*m_delivered);
        return m_delivered->violations;
    }

    IndexerSearchClientFactory factory()
    {
        auto index = m_index;
        return [index](const nlohmann::json&)
        {
            return std::make_unique<FakeIndexerSearchClient>(index);
        };
    }

    void run(size_t numSlices, size_t pageSize = PAGE_SIZE)
    {
        IndexerDownloader downloader(config(numSlices, pageSize), factory(), RETRY_INTERVAL);
        downloader.handleRequest(m_context);
    }

    std::string storedCursor() const
    {
        return m_base->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
    }

    void storeCursor(uint64_t offset) const
    {
        m_base->spRocksDB->put(Utils::getCompactTimestamp(std::time(nullptr)),
                               std::to_string(offset),
                               Components::Columns::CURRENT_OFFSET);
    }

    bool initialLoadPending() const
    {
        if (!m_base->spRocksDB->columnExists(Components::Columns::INITIAL_LOAD_PENDING))
        {
            return false;
        }
        std::string value;
        return m_base->spRocksDB->get(InitialLoadState::PENDING_KEY, value, Components::Columns::INITIAL_LOAD_PENDING);
    }

    void setInitialLoadPending() const
    {
        if (!m_base->spRocksDB->columnExists(Components::Columns::INITIAL_LOAD_PENDING))
        {
            m_base->spRocksDB->createColumn(Components::Columns::INITIAL_LOAD_PENDING);
        }
        m_base->spRocksDB->put(InitialLoadState::PENDING_KEY, "1", Components::Columns::INITIAL_LOAD_PENDING);
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
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, SlicedLoadDeliversEveryDocumentOnce)
{
    run(2);

    EXPECT_EQ(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(m_index->pitsCreated, 1u);
    EXPECT_EQ(durabilityViolations(), 0u);
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
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(durabilityViolations(), 0u);
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
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, StopDuringSlicedLoadKeepsTheLastSafeCursor)
{
    // Slices take turns, so the flush after page 3 always follows a page of each slice and its safe
    // cursor is past offset 0; it stays persisted after the stop, nothing is completed.
    m_index->lockstepSlices = 2;
    m_index->stopAtRequest = 5;

    run(2);

    EXPECT_TRUE(m_stop->check());
    EXPECT_EQ(m_delivered->completions, 0u);
    EXPECT_NE(storedCursor(), "0");
    EXPECT_LE(std::stoull(storedCursor()), FIRST_CVE_OFFSET + CVE_DOCS - 1);
    EXPECT_LT(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, ZeroDocumentsMeansIndexNotReadyAndRetries)
{
    m_index->emptyUntilRequest = 2; // both slices' first page of attempt 1

    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_index->pitsCreated, 2u) << "attempt 1 saw an empty index, attempt 2 loaded it";
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, RestartDuringInitialLoadResumesThroughTheInitialPath)
{
    // Run 1 is stopped after four pages (one flush): a safe cursor and the pending marker stay in the
    // updater DB. Run 2 (a new downloader, same DB, as after a daemon restart) must continue the
    // initial load from that cursor and clear the marker once the completion is accepted. Lockstep
    // slices make the first flush cover a page of each, so the stored cursor is past offset 0.
    m_index->lockstepSlices = 2;
    m_index->stopAtRequest = 5;
    run(2);
    ASSERT_TRUE(initialLoadPending());
    const auto resumeCursor = storedCursor();
    ASSERT_NE(resumeCursor, "0");
    const auto deliveredBeforeRestart = m_delivered->ids.size();

    m_index->lockstepSlices = 0;
    m_index->stopAtRequest = 0;
    m_stop->set(false);
    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_FALSE(initialLoadPending());
    EXPECT_EQ(m_index->pitsCreated, 2u);
    const auto& resumed = firstSearchOf("pit-2");
    ASSERT_TRUE(resumed.query.contains("range")) << resumed.query.dump();
    EXPECT_EQ(resumed.query.at("range").at("offset").at("gt").get<uint64_t>(), std::stoull(resumeCursor));
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS) << "nothing is lost across the restart";
    EXPECT_GT(m_delivered->ids.size(), deliveredBeforeRestart);
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, CompletedLoadWithPendingMarkerHealsItself)
{
    // The marker survived a crash between "completion accepted" and "marker cleared": the next run
    // resumes from the final cursor, finds nothing, sends the completion again and clears the marker.
    setInitialLoadPending();
    storeCursor(FIRST_CVE_OFFSET + CVE_DOCS - 1);
    for (const auto& doc : m_index->docs)
    {
        m_delivered->durable.insert(doc.id);
    }

    run(2);

    EXPECT_EQ(m_delivered->ids.size(), 0u);
    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_FALSE(m_delivered->lastChanged);
    EXPECT_FALSE(initialLoadPending());
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, StoredCursorWithoutMarkerTakesTheIncrementalPath)
{
    // A completed feed (cursor, no marker) keeps today's incremental update: one sequential PIT over
    // the documents after the cursor, whatever numSlices says, and no marker is written.
    storeCursor(FIRST_CVE_OFFSET + 499);

    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(m_index->pitsCreated, 1u);
    const auto& first = firstSearchOf("pit-1");
    ASSERT_TRUE(first.query.contains("range")) << first.query.dump();
    EXPECT_EQ(first.query.at("range").at("offset").at("gt").get<uint64_t>(), FIRST_CVE_OFFSET + 499);
    EXPECT_FALSE(first.slice.has_value());
    EXPECT_EQ(m_delivered->ids.size(), CVE_DOCS - 500);
    EXPECT_FALSE(initialLoadPending());
}

TEST_F(IndexerDownloaderTest, SlicedFinalCursorWaitsForTheCompletionFlush)
{
    // Flushes after pages 5 and 10 of 11-12: the tail is durable only once the completion is
    // processed, so the final cursor may not be stored before it (UpdateIndexerCursor stores it after).
    m_delivered->flushEvery = 5;

    run(2);

    EXPECT_EQ(m_delivered->completions, 1u);
    EXPECT_EQ(deliveredSet().size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_EQ(m_context->data.at("cursor").get<std::string>(), std::to_string(FIRST_CVE_OFFSET + CVE_DOCS - 1));
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, StopAfterTheLastPageLeavesNoUnflushedCursorForTheChain)
{
    // The stop arrives with the last page (request 11): the download ends normally but the completion
    // is skipped, so the cursor of the unflushed tail must not reach UpdateIndexerCursor.
    m_index->stopAtRequest = 11;

    run(1);

    EXPECT_TRUE(m_stop->check());
    EXPECT_EQ(m_delivered->completions, 0u);
    EXPECT_EQ(m_delivered->ids.size(), GLOBAL_DOCS + CVE_DOCS);
    EXPECT_FALSE(m_context->data.contains("cursor"));
    EXPECT_EQ(storedCursor(), std::to_string(FIRST_CVE_OFFSET + 896));
    EXPECT_EQ(durabilityViolations(), 0u);
}

TEST_F(IndexerDownloaderTest, SlicedFlushNeverCoversAnotherSlicesUnflushedPage)
{
    // A slice's "flushed" answer and the frontier it computes must not let another slice deliver an
    // unflushed page in between. The window is a scheduling race: many small pages over four slices,
    // repeated, with every slice thread on one CPU (where the reviewer reproduced it 14/60).
    constexpr size_t ROUNDS {30};
    m_delivered->flushEvery = 2;

    cpu_set_t original;
    const bool pinned = sched_getaffinity(0, sizeof(original), &original) == 0 && [&original]
    {
        cpu_set_t one;
        CPU_ZERO(&one);
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
        {
            if (CPU_ISSET(cpu, &original))
            {
                CPU_SET(cpu, &one);
                break;
            }
        }
        return sched_setaffinity(0, sizeof(one), &one) == 0;
    }();

    for (size_t round = 0; round < ROUNDS && durabilityViolations() == 0; ++round)
    {
        storeCursor(0);
        {
            std::lock_guard<std::mutex> lock(m_delivered->mutex);
            m_delivered->ids.clear();
            m_delivered->durable.clear();
            m_delivered->unflushed.clear();
            m_delivered->pages = 0;
        }
        run(4, 10);
    }

    if (pinned)
    {
        sched_setaffinity(0, sizeof(original), &original);
    }

    EXPECT_EQ(m_delivered->completions, ROUNDS);
    EXPECT_EQ(durabilityViolations(), 0u);
}
