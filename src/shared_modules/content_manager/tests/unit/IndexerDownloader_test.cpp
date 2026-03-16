/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "IndexerDownloader_test.hpp"
#include "updaterContext.hpp"
#include <functional>
#include <string>

using ::testing::_;
using ::testing::Invoke;

/// Definition of the global mock pointer declared in the mock header.
std::shared_ptr<MockIndexerConnectorSync> spIndexerConnectorSyncMock;

namespace
{

nlohmann::json makeConfig()
{
    return nlohmann::json {{"indexer", {{"index", ".cti-cves"}, {"pageSize", 2}}}};
}

} // namespace

/**
 * @brief Cursor "0" triggers initialLoad (match_all query).
 */
TEST_F(IndexerDownloaderTest, InitialLoadWhenCursorIsZero)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string& /*index*/,
                            const nlohmann::json& query,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            // Verify initial load uses match_all.
            EXPECT_TRUE(query.contains("query"));
            EXPECT_TRUE(query.at("query").contains("match_all"));

            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 10));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_callbackMessages.size(), 1u);
    EXPECT_EQ(m_spUpdaterContext->data["cursor"], "10");
}

/**
 * @brief Cursor "500" triggers range query with offset.gt = 500.
 */
TEST_F(IndexerDownloaderTest, IncrementalUpdateWhenCursorExists)
{
    // Set a non-zero cursor in RocksDB.
    m_spUpdaterBaseContext->spRocksDB->put(
        Utils::getCompactTimestamp(std::time(nullptr)), "500", Components::Columns::CURRENT_OFFSET);

    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string& /*index*/,
                            const nlohmann::json& query,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            // Verify incremental update uses range query.
            EXPECT_TRUE(query.contains("query"));
            EXPECT_TRUE(query.at("query").contains("range"));
            EXPECT_EQ(query.at("query").at("range").at("offset").at("gt").get<uint64_t>(), 500u);

            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0501", 501));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data["cursor"], "501");
}

/**
 * @brief REJECTED CVE maps to resource type "delete".
 */
TEST_F(IndexerDownloaderTest, CVERejectedMapsToDelete)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-9999", 1, "REJECTED"));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    downloader->handleRequest(m_spUpdaterContext);

    ASSERT_EQ(m_callbackMessages.size(), 1u);
    auto msg = nlohmann::json::parse(m_callbackMessages[0]);
    EXPECT_EQ(msg.at("data").at(0).at("type"), "delete");
}

/**
 * @brief Non-REJECTED (PUBLISHED) CVE maps to resource type "create".
 */
TEST_F(IndexerDownloaderTest, CVEPublishedMapsToCreate)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 1, "PUBLISHED"));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    downloader->handleRequest(m_spUpdaterContext);

    ASSERT_EQ(m_callbackMessages.size(), 1u);
    auto msg = nlohmann::json::parse(m_callbackMessages[0]);
    EXPECT_EQ(msg.at("data").at(0).at("type"), "create");
}

/**
 * @brief TID-*, FEED-GLOBAL, OSCPE-GLOBAL, CNA-MAPPING-GLOBAL always map to "create".
 */
TEST_F(IndexerDownloaderTest, NonCVEResourceAlwaysCreate)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeNonCveHit("TID-0001", 1, "TRANSLATION"));
            hits.push_back(IndexerDownloaderTest::makeNonCveHit("FEED-GLOBAL", 2, "VENDOR_MAP"));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    downloader->handleRequest(m_spUpdaterContext);

    ASSERT_EQ(m_callbackMessages.size(), 1u);
    auto msg = nlohmann::json::parse(m_callbackMessages[0]);
    for (const auto& resource : msg.at("data"))
    {
        EXPECT_EQ(resource.at("type"), "create");
    }
}

/**
 * @brief TCPE and TVENDORS documents are skipped (excluded from data array).
 */
TEST_F(IndexerDownloaderTest, TCPEAndTVENDORSSkipped)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeNonCveHit("TCPE-001", 1, "TCPE"));
            hits.push_back(IndexerDownloaderTest::makeNonCveHit("TVENDORS-001", 2, "TVENDORS"));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    downloader->handleRequest(m_spUpdaterContext);

    ASSERT_EQ(m_callbackMessages.size(), 1u);
    auto msg = nlohmann::json::parse(m_callbackMessages[0]);
    EXPECT_TRUE(msg.at("data").empty());
}

/**
 * @brief Callback invoked per page, cursor tracks across pages.
 */
TEST_F(IndexerDownloaderTest, MultiPageIteration)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            // Page 1 (2 hits = pageSize, so pagination continues internally in the real connector).
            auto page1 = nlohmann::json::array();
            page1.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 10));
            page1.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0002", 20));
            onResponse(IndexerDownloaderTest::makeResponse(page1));

            // Page 2 (1 hit < pageSize = last page).
            auto page2 = nlohmann::json::array();
            page2.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0003", 30));
            onResponse(IndexerDownloaderTest::makeResponse(page2));
        }));

    downloader->handleRequest(m_spUpdaterContext);

    // Two pages → two callback invocations.
    EXPECT_EQ(m_callbackMessages.size(), 2u);
}

/**
 * @brief context.data["cursor"] == highest offset from last page.
 */
TEST_F(IndexerDownloaderTest, CursorAdvancement)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 100));
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0002", 200));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    downloader->handleRequest(m_spUpdaterContext);
    EXPECT_EQ(m_spUpdaterContext->data["cursor"], "200");
}

/**
 * @brief Callback returning failure propagates as std::runtime_error.
 */
TEST_F(IndexerDownloaderTest, CallbackFailurePropagates)
{
    m_callbackSuccess = false;

    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 1));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    EXPECT_THROW(downloader->handleRequest(m_spUpdaterContext), std::runtime_error);
}

/**
 * @brief Empty hits → fileProcessingCallback not called.
 */
TEST_F(IndexerDownloaderTest, EmptyResponseNoCallback)
{
    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json&,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            // Empty response.
            onResponse(IndexerDownloaderTest::makeResponse(nlohmann::json::array()));
        }));

    downloader->handleRequest(m_spUpdaterContext);
    EXPECT_TRUE(m_callbackMessages.empty());
}

/**
 * @brief spRocksDB = nullptr → initial load path (empty cursor).
 */
TEST_F(IndexerDownloaderTest, NoRocksDBReturnsEmptyCursor)
{
    m_spUpdaterBaseContext->spRocksDB.reset();

    auto config = makeConfig();
    auto downloader = std::make_shared<TestableDownloader>(config);

    EXPECT_CALL(*spIndexerConnectorSyncMock, executeSearchQueryWithPagination(_, _, _))
        .WillOnce(Invoke([](const std::string&,
                            const nlohmann::json& query,
                            std::function<void(const nlohmann::json&)> onResponse)
        {
            // Should be initial load (match_all).
            EXPECT_TRUE(query.at("query").contains("match_all"));

            auto hits = nlohmann::json::array();
            hits.push_back(IndexerDownloaderTest::makeCveHit("CVE-2026-0001", 5));
            onResponse(IndexerDownloaderTest::makeResponse(hits));
        }));

    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data["cursor"], "5");
}
