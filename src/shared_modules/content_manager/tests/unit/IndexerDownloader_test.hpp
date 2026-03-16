/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_DOWNLOADER_TEST_HPP
#define _INDEXER_DOWNLOADER_TEST_HPP

#include "IndexerDownloader.hpp"
#include "conditionSync.hpp"
#include "mocks/MockIndexerConnectorSync.hpp"
#include "updaterContext.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

/// Type alias for the downloader instantiated with the trampoline.
using TestableDownloader = IndexerDownloader<TrampolineIndexerConnectorSync>;

const auto INDEXER_DL_DB_FOLDER {std::filesystem::temp_directory_path() / "indexer_dl_test_db"};

/**
 * @brief Runs unit tests for IndexerDownloader
 */
class IndexerDownloaderTest : public ::testing::Test
{
protected:
    IndexerDownloaderTest() = default;
    ~IndexerDownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext;
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext;

    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)};

    /// Tracks messages passed to the fileProcessingCallback.
    std::vector<std::string> m_callbackMessages;

    /// Whether the callback should report success.
    bool m_callbackSuccess {true};

    void SetUp() override
    {
        m_callbackMessages.clear();
        m_callbackSuccess = true;

        // Create global mock.
        spIndexerConnectorSyncMock = std::make_shared<MockIndexerConnectorSync>();

        m_spUpdaterBaseContext =
            std::make_shared<UpdaterBaseContext>(m_spStopActionCondition,
                                                 [this](const std::string& msg) -> FileProcessingResult {
                                                     m_callbackMessages.push_back(msg);
                                                     return {0, "", m_callbackSuccess};
                                                 });

        m_spUpdaterBaseContext->spRocksDB = std::make_unique<Utils::RocksDBWrapper>(INDEXER_DL_DB_FOLDER);
        m_spUpdaterBaseContext->spRocksDB->createColumn(Components::Columns::CURRENT_OFFSET);
        m_spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);

        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
    }

    void TearDown() override
    {
        spIndexerConnectorSyncMock.reset();

        if (m_spUpdaterBaseContext->spRocksDB)
        {
            m_spUpdaterBaseContext->spRocksDB->deleteAll();
        }
        std::filesystem::remove_all(INDEXER_DL_DB_FOLDER);
    }

    /**
     * @brief Builds a minimal Indexer search response page.
     */
    static nlohmann::json makeResponse(const nlohmann::json& hits)
    {
        nlohmann::json resp;
        resp["hits"]["hits"] = hits;
        return resp;
    }

    /**
     * @brief Builds a single CVE hit.
     */
    static nlohmann::json makeCveHit(const std::string& id,
                                      uint64_t offset,
                                      const std::string& state = "PUBLISHED")
    {
        nlohmann::json hit;
        hit["_id"] = id;
        hit["_source"]["type"] = "CVE";
        hit["_source"]["offset"] = offset;
        hit["_source"]["document"]["cveMetadata"]["state"] = state;
        hit["sort"] = nlohmann::json::array({offset, id});
        return hit;
    }

    /**
     * @brief Builds a non-CVE hit (TID, FEED-GLOBAL, etc.).
     */
    static nlohmann::json makeNonCveHit(const std::string& id,
                                         uint64_t offset,
                                         const std::string& docType)
    {
        nlohmann::json hit;
        hit["_id"] = id;
        hit["_source"]["type"] = docType;
        hit["_source"]["offset"] = offset;
        hit["_source"]["document"] = nlohmann::json::object();
        hit["sort"] = nlohmann::json::array({offset, id});
        return hit;
    }
};

#endif //_INDEXER_DOWNLOADER_TEST_HPP
