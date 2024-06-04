/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 01, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "CtiSnapshotDownloader_test.hpp"
#include "CtiSnapshotDownloader.hpp"
#include "HTTPRequest.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

const auto OK_STATUS = R"([{"stage":"CtiSnapshotDownloader","status":"ok"}])"_json;
const auto FAIL_STATUS = R"([{"stage":"CtiSnapshotDownloader","status":"fail"}])"_json;

constexpr auto CONTENT_TYPE {"raw"};
constexpr auto FAKE_CTI_URL {"http://localhost:4444/snapshot/consumers"};
constexpr auto RAW_URL {"http://localhost:4444/raw"};

const auto OUTPUT_DIR {std::filesystem::temp_directory_path() / "CtiSnapshotDownloaderTest"};

void CtiSnapshotDownloaderTest::SetUp()
{
    // Create base context.
    auto spBaseContext {std::make_shared<UpdaterBaseContext>(m_spStopActionCondition)};
    spBaseContext->downloadsFolder = OUTPUT_DIR;
    spBaseContext->configData["url"] = FAKE_CTI_URL;

    // Create updater context.
    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = spBaseContext;

    // Create output folder.
    std::filesystem::create_directory(spBaseContext->downloadsFolder);
}

void CtiSnapshotDownloaderTest::TearDown()
{
    // Remove output folder and clear fake server errors queue.
    std::filesystem::remove_all(m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder);
    m_spFakeServer->clearErrorsQueue();
}

void CtiSnapshotDownloaderTest::SetUpTestSuite()
{
    if (!m_spFakeServer)
    {
        m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
    }
}

void CtiSnapshotDownloaderTest::TearDownTestSuite()
{
    m_spFakeServer.reset();
}

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(CtiSnapshotDownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(std::make_shared<CtiSnapshotDownloader>(HTTPRequest::instance()));
    EXPECT_NO_THROW(CtiSnapshotDownloader(HTTPRequest::instance()));
}

/**
 * @brief Tests the correct download of an snapshot file.
 *
 */
TEST_F(CtiSnapshotDownloaderTest, SnapshotDownload)
{
    ASSERT_NO_THROW(CtiSnapshotDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));

    // Set expected data.
    const auto expectedContentPath {m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder / SNAPSHOT_FILE_NAME};
    constexpr auto EXPECTED_CURRENT_OFFSET {3};
    nlohmann::json expectedData;
    expectedData["paths"] = nlohmann::json::array();
    expectedData["paths"].push_back(expectedContentPath);
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = EXPECTED_CURRENT_OFFSET;

    EXPECT_EQ(m_spUpdaterContext->currentOffset, EXPECTED_CURRENT_OFFSET);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedContentPath));
}

/**
 * @brief Tests the correct download of an snapshot file with the retry feature.
 *
 */
TEST_F(CtiSnapshotDownloaderTest, SnapshotDownloadWithRetry)
{
    // Push server error.
    m_spFakeServer->pushError(500);

    ASSERT_NO_THROW(CtiSnapshotDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));

    // Set expected data.
    constexpr auto EXPECTED_CURRENT_OFFSET {3};
    const auto expectedContentPath {m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder / SNAPSHOT_FILE_NAME};
    nlohmann::json expectedData;
    expectedData["paths"] = nlohmann::json::array();
    expectedData["paths"].push_back(expectedContentPath);
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = EXPECTED_CURRENT_OFFSET;

    EXPECT_EQ(m_spUpdaterContext->currentOffset, EXPECTED_CURRENT_OFFSET);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedContentPath));
}

/**
 * @brief Tests the download of the snapshot when last_snapshot_link metadata is missing.
 *
 */
TEST_F(CtiSnapshotDownloaderTest, MissingLastSnapshotLinkMetadata)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_offset": 100,
                "last_snapshot_offset": 0
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    ASSERT_THROW(CtiSnapshotDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of the snapshot when last_snapshot_offset metadata is missing.
 *
 */
TEST_F(CtiSnapshotDownloaderTest, MissingLastSnapshotOffsetMetadata)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_offset": 100,
                "last_snapshot_link": "some_link"
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    ASSERT_THROW(CtiSnapshotDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = CONTENT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
