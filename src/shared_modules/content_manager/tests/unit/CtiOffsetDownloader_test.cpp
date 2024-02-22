/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "CtiOffsetDownloader_test.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>

const auto OK_STATUS = R"([{"stage":"CtiOffsetDownloader","status":"ok"}])"_json;
const auto FAIL_STATUS = R"([{"stage":"CtiOffsetDownloader","status":"fail"}])"_json;

constexpr auto DEFAULT_TYPE {"offsets"}; ///< Default content type.

/**
 * @brief Tests handle a valid request with raw data.
 */
TEST_F(CtiOffsetDownloaderTest, TestHandleValidRequestWithRawData)
{
    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/3-" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/3-" + fileName};

    EXPECT_NO_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), contentPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, OK_STATUS);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);

    // It's true because the compressionType is `raw`
    EXPECT_TRUE(std::filesystem::exists(contentPath));

    // It's false because the compressionType isn't `xz`
    EXPECT_FALSE(std::filesystem::exists(downloadPath));
}

/**
 * @brief Tests handle a valid request with compressed data.
 */
TEST_F(CtiOffsetDownloaderTest, TestHandleValidRequestWithCompressedData)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz/consumers";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";

    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/3-" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/3-" + fileName};

    EXPECT_NO_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), downloadPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, OK_STATUS);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);

    // It's false because the compressionType isn't `raw`
    EXPECT_FALSE(std::filesystem::exists(contentPath));

    // It's true because the compressionType is `xz`
    EXPECT_TRUE(std::filesystem::exists(downloadPath));
}

/**
 * @brief Tests handle a valid request with compressed data and invalid output folder.
 */
TEST_F(CtiOffsetDownloaderTest, TestHandleValidRequestWithCompressedDataAndInvalidOutputFolder)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}

/**
 * @brief Tests handle an empty url.
 */
TEST_F(CtiOffsetDownloaderTest, TestHandleAnEmptyUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}

/**
 * @brief Tests handle an invalid url.
 */
TEST_F(CtiOffsetDownloaderTest, TestHandleAnInvalidUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/invalid-url";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}

/**
 * @brief Test the retry feature of the downloader when the server responds with 5xx errors.
 *
 */
TEST_F(CtiOffsetDownloaderTest, DownloadServerErrorWithRetry)
{
    // Push two errors to the server. This will make the client to retry twice.
    m_spFakeServer->pushError(500);
    m_spFakeServer->pushError(599);

    const auto& filename {m_spUpdaterBaseContext->configData.at("contentFileName").get<const std::string>()};
    const auto contentPath {m_spUpdaterBaseContext->contentsFolder.string() + "/3-" + filename};

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(contentPath);
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 3;

    ASSERT_NO_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(contentPath));
}

/**
 * @brief Test the downloader when the server responds with 4xx errors.
 *
 */
TEST_F(CtiOffsetDownloaderTest, DownloadClientErrorNoRetry)
{
    // Push one errors to the server. No retries should be performed.
    m_spFakeServer->pushError(400);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Test the downloader when the server responds with both 4xx and 5xx errors.
 *
 */
TEST_F(CtiOffsetDownloaderTest, DownloadClientAndServerErrorsRetryAndFail)
{
    // Push two errors to the server. This will make the client to retry once.
    m_spFakeServer->pushError(550);
    m_spFakeServer->pushError(400);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Test the download interruption.
 *
 */
TEST_F(CtiOffsetDownloaderTest, DownloadInterrupted)
{
    // Set interruption flag.
    m_spStopActionCondition->set(true);

    ASSERT_NO_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext));

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = OK_STATUS;
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of the offsets when last_offset metadata is missing.
 *
 */
TEST_F(CtiOffsetDownloaderTest, MissingLastOffsetMetadata)
{
    std::string mockMetadata = R"(
        {
            "data":
            {
                "ignored_key": true,
                "last_snapshot_link": "some_link",
                "last_snapshot_offset": 50
            }
        }
    )";
    m_spFakeServer->setCtiMetadata(std::move(mockMetadata));

    ASSERT_THROW(m_spCtiOffsetDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
