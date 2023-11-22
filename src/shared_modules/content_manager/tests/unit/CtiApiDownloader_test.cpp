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

#include "CtiApiDownloader_test.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>

const auto OK_STATUS = R"([{"stage":"CtiApiDownloader","status":"ok"}])"_json;
const auto FAIL_STATUS = R"([{"stage":"CtiApiDownloader","status":"fail"}])"_json;

/**
 * @brief Tests handle a valid request with raw data.
 */
TEST_F(CtiApiDownloaderTest, TestHandleValidRequestWithRawData)
{
    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/3-" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/3-" + fileName};

    EXPECT_NO_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), contentPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, OK_STATUS);

    // It's true because the compressionType is `raw`
    EXPECT_TRUE(std::filesystem::exists(contentPath));

    // It's false because the compressionType isn't `xz`
    EXPECT_FALSE(std::filesystem::exists(downloadPath));
}

/**
 * @brief Tests handle a valid request with compressed data.
 */
TEST_F(CtiApiDownloaderTest, TestHandleValidRequestWithCompressedData)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz/consumers";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";

    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/3-" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/3-" + fileName};

    EXPECT_NO_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), downloadPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, OK_STATUS);

    // It's false because the compressionType isn't `raw`
    EXPECT_FALSE(std::filesystem::exists(contentPath));

    // It's true because the compressionType is `xz`
    EXPECT_TRUE(std::filesystem::exists(downloadPath));
}

/**
 * @brief Tests handle a valid request with compressed data and invalid output folder.
 */
TEST_F(CtiApiDownloaderTest, TestHandleValidRequestWithCompressedDataAndInvalidOutputFolder)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);
}

/**
 * @brief Tests handle an empty url.
 */
TEST_F(CtiApiDownloaderTest, TestHandleAnEmptyUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);
}

/**
 * @brief Tests handle an invalid url.
 */
TEST_F(CtiApiDownloaderTest, TestHandleAnInvalidUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/invalid-url";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    EXPECT_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, FAIL_STATUS);
}

/**
 * @brief Test the retry feature of the downloader when the server responds with 5xx errors.
 *
 */
TEST_F(CtiApiDownloaderTest, DownloadServerErrorWithRetry)
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

    ASSERT_NO_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(contentPath));
}

/**
 * @brief Test the downloader when the server responds with 4xx errors.
 *
 */
TEST_F(CtiApiDownloaderTest, DownloadClientErrorNoRetry)
{
    // Push one errors to the server. No retries should be performed.
    m_spFakeServer->pushError(400);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;

    ASSERT_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Test the downloader when the server responds with both 4xx and 5xx errors.
 *
 */
TEST_F(CtiApiDownloaderTest, DownloadClientAndServerErrorsRetryAndFail)
{
    // Push two errors to the server. This will make the client to retry once.
    m_spFakeServer->pushError(550);
    m_spFakeServer->pushError(400);

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = FAIL_STATUS;

    ASSERT_THROW(m_spCtiApiDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
