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

#include "APIDownloader_test.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>

constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

/**
 * @brief Tests handle a valid request with raw data.
 */
TEST_F(APIDownloaderTest, TestHandleValidRequestWithRawData)
{
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    const auto expectedStageStatus = R"(
        [
            {
                "stage": "APIDownloader",
                "status": "ok"
            }
        ]
    )"_json;

    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/" + fileName};

    EXPECT_NO_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), contentPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, expectedStageStatus);

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
TEST_F(APIDownloaderTest, TestHandleValidRequestWithCompressedData)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    const auto expectedStageStatus = R"(
        [
            {
                "stage": "APIDownloader",
                "status": "ok"
            }
        ]
    )"_json;

    const auto& fileName {
        m_spUpdaterContext->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
    const auto contentPath {static_cast<std::string>(m_spUpdaterBaseContext->contentsFolder) + "/" + fileName};
    const auto downloadPath {static_cast<std::string>(m_spUpdaterBaseContext->downloadsFolder) + "/" + fileName};

    EXPECT_NO_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext));

    EXPECT_EQ(m_spUpdaterContext->data.at("paths").at(0), downloadPath);

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, expectedStageStatus);

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
TEST_F(APIDownloaderTest, TestHandleValidRequestWithCompressedDataAndInvalidOutputFolder)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/xz";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    const auto expectedStageStatus = R"(
        [
            {
                "stage": "APIDownloader",
                "status": "fail"
            }
        ]
    )"_json;

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, expectedStageStatus);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}

/**
 * @brief Tests handle an empty url.
 */
TEST_F(APIDownloaderTest, TestHandleAnEmptyUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    const auto expectedStageStatus = R"(
        [
            {
                "stage": "APIDownloader",
                "status": "fail"
            }
        ]
    )"_json;

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, expectedStageStatus);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}

/**
 * @brief Tests handle an invalid url.
 */
TEST_F(APIDownloaderTest, TestHandleAnInvalidUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "http://localhost:4444/invalid-url";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["outputFolder"] = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->outputFolder = "/tmp/invalid-folder";
    m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
    m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    const auto expectedStageStatus = R"(
        [
            {
                "stage": "APIDownloader",
                "status": "fail"
            }
        ]
    )"_json;

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    EXPECT_TRUE(m_spUpdaterContext->data.at("paths").empty());

    const auto stageStatus = m_spUpdaterContext->data.at("stageStatus");

    EXPECT_EQ(stageStatus, expectedStageStatus);

    const auto type = m_spUpdaterContext->data.at("type");

    EXPECT_EQ(type, DEFAULT_TYPE);
}
