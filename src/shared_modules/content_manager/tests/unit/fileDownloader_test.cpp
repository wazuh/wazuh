/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileDownloader_test.hpp"
#include "fakes/fakeServer.hpp"
#include "fileDownloader.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>
#include <stdexcept>

const auto OK_STATUS = R"({"stage":"FileDownloader","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"FileDownloader","status":"fail"})"_json;
const auto CONTENT_FILENAME_RAW = "raw";
const auto FILEHASH_RAW = "228458095a9502070fc113d99504226a6ff90a9a";
const auto CONTENT_FILENAME_XZ = "xz";
const auto FILEHASH_XZ = "89fe2d7ad5369373c4b96f8eeedd11d27ed3bc79";
const std::string BASE_URL = "localhost:4444/";

constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

void FileDownloaderTest::SetUpTestSuite()
{
    if (!m_spFakeServer)
    {
        m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
    }
}

void FileDownloaderTest::TearDownTestSuite()
{
    m_spFakeServer.reset();
}

void FileDownloaderTest::SetUp()
{
    m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);
    m_spUpdaterBaseContext->downloadsFolder = (m_outputFolder / "downloads").string();
    m_spUpdaterBaseContext->contentsFolder = (m_outputFolder / "contents").string();

    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    std::filesystem::create_directory(m_outputFolder);
    std::filesystem::create_directory(m_spUpdaterBaseContext->downloadsFolder);
    std::filesystem::create_directory(m_spUpdaterBaseContext->contentsFolder);
}

void FileDownloaderTest::TearDown()
{
    std::filesystem::remove_all(m_outputFolder);
}

/**
 * @brief Tests the instantiation of the class.
 *
 */
TEST_F(FileDownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(std::make_shared<FileDownloader>());
    EXPECT_NO_THROW(FileDownloader());
}

/**
 * @brief Tests the downloader with an invalid URL.
 *
 */
TEST_F(FileDownloaderTest, DownloadBadURL)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Set invalid config data. This will make the downloader to download from 'localhost:4444/invalid_file'.
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";
    m_spUpdaterBaseContext->configData["url"] = BASE_URL + "invalid_file";

    // Run downloader.
    ASSERT_THROW(FileDownloader().handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of a raw file.
 *
 */
TEST_F(FileDownloaderTest, DownloadRawFile)
{
    // Given that the file is not compressed, the download should be made into de 'contentsFolder'.
    const auto expectedFilepath {m_spUpdaterBaseContext->contentsFolder / CONTENT_FILENAME_RAW};

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedFilepath.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_RAW;

    // Set config data. This will make the downloader to download from 'localhost:4444/raw'.
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";
    m_spUpdaterBaseContext->configData["url"] = BASE_URL + CONTENT_FILENAME_RAW;

    // Run downloader.
    ASSERT_NO_THROW(FileDownloader().handleRequest(m_spUpdaterContext));

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check downloaded file exists.
    EXPECT_TRUE(std::filesystem::exists(expectedFilepath));
}

/**
 * @brief Tests the download of a compressed file.
 *
 */
TEST_F(FileDownloaderTest, DownloadCompressedFile)
{
    // Given that the file is compressed, the download should be made into de 'downloadsFolder'.
    const auto expectedFilepath {m_spUpdaterBaseContext->downloadsFolder / CONTENT_FILENAME_XZ};

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedFilepath.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_XZ;

    // Set config data. This will make the downloader to download from 'localhost:4444/xz'.
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["url"] = BASE_URL + CONTENT_FILENAME_XZ;

    // Run downloader.
    ASSERT_NO_THROW(FileDownloader().handleRequest(m_spUpdaterContext));

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check downloaded file exists.
    EXPECT_TRUE(std::filesystem::exists(expectedFilepath));
}

/**
 * @brief Tests two downloads in a row of the same file.
 *
 */
TEST_F(FileDownloaderTest, DownloadSameFileTwice)
{
    // Given that the file is compressed, the download should be made into de 'downloadsFolder'.
    const auto expectedFilepath {m_spUpdaterBaseContext->downloadsFolder / CONTENT_FILENAME_XZ};

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedFilepath.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_XZ;

    // Set config data. This will make the downloader to download from 'localhost:4444/xz'.
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->configData["url"] = BASE_URL + CONTENT_FILENAME_XZ;

    // Run downloader. First download.
    EXPECT_NO_THROW(FileDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedFilepath));

    // Reset context.
    m_spUpdaterContext.reset(new UpdaterContext());
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    // Run downloader. Second download. Same file as before.
    EXPECT_NO_THROW(FileDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the downloader with an URL without filename.
 *
 */
TEST_F(FileDownloaderTest, DownloadURLWithoutFilename)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Set invalid config data. This will make the downloader to download from 'localhost:4444/'.
    m_spUpdaterBaseContext->configData["url"] = BASE_URL;

    // Run downloader.
    ASSERT_THROW(FileDownloader().handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
