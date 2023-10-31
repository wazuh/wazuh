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

#include "S3Downloader_test.hpp"
#include "S3Downloader.hpp"
#include "fakes/fakeServer.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include <memory>
#include <stdexcept>

const auto OK_STATUS = R"({"stage":"S3Downloader","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"S3Downloader","status":"fail"})"_json;

void S3DownloaderTest::SetUpTestSuite()
{
    if (!m_spFakeServer)
    {
        m_spFakeServer = std::make_unique<FakeServer>("localhost", 4444);
    }
}

void S3DownloaderTest::TearDownTestSuite()
{
    m_spFakeServer.reset();
}

void S3DownloaderTest::SetUp()
{
    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>();
    m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder = (m_outputFolder / "downloads").string();
    m_spUpdaterContext->spUpdaterBaseContext->contentsFolder = (m_outputFolder / "contents").string();

    std::filesystem::create_directory(m_outputFolder);
    std::filesystem::create_directory(m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder);
    std::filesystem::create_directory(m_spUpdaterContext->spUpdaterBaseContext->contentsFolder);
}

void S3DownloaderTest::TearDown()
{
    std::filesystem::remove_all(m_outputFolder);
}

/**
 * @brief Tests the instantiation of the class.
 *
 */
TEST_F(S3DownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(std::make_shared<S3Downloader>());
    EXPECT_NO_THROW(S3Downloader());
}

/**
 * @brief Tests the downloader with an invalid URL.
 *
 */
TEST_F(S3DownloaderTest, DownloadBadURL)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);

    // Set invalid config data.
    m_spUpdaterContext->spUpdaterBaseContext->configData["url"] = "localhost:999999";
    m_spUpdaterContext->spUpdaterBaseContext->configData["compressionType"] = "raw";
    m_spUpdaterContext->spUpdaterBaseContext->configData["s3FileName"] = "filename";

    // Run downloader.
    ASSERT_THROW(S3Downloader().handleRequest(m_spUpdaterContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of a raw file.
 *
 */
TEST_F(S3DownloaderTest, DownloadRawFile)
{
    // Given that the file is not compressed, the download should be made into de 'contentsFolder'.
    const auto expectedFilepath {m_spUpdaterContext->spUpdaterBaseContext->contentsFolder / "raw"};

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedFilepath.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    // Set config data. This will make the downloader to download from 'localhost:4444/raw'.
    m_spUpdaterContext->spUpdaterBaseContext->configData["url"] = "localhost:4444/";
    m_spUpdaterContext->spUpdaterBaseContext->configData["compressionType"] = "raw";
    m_spUpdaterContext->spUpdaterBaseContext->configData["s3FileName"] = "raw";

    // Run downloader.
    ASSERT_NO_THROW(S3Downloader().handleRequest(m_spUpdaterContext));

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check downloaded file exists.
    EXPECT_TRUE(std::filesystem::exists(expectedFilepath));
}

/**
 * @brief Tests the download of a compressed file.
 *
 */
TEST_F(S3DownloaderTest, DownloadCompressedFile)
{
    // Given that the file is compressed, the download should be made into de 'downloadsFolder'.
    const auto expectedFilepath {m_spUpdaterContext->spUpdaterBaseContext->downloadsFolder / "xz"};

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedFilepath.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    // Set config data. This will make the downloader to download from 'localhost:4444/xz'.
    m_spUpdaterContext->spUpdaterBaseContext->configData["url"] = "localhost:4444/";
    m_spUpdaterContext->spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterContext->spUpdaterBaseContext->configData["s3FileName"] = "xz";

    // Run downloader.
    ASSERT_NO_THROW(S3Downloader().handleRequest(m_spUpdaterContext));

    // Check expected data.
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);

    // Check downloaded file exists.
    EXPECT_TRUE(std::filesystem::exists(expectedFilepath));
}
