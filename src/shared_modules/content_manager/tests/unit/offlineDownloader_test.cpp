/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "offlineDownloader_test.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <memory>

const auto OK_STATUS = R"({"stage":"OfflineDownloader","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"OfflineDownloader","status":"fail"})"_json;

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(OfflineDownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(OfflineDownloader());
    EXPECT_NO_THROW(std::make_shared<OfflineDownloader>());
}

/**
 * @brief Tests the download a raw file. The expected output folder is the contents one.
 *
 */
TEST_F(OfflineDownloaderTest, RawFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));
}

/**
 * @brief Tests the download a compressed file. The expected output folder is the downloads one.
 *
 */
TEST_F(OfflineDownloaderTest, CompressedFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = m_inputFilePathCompressed.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "gzip";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->downloadsFolder.string() + "/" +
                                    m_inputFilePathCompressed.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(
        std::filesystem::exists(m_spUpdaterBaseContext->downloadsFolder / m_inputFilePathCompressed.filename()));
}

/**
 * @brief Tests the download of an inexistant file. Exception is expected, as well as a fail stage status.
 *
 */
TEST_F(OfflineDownloaderTest, InexistantFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = "file://" + m_tempPath.string() + "/inexistant.txt";
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);

    ASSERT_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests two downloads in a row of the same file. The second download should not add the filepath to the data
 * paths.
 *
 */
TEST_F(OfflineDownloaderTest, SkipFileProcessing)
{
    m_spUpdaterBaseContext->configData["url"] = m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));

    // Reset context.
    m_spUpdaterContext.reset(new UpdaterContext());
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    // No paths are expected.
    expectedData.at("paths").clear();

    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests two downloads one after the other. The file from the second download is different from the prior so the
 * output file gets overrided.
 *
 */
TEST_F(OfflineDownloaderTest, TwoFileDownloadsOverrideOutput)
{
    m_spUpdaterBaseContext->configData["url"] = m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);

    // Trigger first download.
    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));

    // Change input file content.
    std::ofstream testFileStream {m_inputFilePathRaw};
    testFileStream << "I'm a test file with a .txt extension and I will override the output file." << std::endl;
    testFileStream.close();

    // Clear first execution data.
    m_spUpdaterContext->data.at("stageStatus").clear();
    m_spUpdaterContext->data.at("paths").clear();

    // Trigger second download.
    ASSERT_NO_THROW(OfflineDownloader().handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));
}
