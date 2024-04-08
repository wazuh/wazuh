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
#include "HTTPRequest.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

const auto OK_STATUS = R"({"stage":"OfflineDownloader","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"OfflineDownloader","status":"fail"})"_json;

constexpr auto FILE_PREFIX {"file://"};
constexpr auto HTTP_PREFIX {"http://"};

const auto CONTENT_FILENAME_RAW = "raw";
const auto FILEHASH_RAW = "228458095a9502070fc113d99504226a6ff90a9a";
const auto CONTENT_FILENAME_XZ = "xz";
const auto FILEHASH_XZ = "89fe2d7ad5369373c4b96f8eeedd11d27ed3bc79";
const std::string BASE_URL = "localhost:4444/";

constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(OfflineDownloaderTest, Instantiation)
{
    EXPECT_NO_THROW(OfflineDownloader(HTTPRequest::instance()));
    EXPECT_NO_THROW(std::make_shared<OfflineDownloader>(HTTPRequest::instance()));
}

/**
 * @brief Tests the download a raw file. The expected output folder is the contents one.
 *
 */
TEST_F(OfflineDownloaderTest, RawFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = m_inputFileHashRaw;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));
}

/**
 * @brief Tests the download a compressed file. The expected output folder is the downloads one.
 *
 */
TEST_F(OfflineDownloaderTest, CompressedFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_inputFilePathCompressed.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "gzip";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->downloadsFolder.string() + "/" +
                                    m_inputFilePathCompressed.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = m_inputFileHashCompressed;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(
        std::filesystem::exists(m_spUpdaterBaseContext->downloadsFolder / m_inputFilePathCompressed.filename()));
}

/**
 * @brief Tests the download of an inexistant file.
 *
 */
TEST_F(OfflineDownloaderTest, InexistantFileDownload)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_tempPath.string() + "/inexistant.txt";
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests two downloads in a row of the same file.
 *
 */
TEST_F(OfflineDownloaderTest, DownloadSameFileTwice)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = m_inputFileHashRaw;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));

    // Reset context.
    m_spUpdaterContext.reset(new UpdaterContext());
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests two downloads one after the other. The file from the second download should override the first one.
 *
 */
TEST_F(OfflineDownloaderTest, TwoFileDownloadsOverrideOutput)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    // Set expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(m_spUpdaterBaseContext->contentsFolder.string() + "/" +
                                    m_inputFilePathRaw.filename().string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = m_inputFileHashRaw;

    // Trigger first download.
    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
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
    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));

    // The new hash should be different from the first one.
    auto newHash {m_spUpdaterContext->data.at("fileMetadata").at("hash").get<std::string>()};
    EXPECT_NE(newHash, m_inputFileHashRaw);
    expectedData["fileMetadata"]["hash"] = std::move(newHash);

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(m_spUpdaterBaseContext->contentsFolder / m_inputFilePathRaw.filename()));
}

/**
 * @brief Tests the download of a raw file with an inexistant content folder. Exception is expected.
 *
 */
TEST_F(OfflineDownloaderTest, InexistantContentFolder)
{
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + m_inputFilePathRaw.string();
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";
    m_spUpdaterBaseContext->contentsFolder = m_outputFolder / "inexistantFolder";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of a raw file from an HTTP server.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadRawFile)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + CONTENT_FILENAME_RAW;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    const auto expectedOutputFile {m_spUpdaterBaseContext->contentsFolder.string() + "/" + CONTENT_FILENAME_RAW};

    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedOutputFile);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_RAW;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));
}

/**
 * @brief Tests the download of a compressed file from an HTTP server.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadCompressedFile)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + CONTENT_FILENAME_XZ;
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";

    const auto expectedOutputFile {m_spUpdaterBaseContext->downloadsFolder.string() + "/" + CONTENT_FILENAME_XZ};

    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedOutputFile);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_XZ;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));
}

/**
 * @brief Tests the download from an HTTP URL without filename.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadFileWithoutFilename)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download from an URL with an unsupported prefix.
 *
 */
TEST_F(OfflineDownloaderTest, DownloadUnknownPrefixedFile)
{
    m_spUpdaterBaseContext->configData["url"] = "prefix://" + BASE_URL + CONTENT_FILENAME_XZ;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext), std::runtime_error);
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of a raw file from an HTTP server, overriding an existing one.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadRawFileOverride)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + CONTENT_FILENAME_RAW;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    const auto expectedOutputFile {m_spUpdaterBaseContext->contentsFolder.string() + "/" + CONTENT_FILENAME_RAW};

    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedOutputFile);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_RAW;

    // Create dummy file in the expected output path.
    std::ofstream testFileStream {expectedOutputFile};
    testFileStream << "I will be overridden :(" << std::endl;
    testFileStream.close();

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));
}

/**
 * @brief Tests the download from an invalid HTTP URL.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadInvalidURL)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + "invalid";
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the download of the same file twice from an HTTP server.
 *
 */
TEST_F(OfflineDownloaderTest, HttpDownloadFileTwice)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + CONTENT_FILENAME_RAW;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    const auto expectedOutputFile {m_spUpdaterBaseContext->contentsFolder.string() + "/" + CONTENT_FILENAME_RAW};

    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedOutputFile);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_RAW;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));

    // Clear first execution data.
    m_spUpdaterContext->data.at("stageStatus").clear();
    m_spUpdaterContext->data.at("paths").clear();

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));
}

/**
 * @brief Tests the download of the same file twice. Once from an HTTP server, and once from the local filesystem.
 *
 */
TEST_F(OfflineDownloaderTest, HttpAndLocalDownloadFileTwice)
{
    m_spUpdaterBaseContext->configData["url"] = HTTP_PREFIX + BASE_URL + CONTENT_FILENAME_RAW;
    m_spUpdaterBaseContext->configData["compressionType"] = "raw";

    const auto expectedOutputFile {m_spUpdaterBaseContext->contentsFolder.string() + "/" + CONTENT_FILENAME_RAW};

    nlohmann::json expectedData;
    expectedData["paths"].push_back(expectedOutputFile);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;
    expectedData["fileMetadata"]["hash"] = FILEHASH_RAW;

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(expectedOutputFile));

    // Clear first execution data.
    m_spUpdaterContext->data.at("stageStatus").clear();
    m_spUpdaterContext->data.at("paths").clear();

    // Create local file with the same content as the downloaded one.
    const auto inputLocalFile {m_outputFolder / CONTENT_FILENAME_RAW};
    std::filesystem::copy(expectedOutputFile, inputLocalFile);
    m_spUpdaterBaseContext->configData["url"] = FILE_PREFIX + inputLocalFile.string();

    ASSERT_NO_THROW(OfflineDownloader(HTTPRequest::instance()).handleRequest(m_spUpdaterContext));
    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
