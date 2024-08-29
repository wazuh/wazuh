/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "XZDecompressor_test.hpp"
#include "XZDecompressor.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

// Expected stage status.
static const auto OK_STATUS = R"({"stage":"XZDecompressor","status":"ok"})"_json;
static const auto FAIL_STATUS = R"({"stage":"XZDecompressor","status":"fail"})"_json;

static constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

// Paths used on tests.
static const std::filesystem::path INPUT_FILES_FOLDER {std::filesystem::current_path() / "input_files" /
                                                       "xzDecompressor"};
static const std::filesystem::path SAMPLE_A_INPUT_FILE {INPUT_FILES_FOLDER / "downloads" / "sample_a.json.xz"};
static const std::filesystem::path SAMPLE_B_INPUT_FILE {INPUT_FILES_FOLDER / "downloads" / "sample_b.json.xz"};
static const std::filesystem::path CONTENT_FOLDER {INPUT_FILES_FOLDER / "contents"};
static const std::filesystem::path SAMPLE_A_OUTPUT_FILE {CONTENT_FOLDER / "sample_a.json"};
static const std::filesystem::path SAMPLE_B_OUTPUT_FILE {CONTENT_FOLDER / "sample_b.json"};

void XZDecompressorTest::SetUp()
{
    m_spUpdaterContext = std::make_shared<UpdaterContext>();
    m_spUpdaterContext->spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);
    // The input files folder simulates the Content Manager output folder.
    m_spUpdaterContext->spUpdaterBaseContext->outputFolder = INPUT_FILES_FOLDER;

    std::filesystem::create_directory(CONTENT_FOLDER);
}

void XZDecompressorTest::TearDown()
{
    std::filesystem::remove_all(CONTENT_FOLDER);
}

/**
 * @brief Tests the correct instantiation of the class.
 *
 */
TEST_F(XZDecompressorTest, Instantiation)
{
    EXPECT_NO_THROW(XZDecompressor());
    EXPECT_NO_THROW(std::make_shared<XZDecompressor>());
}

/**
 * @brief Tests the decompression of no files.
 *
 */
TEST_F(XZDecompressorTest, DecompressNoFiles)
{
    ASSERT_NO_THROW(XZDecompressor().handleRequest(m_spUpdaterContext));

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the correct decompression of one file.
 *
 */
TEST_F(XZDecompressorTest, DecompressOneFile)
{
    m_spUpdaterContext->data.at("paths").push_back(SAMPLE_A_INPUT_FILE);

    ASSERT_NO_THROW(XZDecompressor().handleRequest(m_spUpdaterContext));

    nlohmann::json expectedData;
    expectedData["paths"] = nlohmann::json::array();
    expectedData["paths"].push_back(SAMPLE_A_OUTPUT_FILE);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(SAMPLE_A_OUTPUT_FILE));
}

/**
 * @brief Tests the correct decompression of two files.
 *
 */
TEST_F(XZDecompressorTest, DecompressTwoFiles)
{
    m_spUpdaterContext->data.at("paths").push_back(SAMPLE_A_INPUT_FILE);
    m_spUpdaterContext->data.at("paths").push_back(SAMPLE_B_INPUT_FILE);

    ASSERT_NO_THROW(XZDecompressor().handleRequest(m_spUpdaterContext));

    nlohmann::json expectedData;
    expectedData["paths"] = nlohmann::json::array();
    expectedData["paths"].push_back(SAMPLE_A_OUTPUT_FILE);
    expectedData["paths"].push_back(SAMPLE_B_OUTPUT_FILE);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
    EXPECT_TRUE(std::filesystem::exists(SAMPLE_A_OUTPUT_FILE));
    EXPECT_TRUE(std::filesystem::exists(SAMPLE_B_OUTPUT_FILE));
}

/**
 * @brief Tests the decompression of an inexistant file.
 *
 */
TEST_F(XZDecompressorTest, DecompressInexistantFileThrows)
{
    m_spUpdaterContext->data.at("paths").push_back("inexistant_file.xz");

    EXPECT_THROW(XZDecompressor().handleRequest(m_spUpdaterContext), std::runtime_error);

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}

/**
 * @brief Tests the decompression of two files, one inexistant.
 *
 */
TEST_F(XZDecompressorTest, DecompressTwoFilesOneInexistantThrows)
{
    m_spUpdaterContext->data.at("paths").push_back(SAMPLE_B_INPUT_FILE);
    m_spUpdaterContext->data.at("paths").push_back("inexistant_file.xz");

    EXPECT_THROW(XZDecompressor().handleRequest(m_spUpdaterContext), std::runtime_error);

    nlohmann::json expectedData;
    expectedData["paths"] = m_spUpdaterContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    EXPECT_EQ(m_spUpdaterContext->data, expectedData);
}
