/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gzipDecompressor_test.hpp"
#include "gzipDecompressor.hpp"
#include "json.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

const auto INPUT_SAMPLE_A_FILE_PATH {INPUT_FILES_DIR / "sample_a.json.gz"};
const auto INPUT_SAMPLE_B_FILE_PATH {INPUT_FILES_DIR / "sample_b.json.gz"};
const auto INPUT_INEXISTANT_FILE_PATH {INPUT_FILES_DIR / "inexistant.xml.gz"};

const auto OK_STATUS = R"({"stage":"GzipDecompressor","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"GzipDecompressor","status":"fail"})"_json;

constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

/**
 * @brief Test the correct instantiation of the class.
 *
 */
TEST_F(GzipDecompressorTest, ClassInstantiation)
{
    EXPECT_NO_THROW(std::make_shared<GzipDecompressor>());
    EXPECT_NO_THROW(GzipDecompressor());
}

/**
 * @brief Test the decompression of no file.
 *
 */
TEST_F(GzipDecompressorTest, DecompressNoFile)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_NO_THROW(GzipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);
}

/**
 * @brief Test the successful decompression of one file.
 *
 */
TEST_F(GzipDecompressorTest, DecompressOneFile)
{
    // Set up input paths.
    m_spContext->data.at("paths").push_back(INPUT_SAMPLE_A_FILE_PATH.string());

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(OUTPUT_SAMPLE_A_FILE_PATH.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_NO_THROW(GzipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check output file.
    EXPECT_TRUE(std::filesystem::exists(OUTPUT_SAMPLE_A_FILE_PATH));
}

/**
 * @brief Test the successful decompression of two files.
 *
 */
TEST_F(GzipDecompressorTest, DecompressTwoFiles)
{
    // Set up input paths.
    m_spContext->data.at("paths").push_back(INPUT_SAMPLE_A_FILE_PATH.string());
    m_spContext->data.at("paths").push_back(INPUT_SAMPLE_B_FILE_PATH.string());

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(OUTPUT_SAMPLE_A_FILE_PATH.string());
    expectedData["paths"].push_back(OUTPUT_SAMPLE_B_FILE_PATH.string());
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_NO_THROW(GzipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check output files.
    EXPECT_TRUE(std::filesystem::exists(OUTPUT_SAMPLE_A_FILE_PATH));
    EXPECT_TRUE(std::filesystem::exists(OUTPUT_SAMPLE_B_FILE_PATH));
}

/**
 * @brief Test the failed decompression of an invalid file.
 *
 */
TEST_F(GzipDecompressorTest, DecompressInexistantFile)
{
    // Set up input paths.
    m_spContext->data.at("paths").push_back(INPUT_INEXISTANT_FILE_PATH.string());

    // Set up expected data. 'paths' should remain unchanged.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_THROW(GzipDecompressor().handleRequest(m_spContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);
}

/**
 * @brief Test the failed decompression of one correct and one invalid file.
 *
 */
TEST_F(GzipDecompressorTest, DecompressTwoFilesOneInexistant)
{
    // Set up input paths.
    m_spContext->data.at("paths").push_back(INPUT_SAMPLE_A_FILE_PATH.string());
    m_spContext->data.at("paths").push_back(INPUT_INEXISTANT_FILE_PATH.string());

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"].push_back(OUTPUT_SAMPLE_A_FILE_PATH.string());
    expectedData["paths"].push_back(INPUT_INEXISTANT_FILE_PATH);
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_THROW(GzipDecompressor().handleRequest(m_spContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check output file.
    EXPECT_TRUE(std::filesystem::exists(OUTPUT_SAMPLE_A_FILE_PATH));
}
