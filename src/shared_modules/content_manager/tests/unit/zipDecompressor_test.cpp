/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * November 03, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zipDecompressor_test.hpp"
#include "json.hpp"
#include "zipDecompressor.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>
#include <vector>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

// Folder containing all the input files.
const auto INPUT_FILES_DIR {std::filesystem::current_path() / "input_files" / "zipDecompressor"};

// Zip file containing ZIP_CONTENT_A_EXPECTED_FILES files.
const auto ZIP_CONTENT_A {INPUT_FILES_DIR / "content_a.zip"};
const std::vector<std::filesystem::path> ZIP_CONTENT_A_EXPECTED_FILES {{EXPECTED_CONTENTS_FOLDER / "content.xml"}};

// Zip file containing ZIP_CONTENT_B_EXPECTED_FILES files.
const auto ZIP_CONTENT_B {INPUT_FILES_DIR / "content_b.zip"};
const std::vector<std::filesystem::path> ZIP_CONTENT_B_EXPECTED_FILES {{EXPECTED_CONTENTS_FOLDER / "content_a.json"},
                                                                       {EXPECTED_CONTENTS_FOLDER / "content_b.json"}};

// Empty zip file.
const auto ZIP_EMPTY {INPUT_FILES_DIR / "empty.zip"};

// Expected stage status.
const auto OK_STATUS = R"({"stage":"ZipDecompressor","status":"ok"})"_json;
const auto FAIL_STATUS = R"({"stage":"ZipDecompressor","status":"fail"})"_json;

constexpr auto DEFAULT_TYPE {"raw"}; ///< Default content type.

/**
 * @brief Tests the correct class instantiation.
 *
 */
TEST_F(ZipDecompressorTest, ClassInstantiation)
{
    EXPECT_NO_THROW(std::make_shared<ZipDecompressor>());
    EXPECT_NO_THROW(ZipDecompressor());
}

/**
 * @brief Tests the decompression of no files.
 *
 */
TEST_F(ZipDecompressorTest, DecompressNoFile)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    ASSERT_NO_THROW(ZipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);
}

/**
 * @brief Tests the decompression of a zip file that contains one file inside.
 *
 */
TEST_F(ZipDecompressorTest, DecompressOneZipOneFile)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = ZIP_CONTENT_A_EXPECTED_FILES;
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Set input files.
    m_spContext->data.at("paths").push_back(ZIP_CONTENT_A);

    // Run decompression.
    ASSERT_NO_THROW(ZipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check that the expected files exist.
    for (const auto& expectedPath : ZIP_CONTENT_A_EXPECTED_FILES)
    {
        EXPECT_TRUE(std::filesystem::exists(expectedPath));
    }
}

/**
 * @brief Tests the decompression of a zip file that contains two files inside.
 *
 */
TEST_F(ZipDecompressorTest, DecompressOneZipTwoFiles)
{
    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = ZIP_CONTENT_B_EXPECTED_FILES;
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Set input files.
    m_spContext->data.at("paths").push_back(ZIP_CONTENT_B);

    // Run decompression.
    ASSERT_NO_THROW(ZipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check that the expected files exist.
    for (const auto& expectedPath : ZIP_CONTENT_B_EXPECTED_FILES)
    {
        EXPECT_TRUE(std::filesystem::exists(expectedPath));
    }
}

/**
 * @brief Tests the decompression of two zip files.
 *
 */
TEST_F(ZipDecompressorTest, DecompressTwoZips)
{
    // Set up expected paths.
    auto expectedPaths {ZIP_CONTENT_A_EXPECTED_FILES};
    expectedPaths.insert(expectedPaths.end(), ZIP_CONTENT_B_EXPECTED_FILES.begin(), ZIP_CONTENT_B_EXPECTED_FILES.end());

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = expectedPaths;
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(OK_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Set input files.
    m_spContext->data.at("paths").push_back(ZIP_CONTENT_A);
    m_spContext->data.at("paths").push_back(ZIP_CONTENT_B);

    // Run decompression.
    ASSERT_NO_THROW(ZipDecompressor().handleRequest(m_spContext));

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);

    // Check that the expected files exist.
    for (const auto& expectedPath : expectedPaths)
    {
        EXPECT_TRUE(std::filesystem::exists(expectedPath));
    }
}

/**
 * @brief Tests the decompression of an inexistant file.
 *
 */
TEST_F(ZipDecompressorTest, DecompressInexistantFile)
{
    // Set input invalid file.
    m_spContext->data.at("paths").push_back("inexistant_file.zip");

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    EXPECT_THROW(ZipDecompressor().handleRequest(m_spContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);
}

/**
 * @brief Tests the decompression of an empty zip file.
 *
 */
TEST_F(ZipDecompressorTest, DecompressEmptyZip)
{
    // Set input empty zip file.
    m_spContext->data.at("paths").push_back(ZIP_EMPTY);

    // Set up expected data.
    nlohmann::json expectedData;
    expectedData["paths"] = m_spContext->data.at("paths");
    expectedData["stageStatus"] = nlohmann::json::array();
    expectedData["stageStatus"].push_back(FAIL_STATUS);
    expectedData["type"] = DEFAULT_TYPE;
    expectedData["offset"] = 0;

    // Run decompression.
    EXPECT_THROW(ZipDecompressor().handleRequest(m_spContext), std::runtime_error);

    // Check expected data.
    EXPECT_EQ(m_spContext->data, expectedData);
}
