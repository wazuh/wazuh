/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "zlibHelper_test.hpp"
#include "hashHelper.h"
#include "stringHelper.h"
#include "zlibHelper.hpp"
#include "gtest/gtest.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>

const auto INPUT_FILES_DIR {std::filesystem::current_path() / "input_files" / "zlibHelper"};

// Not compressed file.
const auto RAW_FILE {INPUT_FILES_DIR / "not_compressed.json"};

// Compressed files containing JSON_FILE.
const auto GZ_FILE {INPUT_FILES_DIR / "sample.json.gz"};
const auto ZIP_FILE {INPUT_FILES_DIR / "sample.zip"};

// JSON file whose hash is SHA1_EXPECTED.
const auto JSON_FILE {OUTPUT_DIR / "sample.json"};
const auto SHA1_EXPECTED {"98bf22d47ff4a9279ab98a2b224d9333f4272618"};

// ZIP file contaning the following files:
// file_a.xml
// file_b.xml
// file_c.xml
const auto ZIP_MULTIPLE_FILES {INPUT_FILES_DIR / "multiple_files.zip"};

// ZIP file contaning the following files:
// xml_files
// ├── file_a.xml
// ├── file_b.xml
// └── file_c.xml
const auto ZIP_FOLDER {INPUT_FILES_DIR / "xml_files.zip"};

// ZIP file contaning the following files:
// root_folder
// ├── sample.json
// └── xml_files
//     ├── file_a.xml
//     ├── file_b.xml
//     └── file_c.xml
const auto ZIP_NESTED_FOLDER {INPUT_FILES_DIR / "nested.zip"};

// Empty ZIP file.
const auto ZIP_EMPTY {INPUT_FILES_DIR / "empty.zip"};

// XML files with their respective SHA1 hashes.
const std::map<std::filesystem::path, std::string> XML_DECOMPRESSED {
    {"file_a.xml", "96e78ae9399e8a96dfab08b9afaa0ffba6952f52"},
    {"file_b.xml", "2d3db885dbb2851fe2f7ff268b79779e938a0180"},
    {"file_c.xml", "7c27115c9f9bf0249b4d69bf01b631ef494c23d3"}};

// Folder names used for tests.
const auto XML_FOLDER {"xml_files"};
const auto ROOT_FOLDER {"root_folder"};

// TXT filename used for tests.
const auto TXT_FILE {"supermarket_list.txt"};

std::string ZlibHelperTest::getFileHash(const std::filesystem::path& filepath) const
{
    std::fstream file(filepath, std::fstream::in);
    std::string buffer {};
    getline(file, buffer, '\0');
    file.close();

    Utils::HashData hash;
    hash.update(buffer.c_str(), buffer.size());
    return Utils::asciiToHex(hash.hash());
};

/**
 * @brief Tests the GZ compression when the input file is empty or it doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, GzCompressInvalidInputFile)
{
    const auto outputGzFile = OUTPUT_DIR / "test_output.gz";
    EXPECT_THROW(Utils::ZlibHelper::gzipCompress("", outputGzFile), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipCompress("inexistant.json", outputGzFile), std::runtime_error);
}

/**
 * @brief Tests the GZ compression when the output path doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, GzCompressInvalidOutputPath)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, "inexistant/test.gz"), std::runtime_error);
}

/**
 * @brief Tests the GZ compression with invalid compression levels.
 *
 */
TEST_F(ZlibHelperTest, GzCompressInvalidCompressionLevel)
{
    const auto outputGzFile = OUTPUT_DIR / "test_output.gz";
    EXPECT_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputGzFile, -1), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputGzFile, 10), std::runtime_error);
}

/**
 * @brief Tests the correct GZ compression of a file with default compression level.
 *
 */
TEST_F(ZlibHelperTest, GzCompressFileDefault)
{
    const auto outputGzFile = OUTPUT_DIR / "test_compressed.gz";
    const auto decompressedFile = OUTPUT_DIR / "test_decompressed.json";

    // Compress the file
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputGzFile));

    // Verify the compressed file exists and is not empty
    ASSERT_TRUE(std::filesystem::exists(outputGzFile));
    ASSERT_GT(std::filesystem::file_size(outputGzFile), 0);

    // Decompress the file and verify it matches the original
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipDecompress(outputGzFile, decompressedFile));
    EXPECT_EQ(getFileHash(RAW_FILE), getFileHash(decompressedFile));
}

/**
 * @brief Tests the correct GZ compression of a file with different compression levels.
 *
 */
TEST_F(ZlibHelperTest, GzCompressFileWithDifferentLevels)
{
    const auto decompressedFile = OUTPUT_DIR / "test_decompressed.json";
    std::vector<std::pair<int, std::filesystem::path>> testCases = {
        {0, OUTPUT_DIR / "test_compressed_level0.gz"},
        {1, OUTPUT_DIR / "test_compressed_level1.gz"},
        {6, OUTPUT_DIR / "test_compressed_level6.gz"},
        {9, OUTPUT_DIR / "test_compressed_level9.gz"}
    };

    for (const auto& [level, outputFile] : testCases)
    {
        // Compress the file with specific level
        ASSERT_NO_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputFile, level));

        // Verify the compressed file exists and is not empty
        ASSERT_TRUE(std::filesystem::exists(outputFile));
        ASSERT_GT(std::filesystem::file_size(outputFile), 0);

        // Decompress the file and verify it matches the original
        const auto decompressedTestFile = OUTPUT_DIR / ("decompressed_level" + std::to_string(level) + ".json");
        ASSERT_NO_THROW(Utils::ZlibHelper::gzipDecompress(outputFile, decompressedTestFile));
        EXPECT_EQ(getFileHash(RAW_FILE), getFileHash(decompressedTestFile));
    }
}

/**
 * @brief Tests that higher compression levels produce smaller files.
 *
 */
TEST_F(ZlibHelperTest, GzCompressLevelsProduceDifferentSizes)
{
    const auto outputLevel0 = OUTPUT_DIR / "test_level0.gz";
    const auto outputLevel9 = OUTPUT_DIR / "test_level9.gz";

    // Compress with minimum compression (level 0)
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputLevel0, 0));

    // Compress with maximum compression (level 9)
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipCompress(RAW_FILE, outputLevel9, 9));

    // Verify both files exist
    ASSERT_TRUE(std::filesystem::exists(outputLevel0));
    ASSERT_TRUE(std::filesystem::exists(outputLevel9));

    // Level 9 should produce a smaller or equal file than level 0
    EXPECT_LE(std::filesystem::file_size(outputLevel9), std::filesystem::file_size(outputLevel0));
}

/**
 * @brief Tests the GZ decompression when the input file is empty or it doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, GzInvalidInputFile)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress("", JSON_FILE), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress("inexistant.xml.gz", JSON_FILE), std::runtime_error);
}

/**
 * @brief Tests the GZ decompression when the output file is empty or the path doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, GzInvalidOutputFile)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(GZ_FILE, ""), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(GZ_FILE, "inexistant/sample.json"), std::runtime_error);
}

/**
 * @brief Tests the correct GZ decompression of a file.
 *
 */
TEST_F(ZlibHelperTest, GzDecompressFile)
{
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipDecompress(GZ_FILE, JSON_FILE));

    // Check the expected hash.
    EXPECT_EQ(SHA1_EXPECTED, getFileHash(JSON_FILE));
}

/**
 * @brief Tests the GZ decompression of a file whose format is not '.gz'.
 *
 */
TEST_F(ZlibHelperTest, GzDecompressFileWithoutGzExtension)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(RAW_FILE, JSON_FILE), std::runtime_error);
}

/**
 * @brief Tests the ZIP decompression when the input file is empty or it doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, ZipInvalidInputFile)
{
    EXPECT_THROW(Utils::ZlibHelper::zipDecompress("", OUTPUT_DIR), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::zipDecompress("inexistant.xml.gz", OUTPUT_DIR), std::runtime_error);
}

/**
 * @brief Tests the ZIP decompression when the output directory doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, ZipInvalidOutputDir)
{
    EXPECT_THROW(Utils::ZlibHelper::zipDecompress(ZIP_FILE, "inexistant/"), std::runtime_error);
}

/**
 * @brief Tests the correct ZIP decompression of a file.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressOneFile)
{
    const std::vector<std::string> expectedDecompressedFiles {{JSON_FILE}};
    EXPECT_EQ(expectedDecompressedFiles, Utils::ZlibHelper::zipDecompress(ZIP_FILE, OUTPUT_DIR));

    // Check the expected hash.
    EXPECT_EQ(SHA1_EXPECTED, getFileHash(JSON_FILE));
}

/**
 * @brief Tests the correct ZIP decompression of a file that contains multiple compressed files.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressMultipleFiles)
{
    // Set expected output files.
    std::vector<std::string> expectedDecompressedFiles;
    for (const auto& entry : XML_DECOMPRESSED)
    {
        expectedDecompressedFiles.push_back(OUTPUT_DIR / entry.first.string());
    }

    // Decompress and compare output files.
    ASSERT_EQ(expectedDecompressedFiles, Utils::ZlibHelper::zipDecompress(ZIP_MULTIPLE_FILES, OUTPUT_DIR));

    // Check the expected hashes.
    for (const auto& filepath : expectedDecompressedFiles)
    {
        EXPECT_EQ(XML_DECOMPRESSED.at(std::filesystem::path(filepath).filename()), getFileHash(filepath));
    }
}

/**
 * @brief Tests the ZIP decompression of a not compressed file.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressNotCompressedFile)
{
    EXPECT_THROW(Utils::ZlibHelper::zipDecompress(RAW_FILE, OUTPUT_DIR), std::runtime_error);
}

/**
 * @brief Tests the correct ZIP decompression of a compressed folder.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressFolder)
{
    // Set expected output files.
    std::vector<std::string> expectedDecompressedFiles;
    for (const auto& entry : XML_DECOMPRESSED)
    {
        expectedDecompressedFiles.push_back(OUTPUT_DIR / XML_FOLDER / entry.first.string());
    }

    // Decompress.
    std::vector<std::string> decompressedFiles;
    ASSERT_NO_THROW({ decompressedFiles = Utils::ZlibHelper::zipDecompress(ZIP_FOLDER, OUTPUT_DIR); });

    // Sort decompressed files to properly compare them.
    std::sort(decompressedFiles.begin(), decompressedFiles.end());
    EXPECT_EQ(expectedDecompressedFiles, decompressedFiles);

    // Check the expected hashes.
    for (const auto& filepath : expectedDecompressedFiles)
    {
        EXPECT_EQ(XML_DECOMPRESSED.at(std::filesystem::path(filepath).filename()), getFileHash(filepath));
    }
}

/**
 * @brief Tests the correct ZIP decompression of a nested compressed folder.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressNestedFolder)
{
    // Set expected output files.
    std::vector<std::string> expectedDecompressedFiles;
    expectedDecompressedFiles.push_back(OUTPUT_DIR / ROOT_FOLDER / TXT_FILE);
    for (const auto& entry : XML_DECOMPRESSED)
    {
        expectedDecompressedFiles.push_back(OUTPUT_DIR / ROOT_FOLDER / XML_FOLDER / entry.first.string());
    }

    // Decompress.
    std::vector<std::string> decompressedFiles;
    ASSERT_NO_THROW({ decompressedFiles = Utils::ZlibHelper::zipDecompress(ZIP_NESTED_FOLDER, OUTPUT_DIR); });

    // Sort decompressed files to properly compare them.
    std::sort(decompressedFiles.begin(), decompressedFiles.end());
    EXPECT_EQ(expectedDecompressedFiles, decompressedFiles);
}

/**
 * @brief Tests the decompression of an empty ZIP file.
 *
 */
TEST_F(ZlibHelperTest, ZipDecompressEmptyZip)
{
    // Decompress.
    EXPECT_THROW(Utils::ZlibHelper::zipDecompress(ZIP_EMPTY, OUTPUT_DIR), std::runtime_error);
}
