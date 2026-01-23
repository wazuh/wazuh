/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 19, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "xzHelper_test.hpp"
#include "hashHelper.h"
#include "xzHelper.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <vector>

/**
 * @brief Helper function to calculate the hash of a file
 *
 * @param filepath path to the file.
 * @return std::vector<unsigned char> digest vector.
 */
static std::vector<unsigned char> hashFile(const std::filesystem::path& filepath)
{
    if (std::ifstream inputFile(filepath, std::fstream::in); inputFile)
    {
        constexpr int BUFFER_SIZE {4096};
        std::array<char, BUFFER_SIZE> buffer;

        Utils::HashData hash;
        while (inputFile.read(buffer.data(), buffer.size()))
        {
            hash.update(buffer.data(), inputFile.gcount());
        }
        hash.update(buffer.data(), inputFile.gcount());

        return hash.hash();
    }
    else
    {
        throw std::runtime_error {"Unable to open '" + filepath.string() + "' for hashing."};
    }
};

const auto UNCOMPRESSED_INPUT_FILE {INPUT_PATH / "sample.json"};
const auto COMPRESSED_INPUT_FILE_ST {INPUT_PATH / "sample.json.st.xz"};
const auto COMPRESSED_INPUT_FILE_MT {INPUT_PATH / "sample.json.mt.xz"};

const auto UNCOMPRESSED_REFERENCE_FILE {UNCOMPRESSED_INPUT_FILE};
const auto COMPRESSED_REFERENCE_FILE_ST {COMPRESSED_INPUT_FILE_ST};
const auto COMPRESSED_REFERENCE_FILE_MT {COMPRESSED_INPUT_FILE_MT};

constexpr uint32_t MAX_THREAD_COUNT {0};

std::vector<uint8_t> XzHelperTest::loadFile(const std::filesystem::path& filePath)
{
    std::ifstream fileDataStream(filePath, std::ios::in | std::ios::binary);
    return {(std::istreambuf_iterator<char>(fileDataStream)), std::istreambuf_iterator<char>()};
}

/**
 * @brief Test that setting non existing file as input throws exception.
 *
 */
TEST_F(XzHelperTest, NonExistingInputFile)
{
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-NonExistingInputFile.json"};
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-NonExistingInputFile.json.xz"};

    EXPECT_THROW(Utils::XzHelper(INPUT_PATH / "nofile.json", COMPRESSED_OUTPUT_FILE).compress(), std::runtime_error);
    EXPECT_THROW(Utils::XzHelper(INPUT_PATH / "nofile.json.xz", DECOMPRESSED_OUTPUT_FILE).decompress(),
                 std::runtime_error);
}

/**
 * @brief Test that setting an invalid output file (non existing directory) throws exception.
 *
 */
TEST_F(XzHelperTest, InvalidOutputFile)
{
    EXPECT_THROW(Utils::XzHelper(UNCOMPRESSED_INPUT_FILE, OUTPUT_PATH / "extradir" / "sample.json.xz").compress(),
                 std::runtime_error);
    EXPECT_THROW(Utils::XzHelper(UNCOMPRESSED_INPUT_FILE, OUTPUT_PATH / "extradir" / "sample.json.xz").decompress(),
                 std::runtime_error);
}

/**
 * @brief Test correct compression of a sample file as input, output to file. Single-thread.
 *
 */
TEST_F(XzHelperTest, CompressFileOutputToFileSingleThread)
{
    // Setup
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressFileOutputToFileSingleThread.json.xz"};
    Utils::XzHelper xz(UNCOMPRESSED_INPUT_FILE, COMPRESSED_OUTPUT_FILE);

    // Compress
    ASSERT_NO_THROW(xz.compress());

    // Check that the output file equals the compressed reference file
    EXPECT_EQ(hashFile(COMPRESSED_OUTPUT_FILE), hashFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct compression of a sample file as input, output to file. Multi-thread.
 *
 */
TEST_F(XzHelperTest, CompressFileOutputToFileMultithread)
{
    // Setup
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressFileOutputToFileMultithread.json.xz"};
    Utils::XzHelper xz(UNCOMPRESSED_INPUT_FILE, COMPRESSED_OUTPUT_FILE, MAX_THREAD_COUNT);

    // Compress
    ASSERT_NO_THROW(xz.compress());

    // Check that the output file equals the compressed reference file
    EXPECT_EQ(hashFile(COMPRESSED_OUTPUT_FILE), hashFile(COMPRESSED_REFERENCE_FILE_MT));
}

/**
 * @brief Test correct decompression of a sample file as input, output to file. Single-thread.
 *
 */
TEST_F(XzHelperTest, DecompressFileOutputToFileSingleThread)
{
    // Setup
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-DecompressFileOutputToFileSingleThread.json"};
    Utils::XzHelper xz(COMPRESSED_INPUT_FILE_ST, DECOMPRESSED_OUTPUT_FILE);

    // Decompress
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output file equals the uncompressed reference file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test correct decompression of a sample file as input, output to file. Multi-thread.
 *
 */
TEST_F(XzHelperTest, DecompressFileOutputToFileMultiThread)
{
    // Setup
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-DecompressFileOutputToFileMultiThread.json"};
    Utils::XzHelper xz(COMPRESSED_INPUT_FILE_MT, DECOMPRESSED_OUTPUT_FILE, MAX_THREAD_COUNT);

    // Decompress
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output file equals the uncompressed reference file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test that trying to decompress a non existing file throws exception.
 *
 */
TEST_F(XzHelperTest, DecompressWithNonExistingInputFile)
{
    // Setup
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-DecompressWithNonExistingInputFile.json"};
    Utils::XzHelper xz(INPUT_PATH / "nofile.json", DECOMPRESSED_OUTPUT_FILE);

    // Decompress, expect exception
    EXPECT_THROW(xz.decompress(), std::runtime_error);
}

/**
 * @brief Test that trying to decompress an invalid format file throws exception.
 *
 */
TEST_F(XzHelperTest, DecompressInvalidDataFile)
{
    // Setup: the input file is not compressed so it is invalid
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-DecompressInvalidDataFile.json"};
    Utils::XzHelper xz(UNCOMPRESSED_INPUT_FILE, DECOMPRESSED_OUTPUT_FILE);

    // Decompress, expect exception
    EXPECT_THROW(xz.decompress(), std::runtime_error);
}

/**
 * @brief Test correct compression of a data vector, output to data vector
 *
 */
TEST_F(XzHelperTest, CompressDataVectorToDataVectorSingleThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::vector<uint8_t> compressedData;

    // Compress
    Utils::XzHelper xz(inputData, compressedData);
    ASSERT_NO_THROW(xz.compress());

    // Check that the output compressed data equals the data of the compressed reference file
    EXPECT_EQ(compressedData, loadFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct compression of a data vector, output to data vector. Multi-thread.
 *
 */
TEST_F(XzHelperTest, CompressDataVectorToDataVectorMultiThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::vector<uint8_t> compressedData;

    // Compress
    Utils::XzHelper xz(inputData, compressedData, MAX_THREAD_COUNT);
    xz.compress();

    // Check that the output compressed data equals the data of the compressed reference file
    EXPECT_EQ(compressedData, loadFile(COMPRESSED_REFERENCE_FILE_MT));
}

/**
 * @brief Test correct compression of a string, output to data vector
 *
 */
TEST_F(XzHelperTest, CompressStringToDataVectorSingleThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::string inputString(inputData.begin(), inputData.end());
    std::vector<uint8_t> compressedData;

    // Compress
    Utils::XzHelper xz(inputString, compressedData);
    ASSERT_NO_THROW(xz.compress());

    // Check that the output compressed data equals the data of the compressed reference file
    EXPECT_EQ(compressedData, loadFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct compression of a string, output to data vector. Multi-thread.
 *
 */
TEST_F(XzHelperTest, CompressStringToDataVectorMultiThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::string inputString(inputData.begin(), inputData.end());
    std::vector<uint8_t> compressedData;

    // Compress
    Utils::XzHelper xz(inputString, compressedData, MAX_THREAD_COUNT);
    xz.compress();

    // Check that the output compressed data equals the data of the compressed reference file
    EXPECT_EQ(compressedData, loadFile(COMPRESSED_REFERENCE_FILE_MT));
}

/**
 * @brief Test that trying to decompress data with invalid format throws exception.
 *
 */
TEST_F(XzHelperTest, DecompressInvalidData)
{
    // Setup: load invalid format data. Uncompressed data is invalid for decompression
    const auto invalidFormatData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::vector<uint8_t> decompressedData;

    Utils::XzHelper xz(invalidFormatData, decompressedData);

    // Decompress, expect exception
    EXPECT_THROW(xz.decompress(), std::runtime_error);
}

/**
 * @brief Test correct decompression of a data vector, output to data vector. Single-thread.
 *
 */
TEST_F(XzHelperTest, DecompressDataVectorToDataVectorSingleThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(COMPRESSED_INPUT_FILE_ST)};
    std::vector<uint8_t> decompressedData;

    // Decompress
    Utils::XzHelper xz(inputData, decompressedData);
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output decompressed data equals the data of the uncompressed reference file
    EXPECT_EQ(decompressedData, loadFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test correct decompression of a data vector, output to data vector. Multi-thread.
 *
 */
TEST_F(XzHelperTest, DecompressDataVectorToDataVectorMultiThread)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(COMPRESSED_INPUT_FILE_MT)};
    std::vector<uint8_t> decompressedData;

    // Decompress
    Utils::XzHelper xz(inputData, decompressedData, MAX_THREAD_COUNT);
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output decompressed data equals the data of the uncompressed reference file
    EXPECT_EQ(decompressedData, loadFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test correct compression of a sample file as input, output to data vector
 *
 */
TEST_F(XzHelperTest, CompressFileOutputToDataVector)
{
    // Setup
    std::vector<uint8_t> compressedData;

    // Compress
    Utils::XzHelper xz(UNCOMPRESSED_INPUT_FILE, compressedData);
    ASSERT_NO_THROW(xz.compress());

    // Check that the output data vector equals the data of the compressed reference file
    EXPECT_EQ(compressedData, loadFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct decompression of a sample file as input, output to data vector
 *
 */
TEST_F(XzHelperTest, DecompressFileOutputToDataVector)
{
    // Setup
    std::vector<uint8_t> decompressedData;
    Utils::XzHelper xz(COMPRESSED_INPUT_FILE_ST, decompressedData);

    // Decompress
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output data vector equals the data of the compressed reference file
    EXPECT_EQ(decompressedData, loadFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test correct compression of a data vector, output to file
 *
 */
TEST_F(XzHelperTest, CompressDataVectorToFile)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};

    // Compress
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressDataVectorToFile.json.xz"};
    Utils::XzHelper xz(inputData, COMPRESSED_OUTPUT_FILE);
    ASSERT_NO_THROW(xz.compress());

    // Check that the output compressed file equals the compressed reference file
    EXPECT_EQ(hashFile(COMPRESSED_OUTPUT_FILE), hashFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct compression of a string, output to file
 *
 */
TEST_F(XzHelperTest, CompressStringToFile)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::string inputString(inputData.begin(), inputData.end());

    // Compress
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressStringToFile.json.xz"};
    Utils::XzHelper xz(inputString, COMPRESSED_OUTPUT_FILE);
    ASSERT_NO_THROW(xz.compress());

    // Check that the output compressed file equals the compressed reference file
    EXPECT_EQ(hashFile(COMPRESSED_OUTPUT_FILE), hashFile(COMPRESSED_REFERENCE_FILE_ST));
}

/**
 * @brief Test correct decompression of a data vector, output to file
 *
 */
TEST_F(XzHelperTest, DecompressDataVectorToFile)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(COMPRESSED_INPUT_FILE_ST)};

    // Decompress
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-DecompressDataVectorToFile.json"};
    Utils::XzHelper xz(inputData, DECOMPRESSED_OUTPUT_FILE);
    ASSERT_NO_THROW(xz.decompress());

    // Check that the output decompressed file equals the uncompressed reference file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_REFERENCE_FILE));
}

/**
 * @brief Test that a file can be compressed into a vector and then decompressed to a file obtaining the same file that
 * was used as input
 *
 */
TEST_F(XzHelperTest, CompressAndDecompressFileToDataVector)
{
    // Setup
    std::vector<uint8_t> compressedData;

    // Compress file into vector
    Utils::XzHelper(UNCOMPRESSED_INPUT_FILE, compressedData).compress();

    // Decompress vector into file
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressAndDecompressFileToDataVector.json"};
    Utils::XzHelper(compressedData, DECOMPRESSED_OUTPUT_FILE).decompress();

    // Check that the output decompressed file equals the initial input file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_INPUT_FILE));
}

/**
 * @brief Test that a data vector can be compressed into a file and then decompressed back to a vector equal to the one
 * that was used as input
 *
 */
TEST_F(XzHelperTest, CompressAndDecompressDataVectorToFile)
{
    // Setup
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};

    // Compress vector into file
    const auto COMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressAndDecompressDataVectorToFile.json.xz"};
    Utils::XzHelper(inputData, COMPRESSED_OUTPUT_FILE).compress();

    // Decompress file into vector
    std::vector<uint8_t> decompressedData;
    Utils::XzHelper(COMPRESSED_OUTPUT_FILE, decompressedData).decompress();

    // Check that the output decompressed vector equals the initial input vector
    EXPECT_EQ(decompressedData, inputData);
}

/**
 * @brief Test that a file can be compressed in multi-thread mode and then decompressed in single-thread mode obtaining
 * the same file that was used as input
 *
 */
TEST_F(XzHelperTest, CompressMTAndDecompressSTFileToDataVector)
{
    // Setup
    std::vector<uint8_t> compressedData;

    // Compress file into vector in single-thread mode
    Utils::XzHelper(UNCOMPRESSED_INPUT_FILE, compressedData, MAX_THREAD_COUNT).compress();

    // Decompress vector into file in multi-thread mode
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressMTAndDecompressSTFileToDataVector.json"};
    Utils::XzHelper(compressedData, DECOMPRESSED_OUTPUT_FILE).decompress();

    // Check that the output decompressed file equals the initial input file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_INPUT_FILE));
}

/**
 * @brief Test that a file can be compressed in single-thread mode and then decompressed in multi-thread (internally the
 * decoder will work as single-thread) mode obtaining the same file that was used as input
 *
 */
TEST_F(XzHelperTest, CompressSTAndDecompressMTFileToDataVector)
{
    // Setup
    std::vector<uint8_t> compressedData;

    // Compress file into vector in single-thread mode
    Utils::XzHelper(UNCOMPRESSED_INPUT_FILE, compressedData).compress();

    // Decompress vector into file in multi-thread mode
    const auto DECOMPRESSED_OUTPUT_FILE {OUTPUT_PATH / "sample-CompressSTAndDecompressMTFileToDataVector.json"};
    Utils::XzHelper(compressedData, DECOMPRESSED_OUTPUT_FILE, MAX_THREAD_COUNT).decompress();

    // Check that the output decompressed file equals the initial input file
    EXPECT_EQ(hashFile(DECOMPRESSED_OUTPUT_FILE), hashFile(UNCOMPRESSED_INPUT_FILE));
}

/**
 * @brief Test compression with a non-default compression preset
 *
 */
TEST_F(XzHelperTest, CompressAndDecompressVectorWithNonDefaultPreset)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::vector<uint8_t> compressedData;

    // Compress data into vector, using non-default preset
    constexpr auto COMPRESSION_PRESET {3};
    Utils::XzHelper(inputData, compressedData).compress(COMPRESSION_PRESET);

    // Decompress data for comparison with input data
    std::vector<uint8_t> decompressedData;
    Utils::XzHelper(compressedData, decompressedData).decompress();

    // Check that the output decompressed file equals the initial input file
    EXPECT_EQ(decompressedData, inputData);
}

/**
 * @brief Test that compressing with different presets generate different outputs
 *
 */
TEST_F(XzHelperTest, CompressWithDifferentPresets)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};

    // Compress data sample with a low compression preset
    constexpr auto LOW_COMPRESSION_PRESET {1};
    std::vector<uint8_t> lowCompressionData;
    Utils::XzHelper(inputData, lowCompressionData).compress(LOW_COMPRESSION_PRESET);

    // Compress data sample with a high compression preset
    constexpr auto HIGH_COMPRESSION_PRESET {9};
    std::vector<uint8_t> highCompressionData;
    Utils::XzHelper(inputData, highCompressionData).compress(HIGH_COMPRESSION_PRESET);

    // Check that the outputs are not equal
    EXPECT_NE(lowCompressionData, highCompressionData);
}

/**
 * @brief Test that using an invalid preset throws an exception
 *
 */
TEST_F(XzHelperTest, InvalidCompressionPresetThrows)
{
    // Setup: get data from sample file
    const auto inputData {loadFile(UNCOMPRESSED_INPUT_FILE)};
    std::vector<uint8_t> compressedData;

    // Compress data into vector, using invalid preset
    constexpr auto INVALID_COMPRESSION_PRESET {1000};
    EXPECT_THROW(Utils::XzHelper(inputData, compressedData).compress(INVALID_COMPRESSION_PRESET), std::runtime_error);
}
