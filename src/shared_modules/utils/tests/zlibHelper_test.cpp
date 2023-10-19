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
#include <fstream>
#include <string>

const auto INPUT_FILES_DIR {std::filesystem::current_path() / "input_files" / "zlibHelper"};
const auto COMPRESSED_FILE {INPUT_FILES_DIR / "sample.json.gz"};
const auto NOT_COMPRESSED_FILE {INPUT_FILES_DIR / "not_compressed.json"};
const std::string SHA1_EXPECTED {"98bf22d47ff4a9279ab98a2b224d9333f4272618"};

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
 * @brief Tests the decompressor when the input file is empty or it doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, InvalidInputFile)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress("", OUTPUT_FILE), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress("inexistant.xml.gz", OUTPUT_FILE), std::runtime_error);
}

/**
 * @brief Tests the decompressor when the output file is empty or the path doesn't exist.
 *
 */
TEST_F(ZlibHelperTest, InvalidOutputFile)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(COMPRESSED_FILE, ""), std::runtime_error);
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(COMPRESSED_FILE, "inexistant/sample.json"), std::runtime_error);
}

/**
 * @brief Tests the correct decompression of a file.
 *
 */
TEST_F(ZlibHelperTest, DecompressFile)
{
    ASSERT_NO_THROW(Utils::ZlibHelper::gzipDecompress(COMPRESSED_FILE, OUTPUT_FILE));

    // Check the expected hash.
    EXPECT_EQ(SHA1_EXPECTED, getFileHash(OUTPUT_FILE));
}

/**
 * @brief Tests the decompression of a file whose format is not '.gz'.
 *
 */
TEST_F(ZlibHelperTest, DecompressFileWithoutGzExtension)
{
    EXPECT_THROW(Utils::ZlibHelper::gzipDecompress(NOT_COMPRESSED_FILE, OUTPUT_FILE), std::runtime_error);
}
