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

#ifndef _ZLIB_HELPER_TEST_HPP
#define _ZLIB_HELPER_TEST_HPP

#include "gtest/gtest.h"
#include <filesystem>
#include <string>

const auto OUTPUT_DIR {std::filesystem::temp_directory_path() / "zlibHelper"};

/**
 * @brief Tests for ZlibHelper class.
 *
 */
class ZlibHelperTest : public ::testing::Test
{
protected:
    ZlibHelperTest() = default;
    ~ZlibHelperTest() override = default;

    /**
     * @brief Set up routine for tests. Create the output folder.
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        std::filesystem::create_directory(OUTPUT_DIR);
    }

    /**
     * @brief Tear down routine for tests. Removes the decompressed files.
     *
     */
    // cppcheck-suppress unusedFunction
    void TearDown() override
    {
        std::filesystem::remove_all(OUTPUT_DIR);
    }

    /**
     * @brief Helper function to calculate the hash of a file
     *
     * @param filepath Path to the file to be hashed.
     * @return std::string Digest string.
     */
    std::string getFileHash(const std::filesystem::path& filepath) const;
};

#endif //_ZLIB_HELPER_TEST_HPP
