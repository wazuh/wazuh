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

#ifndef _XZ_HELPER_TEST_HPP
#define _XZ_HELPER_TEST_HPP
#include "gtest/gtest.h"
#include <filesystem>
#include <vector>

const auto INPUT_PATH {std::filesystem::current_path() / "input_files" / "xzHelper"};
const auto OUTPUT_PATH {INPUT_PATH / "tmp"};

/**
 * @brief Tests for XzHelper class
 *
 */
class XzHelperTest : public ::testing::Test
{
protected:
    XzHelperTest() = default;
    ~XzHelperTest() override = default;

    /**
     * @brief Set the Up Test Suite object
     *
     */
    // cppcheck-suppress unusedFunction
    static void SetUpTestSuite()
    {
        std::filesystem::create_directory(OUTPUT_PATH);
    }

    /**
     * @brief Tear down test suite.
     */
    // cppcheck-suppress unusedFunction
    static void TearDownTestSuite()
    {
        std::filesystem::remove_all(OUTPUT_PATH);
    }

    /**
     * @brief Helper function to load a file into a vector
     *
     * @param filePath Path to file
     * @return std::vector<uint8_t> Content of the file
     */
    std::vector<uint8_t> loadFile(const std::filesystem::path& filePath);
};

#endif //_XZ_HELPER_TEST_HPP
