/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015-2023, Wazuh Inc.
 * October 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _JSON_ARRAY_PARSER_TEST_HPP
#define _JSON_ARRAY_PARSER_TEST_HPP

#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>

/**
 * @brief Tests for the JsonArrayParser class.
 *
 */
class JsonArrayParserTest : public ::testing::Test
{
public:
    JsonArrayParserTest() = default;
    ~JsonArrayParserTest() override = default;

protected:
    /// Folder for the temporary files used in the tests
    const std::filesystem::path m_testFolder {std::filesystem::temp_directory_path() /
                                              "wazuh/test_files/json_array_parser"};

    /**
     * @brief Helper function to create a test file.
     *
     * @param data File content
     * @param filepath File path
     */
    void createTestFile(const std::string& data, const std::filesystem::path& filepath)
    {
        std::ofstream file(filepath);
        file << data;
    }

    /**
     * @brief Sets up the test fixture.
     */
    void SetUp() override
    {
        std::filesystem::create_directories(m_testFolder);
    }

    /**
     * @brief Tears down the test fixture.
     */
    void TearDown() override
    {
        std::filesystem::remove_all(m_testFolder);
    }
};
#endif //_JSON_ARRAY_PARSER_TEST_HPP
