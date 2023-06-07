/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cleanUpContent_test.hpp"
#include <filesystem>
#include <memory>

/*
 * @brief Check if the output path is not set.
 */
TEST_F(CleanUpContentTest, OutputPathNotSet)
{
    EXPECT_EQ(m_spUpdaterBaseContext->outputFolder, "");
    EXPECT_NO_THROW(m_spCleanUpContent->handleRequest(m_spUpdaterContext));
}

/*
 * @brief Check if the output path is set.
 */
TEST_F(CleanUpContentTest, OutputPathSet)
{
    // Set the output path
    m_spUpdaterBaseContext->outputFolder = TEST_DIR;

    // Create content in the folder
    std::filesystem::create_directory(TEST_DIR + "/test1");
    std::filesystem::create_directory(TEST_DIR + "/test2");

    // Check if the output path is not empty
    EXPECT_FALSE(std::filesystem::is_empty(TEST_DIR));

    // execute the cleanup
    EXPECT_NO_THROW(m_spCleanUpContent->handleRequest(m_spUpdaterContext));

    // Check if the output path is empty
    EXPECT_TRUE(std::filesystem::is_empty(TEST_DIR));
}
