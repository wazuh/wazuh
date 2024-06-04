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
    // Create content in the folders
    std::filesystem::create_directory(DOWNLOAD_DIR + "/test1");
    std::filesystem::create_directory(CONTENTS_DIR + "/test2");

    // Check if the output path is not empty
    EXPECT_FALSE(std::filesystem::is_empty(DOWNLOAD_DIR));
    EXPECT_FALSE(std::filesystem::is_empty(CONTENTS_DIR));

    // execute the cleanup
    EXPECT_NO_THROW(m_spCleanUpContent->handleRequest(m_spUpdaterContext));

    // Check the folder content
    EXPECT_TRUE(std::filesystem::is_empty(DOWNLOAD_DIR));
    EXPECT_FALSE(std::filesystem::is_empty(CONTENTS_DIR));
}
