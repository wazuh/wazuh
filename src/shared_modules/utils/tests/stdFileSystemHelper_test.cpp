/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stdFileSystemHelper_test.hpp"

void StdFileSystemHelperTest::SetUp() {};

void StdFileSystemHelperTest::TearDown() {};

TEST_F(StdFileSystemHelperTest, FilesystemExpandSimpleWildcard)
{
    constexpr auto PATH_MATCH_SIZE { 2u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;

    Utils::expandAbsolutePath(PATH_TO_EXPAND_1, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_5) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_6) == 1);
    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcard)
{
    constexpr auto PATH_MATCH_SIZE { 4u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;

    Utils::expandAbsolutePath(PATH_TO_EXPAND_2, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_1) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_2) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_3) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_4) == 1);
    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithPrefix)
{
    constexpr auto PATH_MATCH_SIZE { 4u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;

    Utils::expandAbsolutePath(PATH_TO_EXPAND_3, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_1) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_2) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_3) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_4) == 1);
    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithSuffix)
{
    constexpr auto PATH_MATCH_SIZE { 2u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;
    Utils::expandAbsolutePath(PATH_TO_EXPAND_4, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_1) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_3) == 1);

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}
TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithQuestionMark)
{
    constexpr auto PATH_MATCH_SIZE { 2u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;
    Utils::expandAbsolutePath(PATH_TO_EXPAND_5, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_1) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_3) == 1);
    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithQuestionMark2)
{
    constexpr auto PATH_MATCH_SIZE { 2u };
    std::deque<std::string> output;
    std::unordered_map<std::string, uint32_t> outputMap;
    Utils::expandAbsolutePath(PATH_TO_EXPAND_6, output);

    for (const auto& item : output)
    {
        outputMap[item]++;
    }

    EXPECT_TRUE(outputMap.at(EXPAND_PATH_1) == 1);
    EXPECT_TRUE(outputMap.at(EXPAND_PATH_3) == 1);
    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

