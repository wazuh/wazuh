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
    constexpr auto PATH_MATCH_SIZE { 2ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/dum*", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/dummy" || item == "/tmp/wazuh_test/dummy.txt");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcard)
{
    constexpr auto PATH_MATCH_SIZE { 4ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/prefix_*_data/*", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/prefix_1_data/prefix1_1" ||
                    item == "/tmp/wazuh_test/prefix_1_data/prefix1_2" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_1" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_2");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithPrefix)
{
    constexpr auto PATH_MATCH_SIZE { 4ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/prefix_*_data/prefix*", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/prefix_1_data/prefix1_1" ||
                    item == "/tmp/wazuh_test/prefix_1_data/prefix1_2" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_1" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_2");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithSuffix)
{
    constexpr auto PATH_MATCH_SIZE { 2ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/prefix_*_data/*_1", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/prefix_1_data/prefix1_1" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_1");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}
TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithQuestionMark)
{
    constexpr auto PATH_MATCH_SIZE { 2ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/prefix_?_data/*_1", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/prefix_1_data/prefix1_1" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_1");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}

TEST_F(StdFileSystemHelperTest, FilesystemExpandWildcardWithQuestionMark2)
{
    constexpr auto PATH_MATCH_SIZE { 2ull };
    std::vector<std::string> output;
    Utils::expandAbsolutePath("/tmp/wazuh_test/prefix_*_data/prefix?*1", output);

    for (const auto& item : output)
    {
        EXPECT_TRUE(item == "/tmp/wazuh_test/prefix_1_data/prefix1_1" ||
                    item == "/tmp/wazuh_test/prefix_2_data/prefix2_1");
    }

    EXPECT_EQ(output.size(), PATH_MATCH_SIZE);
}


