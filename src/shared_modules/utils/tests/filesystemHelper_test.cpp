/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "filesystemHelper_test.h"

void FilesystemUtilsTest::SetUp() {};

void FilesystemUtilsTest::TearDown() {};
#ifdef WIN32
TEST_F(FilesystemUtilsTest, FilesystemExistsDir)
{
    EXPECT_TRUE(Utils::existsDir(R"(C:\)"));
}

TEST_F(FilesystemUtilsTest, FilesystemEnumerateDir)
{
    const auto items {Utils::enumerateDir(R"(C:\)")};
    EXPECT_FALSE(items.empty());
}

#else
TEST_F(FilesystemUtilsTest, FilesystemExistsDir)
{
    EXPECT_TRUE(Utils::existsDir(R"(/usr)"));
}

TEST_F(FilesystemUtilsTest, FilesystemExistsRegular)
{
    // Check correct input, for macos and linux.
    EXPECT_TRUE(Utils::existsRegular(R"(/etc/services)"));

    // Check wrong input
    EXPECT_FALSE(Utils::existsRegular(R"(/etc)"));
}

TEST_F(FilesystemUtilsTest, FilesystemEnumerateDir)
{
    const auto items {Utils::enumerateDir(R"(/usr)")};
    EXPECT_FALSE(items.empty());
}

TEST_F(FilesystemUtilsTest, getFileContent)
{
    const auto& inputFile{"/etc/services"};
    const auto content {Utils::getFileContent(inputFile)};
    EXPECT_FALSE(content.empty());
}

TEST_F(FilesystemUtilsTest, getFileBinaryContent)
{
    const auto binContent {Utils::getBinaryContent("/usr/bin/gcc")};
    EXPECT_FALSE(binContent.empty());
}

TEST_F(FilesystemUtilsTest, FilesystemExpandSimpleWildcard)
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

TEST_F(FilesystemUtilsTest, FilesystemExpandWildcard)
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

TEST_F(FilesystemUtilsTest, FilesystemExpandWildcardWithPrefix)
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

TEST_F(FilesystemUtilsTest, FilesystemExpandWildcardWithSuffix)
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
TEST_F(FilesystemUtilsTest, FilesystemExpandWildcardWithQuestionMark)
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

TEST_F(FilesystemUtilsTest, FilesystemExpandWildcardWithQuestionMark2)
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


#endif
