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

TEST_F(FilesystemUtilsTest, joinPathsBothEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", ""), "");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", R"(relative\path)"), R"(relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeEmpty)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", ""), R"(C:\base\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsNormalCase)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", R"(relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseWithTrailingSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\)", R"(relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeWithLeadingSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", R"(\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBothWithSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\)", R"(\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsSingleLevel)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base)", "file.txt"), R"(C:\base\file.txt)");
}

TEST_F(FilesystemUtilsTest, joinPathsMixedSeparators)
{
    // Forward slashes should be converted to backslashes on Windows
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", "relative/path/file.txt"), R"(C:\base\path\relative\path\file.txt)");
}

TEST_F(FilesystemUtilsTest, joinPathsMultipleTrailingSlashes)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\\\)", R"(\\\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseOnlySeparators)
{
    EXPECT_EQ(Utils::joinPaths(R"(\\\)", R"(relative\path)"), R"(relative\path)");
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

TEST_F(FilesystemUtilsTest, joinPathsBothEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", ""), "");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", "relative/path"), "relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeEmpty)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", ""), "/base/path");
}

TEST_F(FilesystemUtilsTest, joinPathsNormalCase)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", "relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseWithTrailingSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path/", "relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeWithLeadingSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", "/relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBothWithSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path/", "/relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsSingleLevel)
{
    EXPECT_EQ(Utils::joinPaths("/base", "file.txt"), "/base/file.txt");
}

TEST_F(FilesystemUtilsTest, joinPathsMultipleTrailingSlashes)
{
    EXPECT_EQ(Utils::joinPaths("/base/path///", "///relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseOnlySeparators)
{
    EXPECT_EQ(Utils::joinPaths("///", "relative/path"), "relative/path");
}

#endif
