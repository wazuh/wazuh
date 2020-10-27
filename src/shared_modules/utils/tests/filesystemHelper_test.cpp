/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "filesystemHelper_test.h"
#include "filesystemHelper.h"

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

TEST_F(FilesystemUtilsTest, FilesystemEnumerateDir)
{
    const auto items {Utils::enumerateDir(R"(/usr)")};
    EXPECT_FALSE(items.empty());
}
#endif