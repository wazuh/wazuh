/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 27, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDBUtils.hpp"
#include "fimDBUtilsTest.h"
#include <iostream>

void FIMDBUtilsTest::SetUp() {}

void FIMDBUtilsTest::TearDown() {}

TEST_F(FIMDBUtilsTest, createANewQuery)
{
    const auto expectedReturn = R"({"table":"file_entry",
                                    "query": {"column_list": "[path, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime]",
                                    "row_filter":"WHERE path=/tmp/fakeFile",
                                    "distinct_opt":false,
                                    "order_by_opt":"path",
                                    "count_opt":100
                                    }
                                }
    )"_json;
    auto columnList =
        R"({"column_list":"[path, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime]"})"_json;
    auto filter = "WHERE path=/tmp/fakeFile";
    auto returnStatement = FimDBUtils::dbQuery("file_entry", columnList, filter, "path");
    ASSERT_TRUE(expectedReturn == returnStatement);
}

TEST_F(FIMDBUtilsTest, testGetPathsFromINode)
{
    const auto paths { FimDBUtils::getPathsFromINode<FIMDBMOCK>(1, 12) };
    EXPECT_TRUE(paths.empty());

}
