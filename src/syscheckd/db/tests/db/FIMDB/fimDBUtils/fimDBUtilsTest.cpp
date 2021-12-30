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

#include "fimDBUtilsTest.h"
#include "fimDBUtils.hpp"

void FIMDBUtilsTest::SetUp() {}

void FIMDBUtilsTest::TearDown() {}

ACTION(myThrowException)
{
    throw DbSync::dbsync_error{INVALID_TABLE};
}

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
    std::vector<std::string> paths;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillOnce(testing::InvokeArgument<1>(ReturnTypeCallback::SELECTED, R"({"path":"/tmp/test.txt"})"_json));
    EXPECT_NO_THROW(
    {
        paths = FimDBUtils::getPathsFromINode<FIMDBMOCK>(1, 12);
    });
    ASSERT_TRUE(!paths.empty());
    ASSERT_EQ(paths[0], "/tmp/test.txt");
}

TEST_F(FIMDBUtilsTest, testGetPathsFromINodeWithDBSyncException)
{
    EXPECT_CALL(FIMDBMOCK::getInstance(), logFunction(testing::_, testing::_));
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(1)
    .WillOnce(testing::Throw(DbSync::dbsync_error{INVALID_TABLE}));
    try
    {
        const auto paths = FimDBUtils::getPathsFromINode<FIMDBMOCK>(1, 12);
    }
    catch (const DbSync::dbsync_error& ex)
    {
        std::cout << ex.what() << std::endl;
        ASSERT_EQ(ex.what(), "ERROR");
    }
}

TEST_F(FIMDBUtilsTest, testGetPathsFromINodeWithException)
{
    EXPECT_CALL(FIMDBMOCK::getInstance(), logFunction(testing::_, testing::_));
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillRepeatedly(testing::Throw(std::invalid_argument("ERROR")));
    try
    {
        const auto paths = FimDBUtils::getPathsFromINode<FIMDBMOCK>(1, 12);
    }
    catch (const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
        ASSERT_EQ(ex.what(), "ERROR");
    }
}

TEST_F(FIMDBUtilsTest, testgetPathsFromPattern)
{
    std::vector<std::string> paths;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<1>(ReturnTypeCallback::SELECTED, R"({"path":"/tmp/test.txt"})"_json));
    EXPECT_NO_THROW(
    {
        paths = FimDBUtils::getPathsFromPattern<FIMDBMOCK>("test.txt");
    });
    ASSERT_TRUE(!paths.empty());
    ASSERT_EQ(paths[0], "/tmp/test.txt");
}

TEST_F(FIMDBUtilsTest, testgetPathsFromPatternWithDBSyncException)
{
    EXPECT_CALL(FIMDBMOCK::getInstance(), logFunction(testing::_, testing::_));
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(1)
    .WillOnce(testing::Throw(DbSync::dbsync_error{INVALID_TABLE}));
    try
    {
        const auto paths = FimDBUtils::getPathsFromPattern<FIMDBMOCK>("test.txt");
    }
    catch (const DbSync::dbsync_error& ex)
    {
        std::cout << ex.what() << std::endl;
        ASSERT_EQ(ex.what(), "ERROR");
    }
}

TEST_F(FIMDBUtilsTest, testgetPathsFromPatternWithException)
{
    EXPECT_CALL(FIMDBMOCK::getInstance(), logFunction(testing::_, testing::_));
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillRepeatedly(testing::Throw(std::invalid_argument("ERROR")));
    try
    {
        const auto paths = FimDBUtils::getPathsFromPattern<FIMDBMOCK>("test.txt");
    }
    catch (const std::exception& ex)
    {
        std::cout << ex.what() << std::endl;
        ASSERT_EQ(ex.what(), "ERROR");
    }
}