/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 8, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDBHelper.hpp"
#include "fimDBHelperTest.h"

void FIMHelperTest::SetUp() {}

void FIMHelperTest::TearDown() {}

TEST_F(FIMHelperTest, testInit)
{
    std::shared_ptr<DBSync> handlerDbsync;
    std::shared_ptr<RemoteSync> handlerRsync;
    unsigned int maxFiles = 0;
    unsigned int syncInterval = 0;
#ifndef WIN32
    EXPECT_CALL(FIMDBMOCK::getInstance(), init(testing::_, testing::_, testing::_, testing::_, testing::_, testing::_));
    FIMDBHelper::initDB<FIMDBMOCK>(syncInterval, maxFiles, NULL, NULL, handlerDbsync, handlerRsync);
#else
    unsigned int max_registries = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), init(testing::_, testing::_, testing::_, testing::_, testing::_, testing::_, testing::_));
    FIMDBHelper::initDB<FIMDBMOCK>(syncInterval, maxFiles, max_registries, NULL, NULL, handlerDbsync, handlerRsync);
#endif
}

TEST_F(FIMHelperTest, insertItemToDatabase)
{
    std::string tableName;
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_));
    FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
}

TEST_F(FIMHelperTest, deleteItemToDatabase)
{
    std::string tableName;
    nlohmann::json filter;
    EXPECT_CALL(FIMDBMOCK::getInstance(), removeItem(testing::_));
    FIMDBHelper::removeFromDB<FIMDBMOCK>(tableName, filter);
}


TEST_F(FIMHelperTest, updateItemToDatabaseSuccess)
{
    std::string tableName;
    nlohmann::json updateItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_));
    FIMDBHelper::updateItem<FIMDBMOCK>(tableName, updateItem);
}

TEST_F(FIMHelperTest, executeQuerySuccess)
{
    nlohmann::json itemJson;
    nlohmann::json query;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_));
    FIMDBHelper::getDBItem<FIMDBMOCK>(itemJson, query);
}


TEST_F(FIMHelperTest, executeGetCountSuccess)
{
    std::string tableName;
    int count = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_));
    FIMDBHelper::getCount<FIMDBMOCK>(tableName, count);
}

TEST_F(FIMHelperTest, createANewQuery)
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
    auto columnList = R"({"column_list":"[path, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime]"})"_json;
    auto filter = "WHERE path=/tmp/fakeFile";
    auto returnStatement = FIMDBHelper::dbQuery("file_entry", columnList, filter, "path");
    ASSERT_TRUE(expectedReturn == returnStatement);
}
