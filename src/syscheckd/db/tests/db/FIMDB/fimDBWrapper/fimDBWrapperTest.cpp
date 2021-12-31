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
#include "fimDBUtils.hpp"
#include "fimDBUtilsTest.h"

void FIMWrapperTest::SetUp() {}

void FIMWrapperTest::TearDown() {}

TEST_F(FIMWrapperTest, testInit)
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

TEST_F(FIMWrapperTest, insertItemToDatabase)
{
    bool updated = true;
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillOnce(testing::InvokeArgument<1>(ReturnTypeCallback::INSERTED, R"({})"_json));
    EXPECT_NO_THROW(
    {
        updated = FIMDBHelper::updateItem<FIMDBMOCK>(insertItem);
    });
    ASSERT_FALSE(updated);
}

TEST_F(FIMWrapperTest, deleteItemToDatabase)
{
    std::string tableName = "test";
    nlohmann::json filter = "";
    EXPECT_CALL(FIMDBMOCK::getInstance(), removeItem(testing::_));
    FIMDBHelper::removeFromDB<FIMDBMOCK>(tableName, filter);
}


TEST_F(FIMWrapperTest, updateItemToDatabaseSuccess)
{
    bool updated = false;
    nlohmann::json updateItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillOnce(testing::InvokeArgument<1>(ReturnTypeCallback::MODIFIED, R"({})"_json));
    EXPECT_NO_THROW(
    {
        updated = FIMDBHelper::updateItem<FIMDBMOCK>(updateItem);
    });
    ASSERT_TRUE(updated);
}

TEST_F(FIMWrapperTest, executeQuerySuccess)
{
    nlohmann::json itemJson;
    nlohmann::json query;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_));
    FIMDBHelper::getDBItem<FIMDBMOCK>(itemJson, query);
}


TEST_F(FIMWrapperTest, executeGetCountSuccess)
{
    std::string tableName;
    int count = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillOnce(testing::InvokeArgument<1>(ReturnTypeCallback::SELECTED, R"({"count":5})"_json));
    EXPECT_NO_THROW(
    {
        count = FIMDBHelper::getCount<FIMDBMOCK>(tableName);
    });
    ASSERT_NE(count, 0);
    ASSERT_EQ(count, 5);

}

TEST_F(FIMWrapperTest, executeGetCountSuccessCustomQuery)
{
    std::string tableName = FIMBD_FILE_TABLE_NAME;
    int count = 0;
    nlohmann::json query;
    query["column_list"] = "count(DISTINCT (inode || ',' || dev)) AS count";
    const auto countQuery = FimDBUtils::dbQuery(tableName, query, "", "");
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_))
    .Times(testing::AtLeast(1))
    .WillOnce(testing::InvokeArgument<1>(ReturnTypeCallback::SELECTED, R"({"count":2})"_json));
    EXPECT_NO_THROW(
    {
        count = FIMDBHelper::getCount<FIMDBMOCK>(tableName, query);
    });
    ASSERT_NE(count, 0);
    ASSERT_EQ(count, 2);
}
