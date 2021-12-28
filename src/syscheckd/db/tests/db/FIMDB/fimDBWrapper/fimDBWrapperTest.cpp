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
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_));
    FIMDBHelper::updateItem<FIMDBMOCK>(insertItem);
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
    nlohmann::json updateItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_));
    FIMDBHelper::updateItem<FIMDBMOCK>(updateItem);
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
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_));
    FIMDBHelper::getCount<FIMDBMOCK>(tableName, count);
}

TEST_F(FIMWrapperTest, executeGetCountSuccessCustomQuery)
{
    std::string tableName;
    nlohmann::json query;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_));
    FIMDBHelper::getCount<FIMDBMOCK>(tableName, query);
}
