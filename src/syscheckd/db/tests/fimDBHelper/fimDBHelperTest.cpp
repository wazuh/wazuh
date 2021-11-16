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

void FIMHelperTest::SetUp(){}

void FIMHelperTest::TearDown(){}

TEST_F(FIMHelperTest, insertItemToDatabaseSuccess) {
    std::string tableName;
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expectedReturn = static_cast<int>(dbQueryResult::SUCCESS);
    int returnCode = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, insertItemToDatabaseWithMaxRows) {
    std::string tableName;
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int returnCode = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, insertItemToDatabaseWithSomeDbSyncError) {
    std::string tableName;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int returnCode = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, nullptr);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, deleteItemToDatabaseSuccess) {
    std::string tableName;
    nlohmann::json filter;
    EXPECT_CALL(FIMDBMOCK::getInstance(), removeItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expectedReturn = static_cast<int>(dbQueryResult::SUCCESS);
    int returnCode = FIMDBHelper::removeFromDB<FIMDBMOCK>(tableName, filter);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, deleteItemToDatabaseWithMaxRows) {
    std::string tableName;
    nlohmann::json filter;
    EXPECT_CALL(FIMDBMOCK::getInstance(), removeItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int returnCode = FIMDBHelper::removeFromDB<FIMDBMOCK>(tableName, filter);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, deleteItemToDatabaseWithSomeDbSyncError) {
    std::string tableName;
    EXPECT_CALL(FIMDBMOCK::getInstance(), removeItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int returnCode = FIMDBHelper::removeFromDB<FIMDBMOCK>(tableName, nullptr);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, updateItemToDatabaseSuccess) {
    std::string tableName;
    nlohmann::json updateItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expectedReturn = static_cast<int>(dbQueryResult::SUCCESS);
    int returnCode = FIMDBHelper::updateItem<FIMDBMOCK>(tableName, updateItem);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, updateItemToDatabaseWithMaxRows) {
    std::string tableName;
    nlohmann::json filter;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int returnCode = FIMDBHelper::updateItem<FIMDBMOCK>(tableName, filter);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, updateItemToDatabaseWithSomeDbSyncError) {
    std::string tableName;
    EXPECT_CALL(FIMDBMOCK::getInstance(), updateItem(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int returnCode = FIMDBHelper::updateItem<FIMDBMOCK>(tableName, nullptr);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeQuerySuccess)
{
    nlohmann::json itemJson;
    nlohmann::json query;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expectedReturn = static_cast<int>(dbQueryResult::SUCCESS);
    int returnCode = FIMDBHelper::getDBItem<FIMDBMOCK>(itemJson, query);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeQueryWithMaxRows)
{
    nlohmann::json itemJson;
    nlohmann::json query;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int returnCode = FIMDBHelper::getDBItem<FIMDBMOCK>(itemJson, query);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeQueryWithSomeDbSyncError)
{
    nlohmann::json itemJson;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int returnCode = FIMDBHelper::getDBItem<FIMDBMOCK>(itemJson, nullptr);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeGetCountSuccess)
{
    std::string tableName;
    int count = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expectedReturn = static_cast<int>(dbQueryResult::SUCCESS);
    int returnCode = FIMDBHelper::getCount<FIMDBMOCK>(tableName, count);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeGetCountWithMaxRows)
{
    std::string tableName;
    int count = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int returnCode = FIMDBHelper::getCount<FIMDBMOCK>(tableName, count);
    ASSERT_EQ(returnCode, expectedReturn);
}

TEST_F(FIMHelperTest, executeGetCountWithSomeDbSyncError)
{
    std::string tableName;
    int count = 0;
    EXPECT_CALL(FIMDBMOCK::getInstance(), executeQuery(testing::_, testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expectedReturn = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int returnCode = FIMDBHelper::getCount<FIMDBMOCK>(tableName, count);
    ASSERT_EQ(returnCode, expectedReturn);
}
