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
#include "syscheck.h"

void FIMHelperTest::SetUp()
{
    
}

void FIMHelperTest::TearDown()
{
}

TEST(FIMHelperTest, insert_item_to_database_success) {
    std::string tableName = "file_entry";
    nlohmann::json insertItem;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(0));
    int expected_return = 0;
    int return_code = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
    ASSERT_EQ(return_code, expected_return);
    // EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(0));
    // FIMDBHelper::insertItem<FIMDBMOCK>(aux, item);
}