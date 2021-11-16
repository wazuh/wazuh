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

TEST_F(FIMHelperTest, insert_item_to_database_success) {
    std::string tableName = "file_entry";
    auto insertItem = R"(
        {
            "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2051, "gid":0, "group_name":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
            "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
            "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::SUCCESS)));
    int expected_return = static_cast<int>(dbQueryResult::SUCCESS);
    int return_code = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FIMHelperTest, insert_item_to_database_with_max_rows) {
    std::string tableName = "file_entry";
    auto insertItem = R"(
        {
            "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2051, "gid":0, "group_name":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
            "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
            "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::MAX_ROWS_ERROR)));
    int expected_return = static_cast<int>(dbQueryResult::MAX_ROWS_ERROR);
    int return_code = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, insertItem);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FIMHelperTest, insert_item_to_database_with_some_db_sync_error) {
    std::string tableName = "file_entry";
    EXPECT_CALL(FIMDBMOCK::getInstance(), insertItem(testing::_)).WillOnce(testing::Return(static_cast<int>(dbQueryResult::DBSYNC_ERROR)));
    int expected_return = static_cast<int>(dbQueryResult::DBSYNC_ERROR);
    int return_code = FIMDBHelper::insertItem<FIMDBMOCK>(tableName, nullptr);
    ASSERT_EQ(return_code, expected_return);
}
