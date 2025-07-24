/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2022, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbTest.h"
#include "db.h"

const auto insertFileStatement = R"({
        "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2456, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083,
        "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
        "uid":"0", "owner":"fakeUser"
    }
)"_json;
const auto insertRegistryKeyStatement = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_":"root", "architecture":1,
        "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "permissions":"-rw-rw-r--",
        "uid":"0", "owner":"fakeUser"
    }
)"_json;

const auto insertRegistryValueStatement = R"({
        "value":"testRegistry", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "architecture":0, "path":"/tmp/pathTestRegistry"
    }
)"_json;

void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data)
{
    callback_ctx* event_data = (callback_ctx*)user_data;
    auto expectedValue = R"([{
        "architecture": "[x64]",
        "checksum": "a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "gid":  "0",
        "group_":   "root",
        "mtime":    1578075431,
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "permissions": "-rw-rw-r--",
        "uid":  "0",
        "owner":    "fakeUser"
    }])"_json;
    const cJSON* dbsync_event = NULL;
    cJSON* json_path = NULL;
    ASSERT_EQ(INSERTED, resultType);
    ASSERT_EQ(FIM_ADD, event_data->event->type);

    if (cJSON_IsArray(result_json))
    {
        if (dbsync_event = cJSON_GetArrayItem(result_json, 0), dbsync_event != NULL)
        {
            dbsync_event = result_json;

            if (json_path = cJSON_GetObjectItem(dbsync_event, "path"), json_path != NULL)
            {
                ASSERT_EQ(cJSON_GetStringValue(json_path), expectedValue.at("path"));
            }
        }
    }
}

TEST_F(DBTestFixture, TestFimDBInit)
{
    EXPECT_NO_THROW({
        const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestTransactionsFile)
{
    EXPECT_NO_THROW({
        auto handler = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};
        auto result = fim_db_transaction_sync_row(handler, fileFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}
#ifdef WIN32
TEST_F(DBTestFixture, TestTransactionsRegistryKey)
{
    EXPECT_NO_THROW({
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto registryKeyFIMTest {std::make_unique<RegistryKey>(insertRegistryKeyStatement)};
        auto result = fim_db_transaction_sync_row(handler, registryKeyFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestTransactionsRegistryValue)
{
    EXPECT_NO_THROW({
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto registryValueFIMTest {std::make_unique<RegistryValue>(insertRegistryValueStatement)};
        auto result = fim_db_transaction_sync_row(handler, registryValueFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}
#endif

TEST_F(DBTestFixture, TestInitTransactionWithInvalidParameters)
{
    auto handler = fim_db_transaction_start(nullptr, nullptr, nullptr);
    ASSERT_FALSE(handler);
}

TEST_F(DBTestFixture, TestSyncRowTransactionWithInvalidHandler)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};
    auto result = fim_db_transaction_sync_row(nullptr, fileFIMTest->toFimEntry());
    ASSERT_EQ(result, FIMDB_ERR);
}

TEST_F(DBTestFixture, TestSyncRowTransactionWithInvalidFimEntry)
{
    auto handler = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
    ASSERT_TRUE(handler);
    auto result = fim_db_transaction_sync_row(handler, nullptr);
    ASSERT_EQ(result, FIMDB_ERR);
    result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
    ASSERT_EQ(result, FIMDB_OK);
}

TEST_F(DBTestFixture, TestSyncDeletedRowsTransactionWithInvalidParameters)
{
    auto result = fim_db_transaction_deleted_rows(nullptr, nullptr, nullptr);
    ASSERT_EQ(result, FIMDB_ERR);
}

TEST(DBTest, TestInvalidFimLimit)
{
    mockLog = new MockLoggingCall();

    EXPECT_CALL(*mockLog,
                loggingFunction(LOG_ERROR_EXIT, "Error, id: dbEngine: Invalid row limit, values below 0 not allowed."))
        .Times(1);
    auto result {fim_db_init(FIM_DB_MEMORY, mockLoggingFunction, -1, -1, nullptr)};
    ASSERT_EQ(result, FIMDB_ERR);

    delete mockLog;
}

TEST(DBTest, TestValidFimLimit)
{
    mockLog = new MockLoggingCall();

    auto result {fim_db_init(FIM_DB_MEMORY, mockLoggingFunction, 100, 100000, nullptr)};
    ASSERT_EQ(result, FIMDB_OK);

    delete mockLog;
}
