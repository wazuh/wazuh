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
#include <iostream>


const auto insertFileStatement = R"({
        "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2456, "gid":0, "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":0, "user_name":"fakeUser"
    }
)"_json;
const auto insertRegistryKeyStatement = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root", "arch":1,
        "last_event":1596489275, "mode":0, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
        "scanned":1, "uid":0, "user_name":"fakeUser"
    }
)"_json;

const auto insertRegistryValueStatement = R"({
        "name":"testRegistry", "scanned":1, "last_event":1596489275, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "mode":0, "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "arch":0, "path":"/tmp/pathTestRegistry"
    }
)"_json;

void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data)
{
    fim_txn_context_s *event_data = (fim_txn_context_s *) user_data;
    auto expectedValue = R"([{
        "arch": "[x64]",
        "checksum": "a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "gid":  0,
        "group_name":   "root",
        "last_event":   1596489275,
        "mtime":    1578075431,
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "perm": "-rw-rw-r--",
        "scanned":  1,
        "uid":  0,
        "user_name":    "fakeUser"
    }])"_json;
    const cJSON *dbsync_event = NULL;
    cJSON *json_path = NULL;
    ASSERT_EQ(INSERTED, resultType);
    ASSERT_EQ(FIM_ADD, event_data->evt_data->type);

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
    EXPECT_NO_THROW(
    {
        const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
        bool updated;
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), &updated);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestWinFixture, TestFimDBInitWindows)
{
    EXPECT_NO_THROW(
    {
        const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
        bool updated;
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), &updated);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, DISABLED_TestFimSyncPushMsg)
{
    constexpr auto test{R"({"component":"fim_file","data":{"begin":"/bin","checksum":"88f127efa6329743d539ebd88e1d1ea3ca2a12e7","end":"/usr/sbin/zramctl","id":1642671764},"type":"integrity_check_global"})"};
    EXPECT_NO_THROW(
    {
        fim_sync_push_msg(test);
    });
}

TEST_F(DBTestWinFixture, DISABLED_TestFimRunIntegrity)
{
    EXPECT_NO_THROW(
    {
        fim_run_integrity();
    });
}

TEST_F(DBTestWinFixture, TestTransactionsWinFile)
{
    EXPECT_NO_THROW(
    {
        auto handler = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
        auto result = fim_db_transaction_sync_row(handler, fileFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

    });
}

TEST_F(DBTestFixture, TestTransactionsFile)
{
    EXPECT_NO_THROW(
    {
        auto handler = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
        auto result = fim_db_transaction_sync_row(handler, fileFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestWinFixture, TestTransactionsRegistryKey)
{
    EXPECT_NO_THROW(
    {
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto registryKeyFIMTest { std::make_unique<RegistryKey>(insertRegistryKeyStatement) };
        auto result = fim_db_transaction_sync_row(handler, registryKeyFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestWinFixture, TestTransactionsRegistryValue)
{
    EXPECT_NO_THROW(
    {
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);
        const auto registryValueFIMTest { std::make_unique<RegistryValue>(insertRegistryValueStatement) };
        auto result = fim_db_transaction_sync_row(handler, registryValueFIMTest->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestWinFixture, DISABLED_TestFimRunIntegrityError)
{
    try
    {
        fim_run_integrity();
    }
    catch(std::exception const & err)
    {
        ASSERT_NE(err.what(), std::string(""));
    }
}

TEST_F(DBTestWinFixture, TestInitTransactionWithInvalidParameters)
{
    auto handler = fim_db_transaction_start(nullptr, nullptr, nullptr);
    ASSERT_FALSE(handler);
}

TEST_F(DBTestWinFixture, TestSyncRowTransactionWithInvalidHandler)
{
    const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
    auto result = fim_db_transaction_sync_row(nullptr, fileFIMTest->toFimEntry());
    ASSERT_EQ(result, FIMDB_ERR);
}

TEST_F(DBTestWinFixture, DISABLED_TestSyncRowTransactionWithInvalidFimEntry)
{
    auto handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
    ASSERT_TRUE(handler);
    auto result = fim_db_transaction_sync_row(handler, nullptr);
    ASSERT_EQ(result, FIMDB_ERR);
    result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
    ASSERT_EQ(result, FIMDB_OK);
}

TEST_F(DBTestWinFixture, TestSyncDeletedRowsTransactionWithInvalidParameters)
{
    auto result = fim_db_transaction_deleted_rows(nullptr, nullptr, nullptr);
    ASSERT_EQ(result, FIMDB_ERR);
}
