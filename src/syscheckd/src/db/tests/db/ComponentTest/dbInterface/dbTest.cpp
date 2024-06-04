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
        "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2456, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":"0", "user_name":"fakeUser"
    }
)"_json;
const auto insertRegistryKeyStatement = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_name":"root", "arch":1,
        "last_event":1596489275, "mode":0, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
        "scanned":1, "uid":"0", "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880", "user_name":"fakeUser"
    }
)"_json;

const auto insertRegistryValueStatement = R"({
        "name":"testRegistry", "scanned":1, "last_event":1596489275, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "mode":0, "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "arch":0, "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880", "path":"/tmp/pathTestRegistry"
    }
)"_json;

const auto minSyncInterval { 10 };
const auto maxInterval { 600 };

void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data)
{
    fim_txn_context_s *event_data = (fim_txn_context_s *) user_data;
    auto expectedValue = R"([{
        "arch": "[x64]",
        "checksum": "a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "gid":  "0",
        "group_name":   "root",
        "last_event":   1596489275,
        "mtime":    1578075431,
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "perm": "-rw-rw-r--",
        "scanned":  1,
        "uid":  "0",
        "user_name":    "fakeUser"
    }])"_json;
const cJSON* dbsync_event = NULL;
cJSON* json_path = NULL;
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
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimSyncPushMsg)
{
    const auto test{R"(fim_file no_data {"begin":"a2fbef8f81af27155dcee5e3927ff6243593b91a","end":"a2fbef8f81af27155dcee5e3927ff6243593b91b","id":1})"};
    const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
    ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Executing FIM sync.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Finished FIM sync.")).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_file", testing::_)).Times(1);
#ifdef WIN32
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_key", testing::_)).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_value", testing::_)).Times(1);
#endif
    EXPECT_NO_THROW(
    {
        auto result = fim_run_integrity();
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_sync_push_msg(test);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimRunIntegrity)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Executing FIM sync.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Finished FIM sync.")).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_file", testing::_)).Times(1);
#ifdef WIN32
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_key", testing::_)).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_value", testing::_)).Times(1);
#endif

    EXPECT_NO_THROW(
    {
        auto result = fim_run_integrity();
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimRunIntegrityInitTwice)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "FIM integrity thread already running.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Executing FIM sync.")).Times(1);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Finished FIM sync.")).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_file", testing::_)).Times(1);
#ifdef WIN32
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_key", testing::_)).Times(1);
    EXPECT_CALL(*mockSync, syncMsg("fim_registry_value", testing::_)).Times(1);
#endif

    EXPECT_NO_THROW(
    {
        auto result = fim_run_integrity();
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_run_integrity();
        ASSERT_EQ(result, FIMDB_ERR);
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
#ifdef WIN32
TEST_F(DBTestFixture, TestTransactionsRegistryKey)
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

TEST_F(DBTestFixture, TestTransactionsRegistryValue)
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
#endif

TEST_F(DBTestFixture, TestInitTransactionWithInvalidParameters)
{
    auto handler = fim_db_transaction_start(nullptr, nullptr, nullptr);
    ASSERT_FALSE(handler);
}

TEST_F(DBTestFixture, TestSyncRowTransactionWithInvalidHandler)
{
    const auto fileFIMTest { std::make_unique<FileItem>(insertFileStatement) };
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
    mockSync = new MockSyncMsg();

    EXPECT_CALL(*mockLog,
                loggingFunction(LOG_ERROR_EXIT,
                                "Error, id: dbEngine: Invalid row limit, values below 0 not allowed.")).Times(1);
    auto result
    {
        fim_db_init(FIM_DB_MEMORY,
                    300,
                    maxInterval,
                    minSyncInterval,
                    mockSyncMessage,
                    mockLoggingFunction,
                    -1,
                    -1,
                    true,
                    0,
                    0,
                    nullptr,
                    nullptr)
    };
    ASSERT_EQ(result, FIMDB_ERR);

    delete mockLog;
    delete mockSync;
}

TEST(DBTest, TestValidFimLimit)
{
    mockLog = new MockLoggingCall();
    mockSync = new MockSyncMsg();

    auto result
    {
        fim_db_init(FIM_DB_MEMORY,
                    300,
                    maxInterval,
                    minSyncInterval,
                    mockSyncMessage,
                    mockLoggingFunction,
                    100,
                    100000,
                    true,
                    0,
                    0,
                    nullptr,
                    nullptr)
    };
    ASSERT_EQ(result, FIMDB_OK);

    delete mockLog;
    delete mockSync;
}
