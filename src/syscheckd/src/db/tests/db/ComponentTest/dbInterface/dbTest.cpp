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
        "uid":"0", "owner":"fakeUser", "version":1, "sync":1
    }
)"_json;
const auto insertRegistryKeyStatement = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_":"root", "architecture":1,
        "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "permissions":"-rw-rw-r--",
        "uid":"0", "owner":"fakeUser", "version":1, "sync":1
    }
)"_json;

const auto insertRegistryValueStatement = R"({
        "value":"testRegistry", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "architecture":0, "path":"/tmp/pathTestRegistry", "version":1, "sync":1
    }
)"_json;

void transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data)
{
    callback_ctx_test* event_data = (callback_ctx_test*)user_data;
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
                loggingFunction(LOG_ERROR, "Error, id: dbEngine: Invalid row limit, values below 0 not allowed."))
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

TEST_F(DBTestFixture, TestFimDBCloseAndDelete)
{
    EXPECT_NO_THROW({
        const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
        fim_db_close_and_delete_database();
    });
}

TEST(DBTest, TestFimDBCloseAndDeleteWithoutInit)
{
    mockLog = new MockLoggingCall();

    EXPECT_NO_THROW({
        fim_db_close_and_delete_database();
    });

    delete mockLog;
}

TEST_F(DBTestFixture, TestFimDBGetLastSyncTimeNewTable)
{
    EXPECT_NO_THROW({
        // On first call, should return 0 (no row exists yet, lazy initialization)
        auto lastSyncTime = fim_db_get_last_sync_time(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(lastSyncTime, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetLastSyncTimeNullParameter)
{
    EXPECT_NO_THROW({
        auto lastSyncTime = fim_db_get_last_sync_time(nullptr);
        ASSERT_EQ(lastSyncTime, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBUpdateAndGetLastSyncTime)
{
    EXPECT_NO_THROW({
        const int64_t testTimestamp = 1234567890;

        // Update the last sync time
        fim_db_update_last_sync_time_value(FIMDB_FILE_TABLE_NAME, testTimestamp);

        // Verify it was updated
        auto lastSyncTime = fim_db_get_last_sync_time(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(lastSyncTime, testTimestamp);

        // Update again with a different timestamp
        const int64_t newTimestamp = 9876543210;
        fim_db_update_last_sync_time_value(FIMDB_FILE_TABLE_NAME, newTimestamp);

        lastSyncTime = fim_db_get_last_sync_time(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(lastSyncTime, newTimestamp);
    });
}

TEST_F(DBTestFixture, TestFimDBUpdateLastSyncTimeValueNullParameter)
{
    EXPECT_NO_THROW({
        // Should not crash, just log error
        fim_db_update_last_sync_time_value(nullptr, 1234567890);
    });
}

TEST_F(DBTestFixture, TestFimDBUpdateLastSyncTime)
{
    EXPECT_NO_THROW({
        // Get initial sync time (should be 0)
        auto initialSyncTime = fim_db_get_last_sync_time(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(initialSyncTime, 0);

        // Update to current time using fim_db_update_last_sync_time
        fim_db_update_last_sync_time(FIMDB_FILE_TABLE_NAME);

        // Verify it was updated (should be greater than 0)
        auto updatedSyncTime = fim_db_get_last_sync_time(FIMDB_FILE_TABLE_NAME);
        ASSERT_GT(updatedSyncTime, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBCalculateTableChecksumEmptyTable)
{
    EXPECT_NO_THROW({
        char* checksum = fim_db_calculate_table_checksum(FIMDB_FILE_TABLE_NAME);
        ASSERT_TRUE(checksum != nullptr);
        // Empty table should produce SHA1 of empty string
        ASSERT_STREQ(checksum, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        free(checksum);
    });
}

TEST_F(DBTestFixture, TestFimDBCalculateTableChecksumWithEntries)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};

    EXPECT_NO_THROW({
        // Insert a file entry
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        // Set sync flag to 1 for the inserted entry
        pending_sync_item_t item;
        item.json = cJSON_Parse(insertFileStatement.dump().c_str());
        item.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item, 1);
        cJSON_Delete(item.json);

        // Calculate checksum
        char* checksum = fim_db_calculate_table_checksum(FIMDB_FILE_TABLE_NAME);
        ASSERT_TRUE(checksum != nullptr);

        // Should produce a non-empty checksum different from empty table
        ASSERT_STRNE(checksum, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        // Verify checksum length (SHA1 is 40 hex characters)
        ASSERT_EQ(strlen(checksum), 40);

        free(checksum);
    });
}

TEST_F(DBTestFixture, TestFimDBCalculateTableChecksumNullParameter)
{
    EXPECT_NO_THROW({
        char* checksum = fim_db_calculate_table_checksum(nullptr);
        ASSERT_TRUE(checksum == nullptr);
    });
}

TEST_F(DBTestFixture, TestFimDBGetEveryElementEmptyTable)
{
    EXPECT_NO_THROW({
        cJSON* elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_TRUE(cJSON_IsArray(elements));
        ASSERT_EQ(cJSON_GetArraySize(elements), 0);
        cJSON_Delete(elements);
    });
}

TEST_F(DBTestFixture, TestFimDBGetEveryElementWithSingleEntry)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};

    EXPECT_NO_THROW({
        // Insert a file entry
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        // Get all elements
        cJSON* elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_TRUE(cJSON_IsArray(elements));
        ASSERT_EQ(cJSON_GetArraySize(elements), 1);

        // Verify the entry contains expected fields
        cJSON* firstEntry = cJSON_GetArrayItem(elements, 0);
        ASSERT_TRUE(firstEntry != nullptr);
        ASSERT_TRUE(cJSON_HasObjectItem(firstEntry, "path"));
        ASSERT_TRUE(cJSON_HasObjectItem(firstEntry, "checksum"));
        ASSERT_TRUE(cJSON_HasObjectItem(firstEntry, "inode"));
        ASSERT_TRUE(cJSON_HasObjectItem(firstEntry, "device"));

        // Verify path value
        cJSON* path = cJSON_GetObjectItem(firstEntry, "path");
        ASSERT_TRUE(path != nullptr);
        ASSERT_TRUE(cJSON_IsString(path));
        ASSERT_STREQ(cJSON_GetStringValue(path), "/etc/wgetrc");

        cJSON_Delete(elements);
    });
}

TEST_F(DBTestFixture, TestFimDBGetEveryElementWithMultipleEntries)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertFileStatement)};

    EXPECT_NO_THROW({
        // Insert first entry
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);

        // Insert second entry with different path
        auto secondStatement = insertFileStatement;
        secondStatement["path"] = "/etc/test.conf";
        secondStatement["inode"] = 99999;
        const auto fileFIMTest2 {std::make_unique<FileItem>(secondStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        // Get all elements
        cJSON* elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_TRUE(cJSON_IsArray(elements));
        ASSERT_EQ(cJSON_GetArraySize(elements), 2);

        cJSON_Delete(elements);
    });
}

TEST_F(DBTestFixture, TestFimDBGetEveryElementNullParameter)
{
    EXPECT_NO_THROW({
        cJSON* elements = fim_db_get_every_element(nullptr, NULL);
        ASSERT_TRUE(elements == nullptr);
    });
}

TEST_F(DBTestFixture, TestFimDBIncreaseEachEntryVersionEmptyTable)
{
    EXPECT_NO_THROW({
        // Should succeed with empty table
        int result = fim_db_increase_each_entry_version(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(result, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBIncreaseEachEntryVersionSingleEntry)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertFileStatement)};

    EXPECT_NO_THROW({
        // Insert a file entry with version 1
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        // Get the entry and verify initial version
        cJSON* elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(elements), 1);

        cJSON* entry = cJSON_GetArrayItem(elements, 0);
        cJSON* version = cJSON_GetObjectItem(entry, "version");
        ASSERT_TRUE(version != nullptr);
        ASSERT_EQ(cJSON_GetNumberValue(version), 1);
        cJSON_Delete(elements);

        // Increase all entry versions
        int result = fim_db_increase_each_entry_version(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(result, 0);

        // Verify version was increased to 2
        elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(elements), 1);

        entry = cJSON_GetArrayItem(elements, 0);
        version = cJSON_GetObjectItem(entry, "version");
        ASSERT_TRUE(version != nullptr);
        ASSERT_EQ(cJSON_GetNumberValue(version), 2);

        cJSON_Delete(elements);
    });
}

TEST_F(DBTestFixture, TestFimDBIncreaseEachEntryVersionMultipleEntries)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertFileStatement)};

    EXPECT_NO_THROW({
        // Insert first entry
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);

        // Insert second entry with different path
        auto secondStatement = insertFileStatement;
        secondStatement["path"] = "/etc/test.conf";
        secondStatement["inode"] = 99999;
        const auto fileFIMTest2 {std::make_unique<FileItem>(secondStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        // Insert third entry with different path
        auto thirdStatement = insertFileStatement;
        thirdStatement["path"] = "/etc/another.txt";
        thirdStatement["inode"] = 88888;
        const auto fileFIMTest3 {std::make_unique<FileItem>(thirdStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added), FIMDB_OK);

        // Verify all entries have version 1
        cJSON* elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(elements), 3);

        for (int i = 0; i < 3; i++)
        {
            cJSON* entry = cJSON_GetArrayItem(elements, i);
            cJSON* version = cJSON_GetObjectItem(entry, "version");
            ASSERT_TRUE(version != nullptr);
            ASSERT_EQ(cJSON_GetNumberValue(version), 1);
        }
        cJSON_Delete(elements);

        // Increase all entry versions
        int result = fim_db_increase_each_entry_version(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(result, 0);

        // Verify all entries now have version 2
        elements = fim_db_get_every_element(FIMDB_FILE_TABLE_NAME, NULL);
        ASSERT_TRUE(elements != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(elements), 3);

        for (int i = 0; i < 3; i++)
        {
            cJSON* entry = cJSON_GetArrayItem(elements, i);
            cJSON* version = cJSON_GetObjectItem(entry, "version");
            ASSERT_TRUE(version != nullptr);
            ASSERT_EQ(cJSON_GetNumberValue(version), 2);
        }

        cJSON_Delete(elements);
    });
}

TEST_F(DBTestFixture, TestFimDBIncreaseEachEntryVersionNullParameter)
{
    EXPECT_NO_THROW({
        // Should handle NULL gracefully
        int result = fim_db_increase_each_entry_version(nullptr);
        ASSERT_EQ(result, -1);
    });
}

// Tests for fim_db_count_synced_docs

TEST_F(DBTestFixture, TestFimDBCountSyncedDocsEmptyTable)
{
    EXPECT_NO_THROW({
        int count = fim_db_count_synced_docs(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(count, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBCountSyncedDocsOnlySynced)
{
    // Insert entries and set sync=1
    auto fileStatement1 = insertFileStatement;
    fileStatement1["path"] = "/etc/test1.txt";
    fileStatement1["inode"] = 11111;
    const auto fileFIMTest1 {std::make_unique<FileItem>(fileStatement1)};

    auto fileStatement2 = insertFileStatement;
    fileStatement2["path"] = "/etc/test2.txt";
    fileStatement2["inode"] = 22222;
    const auto fileFIMTest2 {std::make_unique<FileItem>(fileStatement2)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        // Manually set sync flag to 1 for both entries
        pending_sync_item_t item1;
        item1.json = cJSON_Parse(fileStatement1.dump().c_str());
        item1.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item1, 1);
        cJSON_Delete(item1.json);

        pending_sync_item_t item2;
        item2.json = cJSON_Parse(fileStatement2.dump().c_str());
        item2.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item2, 1);
        cJSON_Delete(item2.json);

        int count = fim_db_count_synced_docs(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(count, 2);
    });
}

TEST_F(DBTestFixture, TestFimDBCountSyncedDocsOnlyUnsynced)
{
    // Insert entries with sync=0
    auto fileStatement1 = insertFileStatement;
    fileStatement1["path"] = "/etc/test1.txt";
    fileStatement1["inode"] = 11111;
    fileStatement1["sync"] = 0;
    const auto fileFIMTest1 {std::make_unique<FileItem>(fileStatement1)};

    auto fileStatement2 = insertFileStatement;
    fileStatement2["path"] = "/etc/test2.txt";
    fileStatement2["inode"] = 22222;
    fileStatement2["sync"] = 0;
    const auto fileFIMTest2 {std::make_unique<FileItem>(fileStatement2)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        int count = fim_db_count_synced_docs(FIMDB_FILE_TABLE_NAME);
        ASSERT_EQ(count, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBCountSyncedDocsNullParameter)
{
    EXPECT_NO_THROW({
        int count = fim_db_count_synced_docs(nullptr);
        ASSERT_EQ(count, 0);
    });
}

// Tests for fim_db_get_documents_to_promote

TEST_F(DBTestFixture, TestFimDBGetDocumentsToPromoteEmptyTable)
{
    EXPECT_NO_THROW({
        cJSON* docs = fim_db_get_documents_to_promote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 0);
        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToPromoteOnlyUnsynced)
{
    // Insert entries with sync=0 (to be promoted)
    auto fileStatement1 = insertFileStatement;
    fileStatement1["path"] = "/etc/unsynced1.txt";
    fileStatement1["inode"] = 11111;
    fileStatement1["sync"] = 0;
    const auto fileFIMTest1 {std::make_unique<FileItem>(fileStatement1)};

    auto fileStatement2 = insertFileStatement;
    fileStatement2["path"] = "/etc/unsynced2.txt";
    fileStatement2["inode"] = 22222;
    fileStatement2["sync"] = 0;
    const auto fileFIMTest2 {std::make_unique<FileItem>(fileStatement2)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        cJSON* docs = fim_db_get_documents_to_promote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 2);

        // Verify documents contain all fields (full documents for promoting)
        cJSON* doc = cJSON_GetArrayItem(docs, 0);
        ASSERT_TRUE(cJSON_GetObjectItem(doc, "path") != nullptr);
        ASSERT_TRUE(cJSON_GetObjectItem(doc, "checksum") != nullptr);
        ASSERT_TRUE(cJSON_GetObjectItem(doc, "size") != nullptr);

        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToPromoteWithLimit)
{
    // Insert 5 unsynced entries
    for (int i = 0; i < 5; i++)
    {
        auto fileStatement = insertFileStatement;
        fileStatement["path"] = "/etc/unsynced" + std::to_string(i) + ".txt";
        fileStatement["inode"] = 10000 + i;
        fileStatement["sync"] = 0;
        const auto fileFIMTest {std::make_unique<FileItem>(fileStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    }

    EXPECT_NO_THROW({
        // Request only 3 documents
        cJSON* docs = fim_db_get_documents_to_promote((char*)FIMDB_FILE_TABLE_NAME, 3);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 3);
        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToPromoteAllSynced)
{
    // Insert only synced entries - should return empty array
    auto fileStatement = insertFileStatement;
    fileStatement["path"] = "/etc/synced.txt";
    fileStatement["inode"] = 11111;
    const auto fileFIMTest {std::make_unique<FileItem>(fileStatement)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        // Set sync=1
        pending_sync_item_t item;
        item.json = cJSON_Parse(fileStatement.dump().c_str());
        item.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item, 1);
        cJSON_Delete(item.json);

        cJSON* docs = fim_db_get_documents_to_promote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 0);
        cJSON_Delete(docs);
    });
}

// Tests for fim_db_get_documents_to_demote

TEST_F(DBTestFixture, TestFimDBGetDocumentsToDemoteEmptyTable)
{
    EXPECT_NO_THROW({
        cJSON* docs = fim_db_get_documents_to_demote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 0);
        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToDemoteOnlySynced)
{
    // Insert entries with sync=1 (to be demoted)
    auto fileStatement1 = insertFileStatement;
    fileStatement1["path"] = "/etc/synced1.txt";
    fileStatement1["inode"] = 11111;
    const auto fileFIMTest1 {std::make_unique<FileItem>(fileStatement1)};

    auto fileStatement2 = insertFileStatement;
    fileStatement2["path"] = "/etc/synced2.txt";
    fileStatement2["inode"] = 22222;
    const auto fileFIMTest2 {std::make_unique<FileItem>(fileStatement2)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);

        // Manually set sync flag to 1 for both entries
        pending_sync_item_t item1;
        item1.json = cJSON_Parse(fileStatement1.dump().c_str());
        item1.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item1, 1);
        cJSON_Delete(item1.json);

        pending_sync_item_t item2;
        item2.json = cJSON_Parse(fileStatement2.dump().c_str());
        item2.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item2, 1);
        cJSON_Delete(item2.json);

        cJSON* docs = fim_db_get_documents_to_demote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 2);

        // Verify documents only contain primary keys (path and version for files)
        cJSON* doc = cJSON_GetArrayItem(docs, 0);
        ASSERT_TRUE(cJSON_GetObjectItem(doc, "path") != nullptr);
        ASSERT_TRUE(cJSON_GetObjectItem(doc, "version") != nullptr);

        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToDemoteWithLimit)
{
    // Insert 5 synced entries
    for (int i = 0; i < 5; i++)
    {
        auto fileStatement = insertFileStatement;
        fileStatement["path"] = "/etc/synced" + std::to_string(i) + ".txt";
        fileStatement["inode"] = 10000 + i;
        const auto fileFIMTest {std::make_unique<FileItem>(fileStatement)};
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        // Set sync=1 for this entry
        pending_sync_item_t item;
        item.json = cJSON_Parse(fileStatement.dump().c_str());
        item.sync_value = 1;
        fim_db_set_sync_flag(const_cast<char*>(FIMDB_FILE_TABLE_NAME), &item, 1);
        cJSON_Delete(item.json);
    }

    EXPECT_NO_THROW({
        // Request only 3 documents
        cJSON* docs = fim_db_get_documents_to_demote((char*)FIMDB_FILE_TABLE_NAME, 3);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 3);
        cJSON_Delete(docs);
    });
}

TEST_F(DBTestFixture, TestFimDBGetDocumentsToDemoteAllUnsynced)
{
    // Insert only unsynced entries - should return empty array
    auto fileStatement = insertFileStatement;
    fileStatement["path"] = "/etc/unsynced.txt";
    fileStatement["inode"] = 11111;
    fileStatement["sync"] = 0;
    const auto fileFIMTest {std::make_unique<FileItem>(fileStatement)};

    EXPECT_NO_THROW({
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);

        cJSON* docs = fim_db_get_documents_to_demote((char*)FIMDB_FILE_TABLE_NAME, 10);
        ASSERT_TRUE(docs != nullptr);
        ASSERT_EQ(cJSON_GetArraySize(docs), 0);
        cJSON_Delete(docs);
    });
}

