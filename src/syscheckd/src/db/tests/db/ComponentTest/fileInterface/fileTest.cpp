/*
 * Wazuh Syscheck
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "db.h"
#include "db.hpp"
#include "dbFileItem.hpp"
#include "dbTest.h"
#include "fimDBTests/fimDBImpTests.hpp"
#include <atomic>
#include <chrono>
#include <future>
#include <thread>

const auto insertStatement1 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2456, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083,
        "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0}]
    }
)"_json;
const auto insertStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2221, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083,
        "mtime":1578075431, "path":"/tmp/test.txt", "permissions":"-rw-rw-r--", "size":4925,
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0}]
    }
)"_json;
const auto insertStatement3 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":8432, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":99997083,
        "mtime":1578075431, "path":"/tmp/test2.txt", "permissions":"-rw-rw-r--", "size":4925,
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0}]
    }
)"_json;
const auto insertStatement4 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":8432, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810881,
        "mtime":1578075431, "path":"/tmp/test3.txt", "permissions":"-rw-rw-r--", "size":4925,
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0}]
    }
)"_json;
const auto updateStatement1 = R"({
        "table": "file_entry",
        "data":[{"attributes":"11", "checksum":"e89f3b4c21c2005896c964462da4766057dd94e9", "device":2151, "gid":"1000", "group_":"test",
        "hash_md5":"d6719d8eaa46012a9de38103d5f284e4", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58a",
        "hash_sha256":"0211f049f5b1121fbd034adf7b81ea521d615b5bd8df0e77c8ec8a363459ead1", "inode":18457083,
        "mtime":1578075435, "path":"/etc/wgetrc", "permissions":"-rw-rw-rw-", "size":4925,
        "uid":"1000", "owner":"testuser", "version":1, "sync":0}]
    }
)"_json;
const auto updateStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2151, "gid":"0", "group_":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083,
        "mtime":1578075431, "path":"/tmp/test.txt", "permissions":"-rw-rw-r--", "size":4800,
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0}]
    }
)"_json;

static void callbackTestSearch(void* return_data, void* user_data)
{
    char* path = (char*)return_data;
    ASSERT_TRUE(user_data == NULL);
    ASSERT_TRUE(path);
}

static void callbackTestSearchPath(void* return_data, void* user_data)
{
    char* returnPath = (char*)return_data;
    char* path = (char*)user_data;
    ASSERT_EQ(std::strcmp(returnPath, path), 0);
}

static void callBackTestFIMEntry(void* return_data, void* user_data)
{
    fim_entry* entry = (fim_entry*)user_data;
    fim_entry* returnEntry = (fim_entry*)return_data;

    ASSERT_EQ(std::strcmp(entry->file_entry.path, returnEntry->file_entry.path), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->attributes, returnEntry->file_entry.data->attributes), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->checksum, returnEntry->file_entry.data->checksum), 0);
    ASSERT_EQ(entry->file_entry.data->device, returnEntry->file_entry.data->device);
    ASSERT_EQ(entry->file_entry.data->inode, returnEntry->file_entry.data->inode);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_md5, returnEntry->file_entry.data->hash_md5), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_sha1, returnEntry->file_entry.data->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_sha256, returnEntry->file_entry.data->hash_sha256), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->gid, returnEntry->file_entry.data->gid), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->group, returnEntry->file_entry.data->group), 0);
    ASSERT_EQ(entry->file_entry.data->mtime, returnEntry->file_entry.data->mtime);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->permissions, returnEntry->file_entry.data->permissions), 0);
    ASSERT_EQ(entry->file_entry.data->size, returnEntry->file_entry.data->size);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->uid, returnEntry->file_entry.data->uid), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->owner, returnEntry->file_entry.data->owner), 0);
}

TEST_F(DBTestFixture, TestFimDBFileUpdate)
{

    EXPECT_NO_THROW({
        const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};
        const auto fileFIMTestUpdated {std::make_unique<FileItem>(updateStatement1["data"].front())};
        const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
        const auto fileFIMTestUpdated2 {std::make_unique<FileItem>(updateStatement2["data"].front())};

        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTestUpdated->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTestUpdated2->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
    });
}
TEST_F(DBTestFixture, TestFimDBRemovePath)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};
    EXPECT_NO_THROW({
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPath)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW({
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};
        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.context = fileFIMTest->toFimEntry();
        result = fim_db_get_path("/etc/wgetrc", callback_data, false);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBWithUTF8Path)
{
    const auto utf8_insert = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"abc123", "device":1234, "gid":"0", "group_":"root",
        "hash_md5":"deadbeefdeadbeefdeadbeefdeadbeef", "hash_sha1":"abc", "hash_sha256":"abc",
        "inode":8888, "mtime":1578075431, "path":"/tmp/naïve.txt", "permissions":"-rw-rw-r--",
        "size":4925, "uid":"0", "owner":"utf8User", "version":1, "sync":0}]
    })"_json;

    EXPECT_NO_THROW(
    {
        const auto fileUTF8 {std::make_unique<FileItem>(utf8_insert["data"].front())};
        auto result = fim_db_file_update(fileUTF8->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.context = fileUTF8->toFimEntry();

        result = fim_db_get_path("/tmp/naïve.txt", callback_data, false);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetCountFileEntry)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 0);
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 3);
    });
}

static void noopTxnCallback(ReturnTypeCallback, const cJSON*, void*) {}

TEST_F(DBTestFixture, TestFimDBTransactionCloseKeepsRowsNotReached)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};

    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added), FIMDB_OK);
        ASSERT_EQ(fim_db_get_count_file_entry(), 2);

        // A scan cut short after reaching only the first file.
        const auto handler = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE, noopTxnCallback, &txn_ctx);
        ASSERT_TRUE(handler);
        ASSERT_EQ(fim_db_transaction_sync_row(handler, fileFIMTest1->toFimEntry()), FIMDB_OK);
        ASSERT_EQ(fim_db_transaction_close(handler), FIMDB_OK);

        ASSERT_EQ(fim_db_get_count_file_entry(), 2);
    });
}

TEST_F(DBTestFixture, TestFimDBGetCountFileInode)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 0);
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 3);
    });
}

TEST_F(DBTestFixture, TestFimDBFileInodeSearch)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        char* test;
        test = strdup("/etc/wgetrc");
        callback_context_t callback_data;
        callback_data.callback = callbackTestSearchPath;
        callback_data.context = test;
        result = fim_db_file_inode_search(18277083, 2456, callback_data);
        ASSERT_EQ(result, FIMDB_OK);
        os_free(test);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
        callback_data.callback = callbackTestSearch;
        callback_data.context = NULL;
        result = fim_db_file_inode_search(18457083, 2151, callback_data);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearch)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        callback_context_t callback_data;
        callback_data.callback = callbackTestSearch;
        callback_data.context = nullptr;
        result = fim_db_file_pattern_search("/tmp/%", callback_data);
        ASSERT_EQ(result, FIMDB_OK);
        char* test;
        test = strdup("/etc/wgetrc");
        callback_data.callback = callbackTestSearchPath;
        callback_data.context = test;
        result = fim_db_file_pattern_search("/etc/%", callback_data);
        ASSERT_EQ(result, FIMDB_OK);
        os_free(test);
    });
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchNullParameters)
{
    callback_context_t callback_data {};
    callback_data.callback = callbackTestSearch;
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(2));
    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_file_pattern_search(nullptr, callback_data), FIMDB_ERR);
        callback_data.callback = nullptr;
        ASSERT_EQ(fim_db_file_pattern_search("", callback_data), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBFileINodeSearchNullParameter)
{
    callback_context_t callback_data {};
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW({ ASSERT_EQ(fim_db_file_inode_search(0, 0, callback_data), FIMDB_ERR); });
}

TEST_F(DBTestFixture, TestFimDBGetPathNullParameters)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW(
    {
        callback_context_t callback_data {};
        ASSERT_EQ(fim_db_get_path("/etc/wgetrc", callback_data, false), FIMDB_ERR);
        callback_data.callback = callBackTestFIMEntry;
        ASSERT_EQ(fim_db_get_path(nullptr, callback_data, false), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBFileUpdateNullParameters)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(2));

    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_file_update(nullptr, callback_data_added), FIMDB_ERR);
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_null), FIMDB_ERR);
    });
}

// Test callback to validate inode conversion to string
static void callbackValidateInodeStringConversion(ReturnTypeCallback result_type,
                                                  const cJSON* result_json,
                                                  void* user_data)
{
    ASSERT_TRUE(result_json != NULL);
    ASSERT_TRUE(user_data != NULL);

    // Assert that we received a MODIFIED event (not INSERTED/DELETED)
    ASSERT_EQ(result_type, ReturnTypeCallback::MODIFIED)
            << "Expected MODIFIED event, but got type: " << static_cast<int>(result_type);

    // For MODIFIED events, both "old" and "new" objects must be present
    cJSON* old_obj = cJSON_GetObjectItem(result_json, "old");
    ASSERT_TRUE(old_obj != NULL) << "MODIFIED event must contain 'old' object";

    cJSON* new_obj = cJSON_GetObjectItem(result_json, "new");
    ASSERT_TRUE(new_obj != NULL) << "MODIFIED event must contain 'new' object";

    // Validate "old" object has inode as string
    cJSON* old_inode = cJSON_GetObjectItem(old_obj, "inode");
    ASSERT_TRUE(old_inode != NULL) << "old object must contain 'inode' field";
    ASSERT_TRUE(cJSON_IsString(old_inode)) << "old.inode should be a string, but got type: "
                                           << old_inode->type;
    // Verify the value is correct
    const char* old_inode_str = cJSON_GetStringValue(old_inode);
    ASSERT_TRUE(old_inode_str != NULL);
    ASSERT_STREQ(old_inode_str, "18277083") << "old.inode string value mismatch";

    // Validate "new" object has inode as string
    cJSON* new_inode = cJSON_GetObjectItem(new_obj, "inode");
    ASSERT_TRUE(new_inode != NULL) << "new object must contain 'inode' field";
    ASSERT_TRUE(cJSON_IsString(new_inode)) << "new.inode should be a string, but got type: "
                                           << new_inode->type;
    // Verify the value is correct
    const char* new_inode_str = cJSON_GetStringValue(new_inode);
    ASSERT_TRUE(new_inode_str != NULL);
    ASSERT_STREQ(new_inode_str, "18457083") << "new.inode string value mismatch";
}

TEST_F(DBTestFixture, TestFimDBFileUpdateInodeConversion)
{
    // This test validates that fim_db_file_update converts inode fields
    // from integer to string in both "old" and "new" JSON objects when
    // processing MODIFIED events.

    const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTestUpdated {std::make_unique<FileItem>(updateStatement1["data"].front())};

    EXPECT_NO_THROW(
    {
        // First insert the file (INSERTED event)
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        // Now update the file (MODIFIED event) with custom callback
        callback_context_t callback_inode_validation;
        callback_inode_validation.callback_txn = callbackValidateInodeStringConversion;
        callback_inode_validation.context = &ctx1;

        result = fim_db_file_update(fileFIMTestUpdated->toFimEntry(), callback_inode_validation);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPathNoFile)
{
    callback_context_t callback_data {callBackTestFIMEntry, nullptr};
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "No entry found for /etc/wgetrc"))
    .Times(testing::AtLeast(1));
    EXPECT_NO_THROW({ ASSERT_EQ(fim_db_get_path("/etc/wgetrc", callback_data, false), FIMDB_ERR); });
}

TEST_F(DBTestFixture, TestFimDBInvalidSearchPath)
{
    EXPECT_THROW(
    { DB::instance().searchFile(std::make_tuple(static_cast<FILE_SEARCH_TYPE>(-1), "", "", ""), nullptr); },
    std::runtime_error);
}

TEST_F(DBTestFixture, TestFimDBFileInodeSearchWithBigInode)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement4["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        char* test;
        test = strdup("/etc/wgetrc");
        callback_context_t callback_data;
        callback_data.callback = callbackTestSearchPath;
        callback_data.context = test;
        result = fim_db_file_inode_search(18277083, 2456, callback_data);
        ASSERT_EQ(result, FIMDB_OK);
        os_free(test);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
        callback_data.callback = callbackTestSearch;
        callback_data.context = NULL;
        result = fim_db_file_inode_search(1152921500312810881, 8432, callback_data);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionFileEmptyDB)
{
    EXPECT_NO_THROW(
    {
        auto maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionFileWithEntries)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};
    const auto fileFIMTest3 {std::make_unique<FileItem>(insertStatement3["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_file(5);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 5);
    });
}

TEST_F(DBTestFixture, TestFimDBSetVersionFile)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_file(10);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 10);
    });
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileMultipleTimes)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_file(5);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 5);

        setResult = fim_db_set_version_file(15);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 15);

        setResult = fim_db_set_version_file(20);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 20);
    });
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileWithFileEntries)
{
    const auto fileFIMTest1 {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTest2 {std::make_unique<FileItem>(insertStatement2["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_file(100);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_file();
        ASSERT_EQ(maxVersion, 100);
    });
}

static void callbackTestDeleted(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data)
{
    ASSERT_EQ(result_type, ReturnTypeCallback::DELETED);
    ASSERT_NE(result_json, nullptr);
    ASSERT_EQ(user_data, nullptr);
}

const auto insertSpecialCharsPayload = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"abc123", "device":1234, "gid":"0", "group_":"root",
        "hash_md5":"deadbeefdeadbeefdeadbeefdeadbeef", "hash_sha1":"abc", "hash_sha256":"abc",
        "inode":77777, "mtime":1578075431,
        "path":"/tmp/evil\"UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--",
        "permissions":"-rw-rw-r--", "size":100, "uid":"0", "owner":"root", "version":1, "sync":0}]
    })"_json;

TEST_F(DBTestFixture, TestFimDBGetPathWithSpecialCharsInPath)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertSpecialCharsPayload["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.context = fileFIMTest->toFimEntry();

        result = fim_db_get_path(
                     "/tmp/evil\"UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--",
                     callback_data,
                     false);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPathWithSpecialCharsReturnsNoExtraRows)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.context = nullptr;

        result = fim_db_get_path(
                     "\" UNION SELECT path,checksum,device,inode,size,permissions,attributes,uid,gid,owner,group_,hash_md5,hash_sha1,hash_sha256,mtime,version,sync FROM file_entry--",
                     callback_data, false);
        ASSERT_EQ(result, FIMDB_ERR);
    });
}

static std::vector<std::string> searchPaths(const char* pattern);

TEST_F(DBTestFixture, TestFimDBPatternSearchWithSpecialCharsInPath)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
    });

    ASSERT_EQ(fim_db_get_count_file_entry(), 1);
    EXPECT_TRUE(searchPaths("\" UNION SELECT path FROM file_entry--/%").empty());
}

TEST_F(DBTestFixture, TestFimDBDeletePathWithSpecialCharsInPath)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertSpecialCharsPayload["data"].front())};

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);

        auto count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 1);

        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.callback_txn = callbackTestDeleted;
        callback_data.context = nullptr;

        result = fim_db_get_path(
                     "/tmp/evil\"UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--",
                     callback_data, true);
        ASSERT_EQ(result, FIMDB_OK);

        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 0);
    });
}

static void callbackCollectPaths(void* return_data, void* user_data)
{
    static_cast<std::vector<std::string>*>(user_data)->push_back(static_cast<char*>(return_data));
}

static void insertFilesWithPaths(const std::vector<std::string>& paths)
{
    for (const auto& path : paths)
    {
        nlohmann::json item = insertStatement1["data"].front();
        item["path"] = path;
        const auto fileFIMTest { std::make_unique<FileItem>(item) };
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    }
}

static std::vector<std::string> searchPaths(const char* pattern)
{
    std::vector<std::string> found;
    callback_context_t callback_data { callbackCollectPaths, &found };

    EXPECT_EQ(fim_db_file_pattern_search(pattern, callback_data), FIMDB_OK);

    return found;
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchPrefixBoundaries)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a", "/data/a.", "/data/a/f1", "/data/a/sub/f2", "/data/a0", "/data/a0/x", "/data/a1", "/data/ab/f3"}));

    EXPECT_EQ(searchPaths("/data/a/%"), (std::vector<std::string> {"/data/a/f1", "/data/a/sub/f2"}));
    EXPECT_EQ(searchPaths("/data/ab/%"), (std::vector<std::string> {"/data/ab/f3"}));
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchPrefixWithPercentChar)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a/f1", "/data/axb/f4", "/data/%/x", "/data/%/y/z"}));

    EXPECT_EQ(searchPaths("/data/%/%"), (std::vector<std::string> {"/data/%/x", "/data/%/y/z"}));
    EXPECT_TRUE(searchPaths("/data/%x/%").empty());
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchPrefixWithUnderscoreChar)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a_b/f1", "/data/a/b/f2", "/data/axb/f3"}));

    EXPECT_EQ(searchPaths("/data/a_b/%"), (std::vector<std::string> {"/data/a_b/f1"}));
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchPrefixExactBytes)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/dir/f", "/data/Dir/f"}));

    EXPECT_EQ(searchPaths("/data/Dir/%"), (std::vector<std::string> {"/data/Dir/f"}));
    EXPECT_EQ(searchPaths("/data/dir/%"), (std::vector<std::string> {"/data/dir/f"}));
    EXPECT_TRUE(searchPaths("/data/DIR/%").empty());
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchWindowsStylePrefix)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"c:\\data\\a\\b\\f", "c:\\data\\a_b\\f", "c:\\data\\a_b]", "c:\\data\\a_b]x", "c:\\data\\axb\\f"}));

    EXPECT_EQ(searchPaths("c:\\data\\a_b\\%"), (std::vector<std::string> {"c:\\data\\a_b\\f"}));
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchNonAsciiPrefix)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/caf\xC3\xA9/f", "/data/caf\xC3\xA9x/f", "/data/cafe/f"}));

    EXPECT_EQ(searchPaths("/data/caf\xC3\xA9/%"), (std::vector<std::string> {"/data/caf\xC3\xA9/f"}));
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchEmptyPrefix)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a/f1"}));

    EXPECT_TRUE(searchPaths("").empty());
    EXPECT_TRUE(searchPaths("%").empty());
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchPrefixWithoutSeparator)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a/f1", "/data/a0/x", "/data/ab/y", "/data/b/z"}));

    EXPECT_TRUE(searchPaths("/data/a%").empty());
    EXPECT_TRUE(searchPaths("/data/a\xFF%").empty());
    EXPECT_TRUE(searchPaths("/data/a/").empty());
    EXPECT_TRUE(searchPaths("/%").empty());
}

static void callbackRemoveAndCollect(void* return_data, void* user_data)
{
    const std::string path { static_cast<char*>(return_data) };
    static_cast<std::vector<std::string>*>(user_data)->push_back(path);

    // Same nested lookup and delete as the production delete path.
    callback_context_t deleteCallback;
    deleteCallback.callback_txn = callbackTestDeleted;
    deleteCallback.context = nullptr;
    EXPECT_EQ(fim_db_get_path(path.c_str(), deleteCallback, true), FIMDB_OK);
}

TEST_F(DBTestFixture, TestFimDBFilePatternSearchRemoveDuringSearch)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a/b/c/f3", "/data/a/b/f2", "/data/a/f1", "/data/a/z", "/data/a0/x", "/data/ab/y"}));

    std::vector<std::string> removed;
    callback_context_t callback_data { callbackRemoveAndCollect, &removed };

    EXPECT_EQ(fim_db_file_pattern_search("/data/a/%", callback_data), FIMDB_OK);
    EXPECT_EQ(removed, (std::vector<std::string> {"/data/a/b/c/f3", "/data/a/b/f2", "/data/a/f1", "/data/a/z"}));
    EXPECT_TRUE(searchPaths("/data/a/%").empty());
    EXPECT_EQ(searchPaths("/data/a0/%"), (std::vector<std::string> {"/data/a0/x"}));
    EXPECT_EQ(searchPaths("/data/ab/%"), (std::vector<std::string> {"/data/ab/y"}));
    EXPECT_EQ(fim_db_get_count_file_entry(), 2);
}

static void callbackFileUpdateAny(ReturnTypeCallback, const cJSON*, void*) {}

static nlohmann::json fileRow(const std::string& path)
{
    nlohmann::json row;
    DB::instance().getFile(path, [&row](const nlohmann::json & result)
    {
        row = result;
    });
    return row;
}

static nlohmann::json fileItemWithChecksum(const std::string& path, const std::string& checksum)
{
    nlohmann::json item = insertStatement1["data"].front();
    item["path"] = path;
    item["checksum"] = checksum;
    return item;
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileKeepsContent)
{
    const auto fileFIMTest {std::make_unique<FileItem>(insertStatement1["data"].front())};
    const auto fileFIMTestUpdated {std::make_unique<FileItem>(updateStatement1["data"].front())};

    ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_data_added), FIMDB_OK);
    ASSERT_EQ(fim_db_file_update(fileFIMTestUpdated->toFimEntry(), callback_data_modified), FIMDB_OK);

    ASSERT_EQ(fim_db_set_version_file(10), 0);

    const auto row = fileRow("/etc/wgetrc");
    EXPECT_EQ(row.at("checksum"), updateStatement1["data"].front().at("checksum"));
    EXPECT_EQ(row.at("hash_sha1"), updateStatement1["data"].front().at("hash_sha1"));
    EXPECT_EQ(row.at("version"), 10);
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileOnlyRaises)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/high"}));
    ASSERT_EQ(fim_db_set_version_file(12), 0);
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/low"}));

    ASSERT_EQ(fim_db_set_version_file(10), 0);

    EXPECT_EQ(fileRow("/data/high").at("version"), 12);
    EXPECT_EQ(fileRow("/data/low").at("version"), 10);
}

// DBSync that runs a hook around the version update. Setting the version by reading the whole table
// and rewriting each row lost a row written in between: the hook after a full read of the table is
// that write. With the single update there is no such point, so the hook runs right before it.
class DBSyncWithRaceHook final : public DBSync
{
    public:
        using DBSync::DBSync;

        void selectRows(const nlohmann::json& jsInput, ResultCallbackData callbackData) override
        {
            DBSync::selectRows(jsInput, callbackData);

            if (jsInput.at("query").at("column_list") == nlohmann::json::array({"*"}))
            {
                runHookOnce();
            }
        }

        void setEachEntryVersion(const std::string& tableName, const long long version) override
        {
            runHookOnce();
            DBSync::setEachEntryVersion(tableName, version);
        }

        std::function<void(DBSync&)> m_hook;

    private:
        void runHookOnce()
        {
            if (m_hook)
            {
                const auto hook {std::move(m_hook)};
                m_hook = nullptr;
                hook(*this);
            }
        }
};

TEST_F(DBTestFixture, TestFimDBSetVersionFileKeepsRowWrittenMeanwhile)
{
    constexpr auto NEW_CHECKSUM {"e89f3b4c21c2005896c964462da4766057dd94e9"};

    auto dbsyncHandler {std::make_shared<DBSyncWithRaceHook>(HostType::AGENT,
                                                             DbEngineType::SQLITE3,
                                                             FIM_DB_MEMORY_PATH,
                                                             FIMDBCreator<OS_TYPE>::CreateStatement(),
                                                             DbManagement::PERSISTENT)};
    FIMDB::instance().init([](modules_log_level_t, const std::string&) {}, dbsyncHandler, MAX_FILE_LIMIT, 100000);

    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a", "/data/b", "/data/c"}));

    // An event changes /data/b at the hook point. Like a real event, it carries no version, so
    // the row gets the next one.
    dbsyncHandler->m_hook = [&](DBSync & dbsync)
    {
        auto item = fileItemWithChecksum("/data/b", NEW_CHECKSUM);
        item.erase("version");
        item.erase("sync");

        nlohmann::json input;
        input["table"] = FIMDB_FILE_TABLE_NAME;
        input["data"] = nlohmann::json::array({item});
        dbsync.DBSync::syncRow(input, [](ReturnTypeCallback, const nlohmann::json&) {});
    };

    ASSERT_EQ(fim_db_set_version_file(10), 0);
    ASSERT_FALSE(dbsyncHandler->m_hook) << "the concurrent write never ran";

    const auto row = fileRow("/data/b");
    EXPECT_EQ(row.at("checksum").get<std::string>(), NEW_CHECKSUM);
    EXPECT_EQ(row.at("version"), 10);
    EXPECT_EQ(fileRow("/data/a").at("version"), 10);
    EXPECT_EQ(fileRow("/data/c").at("version"), 10);
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileReportsADatabaseError)
{
    auto dbsyncHandler {std::make_shared<DBSyncWithRaceHook>(HostType::AGENT,
                                                             DbEngineType::SQLITE3,
                                                             FIM_DB_MEMORY_PATH,
                                                             FIMDBCreator<OS_TYPE>::CreateStatement(),
                                                             DbManagement::PERSISTENT)};
    const auto loggedError {std::make_shared<std::string>()};
    FIMDB::instance().init([loggedError](modules_log_level_t level, const std::string & log)
    {
        if (LOG_ERROR == level)
        {
            *loggedError = log;
        }
    }, dbsyncHandler, MAX_FILE_LIMIT, 100000);

    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a"}));

    dbsyncHandler->m_hook = [](DBSync&)
    {
        throw std::runtime_error {"disk I/O error"};
    };

    EXPECT_EQ(fim_db_set_version_file(10), -1);
    EXPECT_EQ(*loggedError, "Error setting the version for table file_entry: disk I/O error");
    EXPECT_EQ(fileRow("/data/a").at("version"), 1);
}

TEST_F(DBTestFixture, TestFimDBSetVersionFileUnderConcurrentWrites)
{
    constexpr auto ROWS {2000};
    constexpr auto SET_VERSION_CALLS {50};

    std::vector<std::string> paths;

    for (auto i {0}; i < ROWS; ++i)
    {
        paths.push_back("/data/f" + std::to_string(i));
    }

    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths(paths));

    std::vector<std::string> lastChecksum(ROWS, insertStatement1["data"].front().at("checksum").get<std::string>());
    std::atomic<bool> stop {false};
    std::atomic<int> writes {0};

    std::thread writer
    {
        [&]()
        {
            callback_context_t callback;
            callback.callback_txn = callbackFileUpdateAny;
            callback.context = &ctx1;
            unsigned int seed {12345};

            while (!stop)
            {
                seed = seed * 1103515245u + 12345u;
                const auto index {(seed >> 8) % ROWS};
                const auto checksum {"checksum-" + std::to_string(++writes)};
                const auto item {std::make_unique<FileItem>(fileItemWithChecksum(paths[index], checksum))};

                if (fim_db_file_update(item->toFimEntry(), callback) == FIMDB_OK)
                {
                    lastChecksum[index] = checksum;
                }
            }
        }};

    auto version {100};

    for (auto i {0}; i < SET_VERSION_CALLS; ++i)
    {
        // Let the writer land some rows between two calls
        const auto writesBefore {writes.load()};

        while (writes.load() < writesBefore + 20)
        {
            std::this_thread::yield();
        }

        version += 100;
        EXPECT_EQ(fim_db_set_version_file(version), 0);
    }

    stop = true;
    writer.join();

    for (auto i {0}; i < ROWS; ++i)
    {
        const auto row = fileRow(paths[i]);
        ASSERT_EQ(row.at("checksum"), lastChecksum[i]) << paths[i];
        ASSERT_GE(row.at("version").get<int>(), version) << paths[i];
    }
}

TEST_F(DBTestFixture, TestFimDBFileDelete)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a", "/data/b"}));

    EXPECT_EQ(fim_db_file_delete("/data/a"), FIMDB_OK);

    EXPECT_EQ(fim_db_get_count_file_entry(), 1);
    EXPECT_EQ(fileRow("/data/b").at("path"), "/data/b");
}

static std::promise<void>* deleteCallbackEntered;
static std::shared_future<void>* deleteCallbackRelease;

static void callbackTestDeletedBlocking(ReturnTypeCallback result_type, const cJSON*, void*)
{
    EXPECT_EQ(result_type, ReturnTypeCallback::DELETED);
    deleteCallbackEntered->set_value();
    deleteCallbackRelease->wait();
}

TEST_F(DBTestFixture, TestFimDBQuiesceWaitsForDeleteInFlight)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a"}));

    std::promise<void> entered;
    std::promise<void> release;
    std::shared_future<void> releaseFuture {release.get_future()};
    deleteCallbackEntered = &entered;
    deleteCallbackRelease = &releaseFuture;

    std::thread deleter
    {
        []()
        {
            callback_context_t callback;
            callback.callback = nullptr;
            callback.callback_txn = callbackTestDeletedBlocking;
            callback.context = nullptr;
            EXPECT_EQ(fim_db_get_path("/data/a", callback, true), FIMDB_OK);
        }};

    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);

    // The row is gone and its DELETED event is still being reported: quiesce has to wait for it
    auto quiesced {std::async(std::launch::async, []()
    {
        fim_db_quiesce();
    })};
    EXPECT_EQ(quiesced.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    release.set_value();
    EXPECT_EQ(quiesced.wait_for(std::chrono::seconds(10)), std::future_status::ready);
    deleter.join();

    // Initialized again to read the table: the delete in flight was applied
    FIMDB::instance().init([](modules_log_level_t, const std::string&) {},
                           FIMDB::instance().DBSyncHandler(), MAX_FILE_LIMIT, 100000);
    EXPECT_EQ(fim_db_get_count_file_entry(), 0);
}

TEST_F(DBTestFixture, TestFimDBQuiesceStopsRowWrites)
{
    ASSERT_NO_FATAL_FAILURE(insertFilesWithPaths({"/data/a", "/data/b"}));

    EXPECT_CALL(*mockLog, loggingFunction(testing::_, testing::_)).Times(testing::AnyNumber());
    EXPECT_CALL(*mockLog,
                loggingFunction(LOG_WARNING, "FIM is busy or shutting down, version not set for table file_entry"));

    fim_db_quiesce();

    const auto updated {std::make_unique<FileItem>(fileItemWithChecksum("/data/a", "not-written"))};
    callback_context_t callback;
    callback.callback_txn = callbackFileUpdateAny;
    callback.context = &ctx1;
    EXPECT_EQ(fim_db_file_update(updated->toFimEntry(), callback), FIMDB_OK);

    // A delete does not even find the row, so nothing is removed or reported
    callback_context_t deleteCallback;
    deleteCallback.callback_txn = callbackTestDeleted;
    deleteCallback.context = nullptr;
    EXPECT_EQ(fim_db_get_path("/data/b", deleteCallback, true), FIMDB_ERR);

    EXPECT_EQ(fim_db_set_version_file(10), -1);

    // Initialized again to read the table: nothing changed after the quiesce
    FIMDB::instance().init([](modules_log_level_t, const std::string&) {},
                           FIMDB::instance().DBSyncHandler(), MAX_FILE_LIMIT, 100000);
    EXPECT_EQ(fim_db_get_count_file_entry(), 2);
    const auto row = fileRow("/data/a");
    EXPECT_EQ(row.at("checksum"), insertStatement1["data"].front().at("checksum"));
    EXPECT_EQ(row.at("version"), 1);
}
