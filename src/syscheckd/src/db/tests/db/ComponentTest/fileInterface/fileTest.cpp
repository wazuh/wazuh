/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * December 31, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbTest.h"
#include "dbFileItem.hpp"
#include "db.h"
#include "db.hpp"
#include "fimDBTests/fimDBImpTests.hpp"

const auto insertStatement1 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2456, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":"0", "user_name":"fakeUser"}]
    }
)"_json;
const auto insertStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2221, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":"0", "user_name":"fakeUser"}]
    }
)"_json;
const auto insertStatement3 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":8432, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":99997083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test2.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":"0", "user_name":"fakeUser"}]
    }
)"_json;
const auto insertStatement4 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":8432, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810881, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test3.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4925,
        "uid":"0", "user_name":"fakeUser"}]
    }
)"_json;
const auto updateStatement1 = R"({
        "table": "file_entry",
        "data":[{"attributes":"11", "checksum":"e89f3b4c21c2005896c964462da4766057dd94e9", "dev":2151, "gid":"1000", "group_name":"test",
        "hash_md5":"d6719d8eaa46012a9de38103d5f284e4", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58a",
        "hash_sha256":"0211f049f5b1121fbd034adf7b81ea521d615b5bd8df0e77c8ec8a363459ead1", "inode":18457083, "last_event":1596489275,
        "mode":0, "mtime":1578075435, "options":131583, "path":"/etc/wgetrc", "perm":"-rw-rw-rw-", "scanned":1, "size":4925,
        "uid":"1000", "user_name":"testuser"}]
    }
)"_json;
const auto updateStatement2 = R"({
        "table": "file_entry",
        "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "dev":2151, "gid":"0", "group_name":"root",
        "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":18277083, "last_event":1596489275,
        "mode":0, "mtime":1578075431, "options":131583, "path":"/tmp/test.txt", "perm":"-rw-rw-r--", "scanned":1, "size":4800,
        "uid":"0", "user_name":"fakeUser"}]
    }
)"_json;

static void callbackTestSearch(void* return_data, void* user_data)
{
    char *path = (char *)return_data;
    ASSERT_TRUE(user_data == NULL);
    ASSERT_TRUE(path);
}

static void callbackTestSearchPath(void* return_data, void* user_data)
{
    char *returnPath = (char *) return_data;
    char *path = (char *) user_data;
    ASSERT_EQ(std::strcmp(returnPath, path), 0);
}

static void callBackTestFIMEntry(void* return_data, void* user_data)
{
    fim_entry *entry = (fim_entry *) user_data;
    fim_entry *returnEntry = (fim_entry *) return_data;

    ASSERT_EQ(std::strcmp(entry->file_entry.path, returnEntry->file_entry.path), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->attributes, returnEntry->file_entry.data->attributes), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->checksum, returnEntry->file_entry.data->checksum), 0);
    ASSERT_EQ(entry->file_entry.data->dev, returnEntry->file_entry.data->dev);
    ASSERT_EQ(entry->file_entry.data->inode, returnEntry->file_entry.data->inode);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_md5, returnEntry->file_entry.data->hash_md5), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_sha1, returnEntry->file_entry.data->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->hash_sha256, returnEntry->file_entry.data->hash_sha256), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->gid, returnEntry->file_entry.data->gid), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->group_name, returnEntry->file_entry.data->group_name), 0);
    ASSERT_EQ(entry->file_entry.data->last_event, returnEntry->file_entry.data->last_event);
    ASSERT_EQ(entry->file_entry.data->mode, returnEntry->file_entry.data->mode);
    ASSERT_EQ(entry->file_entry.data->mtime, returnEntry->file_entry.data->mtime);
    ASSERT_EQ(entry->file_entry.data->options, returnEntry->file_entry.data->options);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->perm, returnEntry->file_entry.data->perm), 0);
    ASSERT_EQ(entry->file_entry.data->scanned, returnEntry->file_entry.data->scanned);
    ASSERT_EQ(entry->file_entry.data->size, returnEntry->file_entry.data->size);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->uid, returnEntry->file_entry.data->uid), 0);
    ASSERT_EQ(std::strcmp(entry->file_entry.data->user_name, returnEntry->file_entry.data->user_name), 0);
}

TEST_F(DBTestFixture, TestFimDBFileUpdate)
{

    EXPECT_NO_THROW(
    {
        const auto fileFIMTest { std::make_unique<FileItem>(insertStatement1["data"].front()) };
        const auto fileFIMTestUpdated { std::make_unique<FileItem>(updateStatement1["data"].front()) };
        const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
        const auto fileFIMTestUpdated2 { std::make_unique<FileItem>(updateStatement2["data"].front()) };

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
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };
    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/etc/wgetrc");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test.txt");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test2.txt");
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPath)
{
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        const auto fileFIMTest { std::make_unique<FileItem>(insertStatement1["data"].front()) };
        callback_context_t callback_data;
        callback_data.callback = callBackTestFIMEntry;
        callback_data.context = fileFIMTest->toFimEntry();
        result = fim_db_get_path("/etc/wgetrc", callback_data);
        ASSERT_EQ(result, FIMDB_OK);
    });
}

TEST_F(DBTestFixture, TestFimDBGetCountFileEntry)
{
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

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
        result = fim_db_remove_path("/etc/wgetrc");
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 2);
        result =fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 3);
        result =fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 3);
        result = fim_db_remove_path("/etc/wgetrc");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test.txt");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test2.txt");
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_entry();
        ASSERT_EQ(count, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetCountFileInode)
{
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

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
        result = fim_db_remove_path("/etc/wgetrc");
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 2);
        result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 3);
        result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_modified);
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 3);
        result = fim_db_remove_path("/etc/wgetrc");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test.txt");
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_remove_path("/tmp/test2.txt");
        ASSERT_EQ(result, FIMDB_OK);
        count = fim_db_get_count_file_inode();
        ASSERT_EQ(count, 0);
    });
}


TEST_F(DBTestFixture, TestFimDBFileInodeSearch)
{
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        char *test;
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
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement2["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

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
        char *test;
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
    callback_context_t callback_data{};
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
    callback_context_t callback_data{};
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW(
    {
               ASSERT_EQ(fim_db_file_inode_search(0, 0, callback_data), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPathNullParameters)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW(
    {
        callback_context_t callback_data {};
        ASSERT_EQ(fim_db_get_path("/etc/wgetrc", callback_data), FIMDB_ERR);
        callback_data.callback = callBackTestFIMEntry;
        ASSERT_EQ(fim_db_get_path(nullptr, callback_data), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBRemovePathNullParameter)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_remove_path(nullptr), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBFileUpdateNullParameters)
{
    const auto fileFIMTest { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "Invalid parameters")).Times(testing::AtLeast(2));

    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_file_update(nullptr, callback_data_added), FIMDB_ERR);
        ASSERT_EQ(fim_db_file_update(fileFIMTest->toFimEntry(), callback_null), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBGetPathNoFile)
{
    callback_context_t callback_data {callBackTestFIMEntry, nullptr};
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "No entry found for /etc/wgetrc")).Times(testing::AtLeast(1));
    EXPECT_NO_THROW(
    {
        ASSERT_EQ(fim_db_get_path("/etc/wgetrc", callback_data), FIMDB_ERR);
    });
}

TEST_F(DBTestFixture, TestFimDBInvalidSearchPath)
{
    EXPECT_THROW(
    {
        DB::instance().searchFile(std::make_tuple(static_cast<FILE_SEARCH_TYPE>(-1), "","",""), nullptr);
    }, std::runtime_error);
}

TEST_F(DBTestFixture, TestFimDBFileInodeSearchWithBigInode)
{
    const auto fileFIMTest1 { std::make_unique<FileItem>(insertStatement1["data"].front()) };
    const auto fileFIMTest2 { std::make_unique<FileItem>(insertStatement4["data"].front()) };
    const auto fileFIMTest3 { std::make_unique<FileItem>(insertStatement3["data"].front()) };

    EXPECT_NO_THROW(
    {
        auto result = fim_db_file_update(fileFIMTest1->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest2->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        result = fim_db_file_update(fileFIMTest3->toFimEntry(), callback_data_added);
        ASSERT_EQ(result, FIMDB_OK);
        char *test;
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
