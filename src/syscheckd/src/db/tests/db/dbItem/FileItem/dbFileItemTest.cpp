/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 5, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbFileItem.hpp"
#include "dbFileItemTest.h"
#include "syscheck.h"

void FileItemTest::SetUp()
{
    fimEntryTest = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_file_data* data = reinterpret_cast<fim_file_data*>(std::calloc(1, sizeof(fim_file_data)));

    fimEntryTest->type = FIM_TYPE_FILE;
    fimEntryTest->file_entry.path = const_cast<char*>("/etc/wgetrc");
    data->attributes = const_cast<char*>("10");
    std::snprintf(data->checksum, sizeof(data->checksum), "a2fbef8f81af27155dcee5e3927ff6243593b91a");
    data->device = 2051;
    data->gid = const_cast<char*>("0");
    data->group = const_cast<char*>("root");
    std::snprintf(data->hash_md5, sizeof(data->hash_md5), "4b531524aa13c8a54614100b570b3dc7");
    std::snprintf(data->hash_sha1, sizeof(data->hash_sha1), "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b");
    std::snprintf(data->hash_sha256,
                  sizeof(data->hash_sha256),
                  "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a");
    data->inode = 1152921500312810880;
    data->mtime = 1578075431;
    data->permissions = const_cast<char*>("-rw-rw-r--");
    data->size = 4925;
    data->uid = const_cast<char*>("0");
    data->owner = const_cast<char*>("fakeUser");
    fimEntryTest->file_entry.data = data;
}

void FileItemTest::TearDown()
{
    os_free(fimEntryTest->file_entry.data);
    os_free(fimEntryTest);
}

TEST_F(FileItemTest, fileItemConstructorFromFIM)
{
    EXPECT_NO_THROW({
        auto file = new FileItem(fimEntryTest);
        delete file;
    });
}

TEST_F(FileItemTest, fileItemConstructorFromFIMWithNullParameters)
{
    fim_entry* fimEntryTestNull = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_file_data* data = reinterpret_cast<fim_file_data*>(std::calloc(1, sizeof(fim_file_data)));

    fimEntryTestNull->type = FIM_TYPE_FILE;
    fimEntryTestNull->file_entry.path = NULL;
    data->attributes = NULL;
    data->checksum[0] = '\0';
    data->device = 0;
    data->gid = NULL;
    data->group = NULL;
    data->hash_md5[0] = '\0';
    data->hash_sha1[0] = '\0';
    data->hash_sha256[0] = '\0';
    data->inode = 0;
    data->mtime = 0;
    data->permissions = NULL;
    data->size = 0;
    data->uid = NULL;
    data->owner = NULL;
    fimEntryTestNull->file_entry.data = data;
    EXPECT_NO_THROW({
        auto file = new FileItem(fimEntryTestNull);
        delete file;
    });
    os_free(data);
    os_free(fimEntryTestNull);
}

TEST_F(FileItemTest, fileItemConstructorFromJSON)
{
    const auto insertJSON = R"(
        {
            "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2051, "gid":"0", "group_":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810880,
            "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
            "uid":"0", "owner":"fakeUser"
        }
    )"_json;
    EXPECT_NO_THROW({
        auto fileTest = new FileItem(insertJSON);
        delete fileTest;
    });
}

TEST_F(FileItemTest, getFIMEntryWithFimCtr)
{
    auto file = new FileItem(fimEntryTest);
    auto fileEntry = file->toFimEntry();
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.path, fimEntryTest->file_entry.path), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->attributes, fimEntryTest->file_entry.data->attributes), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->checksum, fimEntryTest->file_entry.data->checksum), 0);
    ASSERT_EQ(fileEntry->file_entry.data->device, fimEntryTest->file_entry.data->device);
    ASSERT_EQ(fileEntry->file_entry.data->inode, fimEntryTest->file_entry.data->inode);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_md5, fimEntryTest->file_entry.data->hash_md5), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha1, fimEntryTest->file_entry.data->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha256, fimEntryTest->file_entry.data->hash_sha256), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->gid, fimEntryTest->file_entry.data->gid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->group, fimEntryTest->file_entry.data->group), 0);
    ASSERT_EQ(fileEntry->file_entry.data->mtime, fimEntryTest->file_entry.data->mtime);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->permissions, fimEntryTest->file_entry.data->permissions), 0);
    ASSERT_EQ(fileEntry->file_entry.data->size, fimEntryTest->file_entry.data->size);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->uid, fimEntryTest->file_entry.data->uid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->owner, fimEntryTest->file_entry.data->owner), 0);

    delete file;
}

TEST_F(FileItemTest, getFIMEntryWithJSONCtr)
{
    const auto insertJSON = R"(
        {
            "attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2051, "gid":"0", "group_":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810880,
            "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
            "uid":"0", "owner":"fakeUser"
        }
    )"_json;
    auto file = new FileItem(insertJSON);
    auto fileEntry = file->toFimEntry();
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.path, fimEntryTest->file_entry.path), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->attributes, fimEntryTest->file_entry.data->attributes), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->checksum, fimEntryTest->file_entry.data->checksum), 0);
    ASSERT_EQ(fileEntry->file_entry.data->device, fimEntryTest->file_entry.data->device);
    ASSERT_EQ(fileEntry->file_entry.data->inode, fimEntryTest->file_entry.data->inode);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_md5, fimEntryTest->file_entry.data->hash_md5), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha1, fimEntryTest->file_entry.data->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha256, fimEntryTest->file_entry.data->hash_sha256), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->gid, fimEntryTest->file_entry.data->gid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->group, fimEntryTest->file_entry.data->group), 0);
    ASSERT_EQ(fileEntry->file_entry.data->mtime, fimEntryTest->file_entry.data->mtime);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->permissions, fimEntryTest->file_entry.data->permissions), 0);
    ASSERT_EQ(fileEntry->file_entry.data->size, fimEntryTest->file_entry.data->size);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->uid, fimEntryTest->file_entry.data->uid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->owner, fimEntryTest->file_entry.data->owner), 0);

    delete file;
}

TEST_F(FileItemTest, getJSONWithFimCtr)
{
    auto file = new FileItem(fimEntryTest);
    const auto expectedValue = R"(
        {
            "table": "file_entry",
            "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2051, "gid":"0", "group_":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810880,
            "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
            "uid":"0", "owner":"fakeUser"}]
        }
    )"_json;
    ASSERT_TRUE(*file->toJSON() == expectedValue);
    delete file;
}

TEST_F(FileItemTest, getJSONWithJSONCtr)
{
    auto file = new FileItem(fimEntryTest);
    const auto expectedValue = R"(
        {
            "table": "file_entry",
            "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2051, "gid":"0", "group_":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810880,
            "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
            "uid":"0", "owner":"fakeUser"}]
        }
    )"_json;
    ASSERT_TRUE(*file->toJSON() == expectedValue);
    delete file;
}

TEST_F(FileItemTest, fileItemReportOldData)
{
    auto file = new FileItem(fimEntryTest, true);
    const auto expectedValue = R"(
        {
            "table": "file_entry",
            "data":[{"attributes":"10", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "device":2051, "gid":"0", "group_":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7", "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "inode":1152921500312810880,
            "mtime":1578075431, "path":"/etc/wgetrc", "permissions":"-rw-rw-r--", "size":4925,
            "uid":"0", "owner":"fakeUser"}],"options":{"return_old_data": true}
        }
    )"_json;
    ASSERT_TRUE(*file->toJSON() == expectedValue);
    delete file;
}
