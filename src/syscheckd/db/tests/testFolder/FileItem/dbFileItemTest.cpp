/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
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


void FileItemTest::SetUp() {
    fimEntryTest = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_file_data* data = reinterpret_cast<fim_file_data*>(std::calloc(1, sizeof(fim_file_data)));

    fimEntryTest->type = FIM_TYPE_FILE;
    fimEntryTest->file_entry.path = const_cast<char*>("/tmp/hello_world.txt");
    data->attributes = const_cast<char*>("10");
    std::strncpy(data->checksum, "0f05afadabd7e2bc6840e85b0dd1ad2902de9635", sizeof(data->checksum));
    data->dev = 3;
    data->gid = const_cast<char*>("7");
    data->group_name = const_cast<char*>("fakeGroup");
    std::strncpy(data->hash_md5, "d41d8cd98f00b204e9800998ecf8427e", sizeof(data->hash_md5));
    std::strncpy(data->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", sizeof(data->hash_sha1));
    std::strncpy(data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sizeof(data->hash_sha256));
    data->inode = 0;
    data->last_event = std::time_t(0);
    data->mode = FIM_SCHEDULED;
    data->mtime = std::time_t(0);
    data->options = 0;
    data->perm = const_cast<char*>("-rw-rw-r--");
    data->scanned = 1;
    data->size = 3732;
    data->uid = const_cast<char*>("82");
    data->user_name = const_cast<char*>("fakeUser");
    fimEntryTest->file_entry.data = data;
}

void FileItemTest::TearDown() {
}

TEST_F(FileItemTest, fileFileConstructorFromFIM) {
    EXPECT_NO_THROW({
       auto file = new FileItem(fimEntryTest);
       delete file;
    });
}

TEST_F(FileItemTest, fileFileConstructorFromParameters) {
    EXPECT_NO_THROW({
        auto file = new FileItem("/tmp/hello_world.txt",
                                 "0f05afadabd7e2bc6840e85b0dd1ad2902de9635",
                                 std::time_t(0), FIM_SCHEDULED,
                                 1, 0, 0, 0, std::time_t(0), 3732, 3, 0, "10",
                                 "fakeGroup", "d41d8cd98f00b204e9800998ecf8427e", "-rw-rw-r--",
                                 "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "fakeUser");
        delete file;
    });
}

TEST_F(FileItemTest, getFIMEntry) {
    auto file = new FileItem("/tmp/hello_world.txt",
                             "0f05afadabd7e2bc6840e85b0dd1ad2902de9635",
                             std::time_t(0), FIM_SCHEDULED,
                             1, 0, 82, 7, std::time_t(0), 3732, 3, 0, "10",
                             "fakeGroup", "d41d8cd98f00b204e9800998ecf8427e", "-rw-rw-r--",
                             "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "fakeUser");
    auto fileEntry = file->toFimEntry();
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.path, fimEntryTest->file_entry.path), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->attributes, fimEntryTest->file_entry.data->attributes), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->checksum, fimEntryTest->file_entry.data->checksum), 0);
    ASSERT_EQ(fileEntry->file_entry.data->dev, fimEntryTest->file_entry.data->dev);
    ASSERT_EQ(fileEntry->file_entry.data->inode, fimEntryTest->file_entry.data->inode);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_md5, fimEntryTest->file_entry.data->hash_md5), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha1, fimEntryTest->file_entry.data->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->hash_sha256, fimEntryTest->file_entry.data->hash_sha256), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->gid, fimEntryTest->file_entry.data->gid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->group_name, fimEntryTest->file_entry.data->group_name), 0);
    ASSERT_EQ(fileEntry->file_entry.data->last_event, fimEntryTest->file_entry.data->last_event);
    ASSERT_EQ(fileEntry->file_entry.data->mode, fimEntryTest->file_entry.data->mode);
    ASSERT_EQ(fileEntry->file_entry.data->mtime, fimEntryTest->file_entry.data->mtime);
    ASSERT_EQ(fileEntry->file_entry.data->options, fimEntryTest->file_entry.data->options);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->perm, fimEntryTest->file_entry.data->perm), 0);
    ASSERT_EQ(fileEntry->file_entry.data->scanned, fimEntryTest->file_entry.data->scanned);
    ASSERT_EQ(fileEntry->file_entry.data->size, fimEntryTest->file_entry.data->size);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->uid, fimEntryTest->file_entry.data->uid), 0);
    ASSERT_EQ(std::strcmp(fileEntry->file_entry.data->user_name, fimEntryTest->file_entry.data->user_name), 0);

    delete file;
}

TEST_F(FileItemTest, getJSON) {
    auto file = new FileItem(fimEntryTest);
    const auto expectedValue {
        R"({"attributes":"10", "checksum":"0f05afadabd7e2bc6840e85b0dd1ad2902de9635", "dev":3, "gid":7, "group_name":"fakeGroup",
            "hash_md5":"d41d8cd98f00b204e9800998ecf8427e", "hash_sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "hash_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "inode":0, "last_event":0, "mode":0,
            "mtime":0, "options":0, "path":"/tmp/hello_world.txt", "perm":"-rw-rw-r--", "scanned":1, "size":3732, "uid":82,
            "user_name":"fakeUser"})"_json
    };
    ASSERT_TRUE(expectedValue.dump().find(file->toJSON()->dump()) != std::string::npos);
    delete file;
}
