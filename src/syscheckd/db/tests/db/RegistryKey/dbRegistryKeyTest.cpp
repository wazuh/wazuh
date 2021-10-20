/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryKey.hpp"
#include "dbRegistryKeyTest.h"
#include "syscheck.h"


void RegistryKeyTest::SetUp()
{
    fimEntryTest = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_registry_key* key = reinterpret_cast<fim_registry_key*>(std::calloc(1, sizeof(fim_registry_key)));

    fimEntryTest->type = FIM_TYPE_REGISTRY;
    key->arch = ARCH_64BIT;
    std::strncpy(key->checksum, "a2fbef8f81af27155dcee5e3927ff6243593b91a", sizeof(key->checksum));
    key->gid = const_cast<char*>("0");
    key->group_name = const_cast<char*>("root");
    key->id = 50;
    key->last_event = 1596489275;
    key->mtime = 1578075431;
    key->path = const_cast<char*>("HKEY_LOCAL_MACHINE\\SOFTWARE");
    key->perm = const_cast<char*>("-rw-rw-r--");
    key->scanned = 1;
    key->uid = const_cast<char*>("0");
    key->user_name = const_cast<char*>("fakeUser");
    fimEntryTest->registry_entry.key = key;
}

void RegistryKeyTest::TearDown()
{
    free(fimEntryTest->registry_entry.key);
    free(fimEntryTest);
}

TEST_F(RegistryKeyTest, registryKeyConstructorFromFIM)
{
    EXPECT_NO_THROW(
    {
        auto key = new RegistryKey(fimEntryTest);
        auto scanned = key->state();
        EXPECT_TRUE(scanned);
        delete key;
    });
}

TEST_F(RegistryKeyTest, registryKeyConstructorFromParameters)
{
    EXPECT_NO_THROW(
    {
        auto key = new RegistryKey("50", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, ARCH_64BIT,
                                   0, "root", "HKEY_LOCAL_MACHINE\\SOFTWARE", "-rw-rw-r--", 1578075431, 0, "fakeUser");
        auto scanned = key->state();
        EXPECT_TRUE(scanned);
        delete key;
    });
}

TEST_F(RegistryKeyTest, registryKeyConstructorFromJSON)
{
    const auto json = R"(
        {
            "id":"50", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root", "arch":1,
            "last_event":1596489275, "mode":0, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--", "scanned":1,
            "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    EXPECT_NO_THROW(
    {
        auto keyTest = new RegistryKey(json);
        auto scanned = keyTest->state();
        EXPECT_TRUE(scanned);
        delete keyTest;
    });
}

TEST_F(RegistryKeyTest, getFIMEntryWithParametersCtr)
{
    auto key = new RegistryKey("50", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, ARCH_64BIT,
                               0, "root", "HKEY_LOCAL_MACHINE\\SOFTWARE", "-rw-rw-r--", 1578075431, 0, "fakeUser");
    auto keyEntry = key->toFimEntry();
    ASSERT_EQ(keyEntry->registry_entry.key->id, fimEntryTest->registry_entry.key->id);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->checksum, fimEntryTest->registry_entry.key->checksum), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->gid, fimEntryTest->registry_entry.key->gid), 0);
    ASSERT_EQ(fimEntryTest->registry_entry.key->arch, fimEntryTest->registry_entry.key->arch);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->path, fimEntryTest->registry_entry.key->path), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->group_name, fimEntryTest->registry_entry.key->group_name), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->last_event, fimEntryTest->registry_entry.key->last_event);
    ASSERT_EQ(keyEntry->registry_entry.key->mtime, fimEntryTest->registry_entry.key->mtime);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->perm, fimEntryTest->registry_entry.key->perm), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->scanned, fimEntryTest->registry_entry.key->scanned);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->uid, fimEntryTest->registry_entry.key->uid), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->user_name, fimEntryTest->registry_entry.key->user_name), 0);

    delete key;
}

TEST_F(RegistryKeyTest, getFIMEntryWithFimCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    auto keyEntry = key->toFimEntry();
    ASSERT_EQ(keyEntry->registry_entry.key->id, fimEntryTest->registry_entry.key->id);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->checksum, fimEntryTest->registry_entry.key->checksum), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->gid, fimEntryTest->registry_entry.key->gid), 0);
    ASSERT_EQ(fimEntryTest->registry_entry.key->arch, fimEntryTest->registry_entry.key->arch);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->path, fimEntryTest->registry_entry.key->path), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->group_name, fimEntryTest->registry_entry.key->group_name), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->last_event, fimEntryTest->registry_entry.key->last_event);
    ASSERT_EQ(keyEntry->registry_entry.key->mtime, fimEntryTest->registry_entry.key->mtime);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->perm, fimEntryTest->registry_entry.key->perm), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->scanned, fimEntryTest->registry_entry.key->scanned);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->uid, fimEntryTest->registry_entry.key->uid), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->user_name, fimEntryTest->registry_entry.key->user_name), 0);

    delete key;
}

TEST_F(RegistryKeyTest, getFIMEntryWithJSONCtr)
{
    const auto json = R"(
        {
            "id":"50", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root", "arch":1,
            "last_event":1596489275, "mode":0, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--", "scanned":1,
            "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    auto key = new RegistryKey(json);
    auto keyEntry = key->toFimEntry();
    ASSERT_EQ(keyEntry->registry_entry.key->id, fimEntryTest->registry_entry.key->id);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->checksum, fimEntryTest->registry_entry.key->checksum), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->gid, fimEntryTest->registry_entry.key->gid), 0);
    ASSERT_EQ(fimEntryTest->registry_entry.key->arch, fimEntryTest->registry_entry.key->arch);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->path, fimEntryTest->registry_entry.key->path), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->group_name, fimEntryTest->registry_entry.key->group_name), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->last_event, fimEntryTest->registry_entry.key->last_event);
    ASSERT_EQ(keyEntry->registry_entry.key->mtime, fimEntryTest->registry_entry.key->mtime);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->perm, fimEntryTest->registry_entry.key->perm), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->scanned, fimEntryTest->registry_entry.key->scanned);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->uid, fimEntryTest->registry_entry.key->uid), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->user_name, fimEntryTest->registry_entry.key->user_name), 0);

    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithParametersCtr)
{
    auto key = new RegistryKey("50", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, ARCH_64BIT,
                               0, "root", "HKEY_LOCAL_MACHINE\\SOFTWARE", "-rw-rw-r--", 1578075431, 0, "fakeUser");
    const auto expectedValue = R"(
        {
            "arch":1, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root",
            "id":"50", "last_event":1596489275, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
            "scanned":1, "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    ASSERT_TRUE(*key->toJSON() == expectedValue);
    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithFimCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    const auto expectedValue = R"(
        {
            "arch":1, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root",
            "id":"50", "last_event":1596489275, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
            "scanned":1, "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    ASSERT_TRUE(*key->toJSON() == expectedValue);
    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithJSONCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    const auto expectedValue = R"(
        {
            "arch":1, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":0, "group_name":"root",
            "id":"50", "last_event":1596489275, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
            "scanned":1, "uid":0, "user_name":"fakeUser"
        }
    )"_json;
    ASSERT_TRUE(*key->toJSON() == expectedValue);
    delete key;
}
