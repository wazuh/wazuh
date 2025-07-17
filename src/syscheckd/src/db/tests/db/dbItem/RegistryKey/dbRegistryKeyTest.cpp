/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
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
    key->architecture = ARCH_64BIT;
    std::snprintf(key->checksum, sizeof(key->checksum), "a2fbef8f81af27155dcee5e3927ff6243593b91a");
    key->gid = const_cast<char*>("0");
    key->group = const_cast<char*>("root");
    key->mtime = 1578075431;
    key->path = const_cast<char*>("HKEY_LOCAL_MACHINE\\SOFTWARE");
    key->permissions = const_cast<char*>("-rw-rw-r--");
    key->uid = const_cast<char*>("0");
    key->owner = const_cast<char*>("fakeUser");
    fimEntryTest->registry_entry.key = key;
}

void RegistryKeyTest::TearDown()
{
    free(fimEntryTest->registry_entry.key);
    free(fimEntryTest);
}

TEST_F(RegistryKeyTest, registryKeyConstructorFromFIM)
{
    EXPECT_NO_THROW({
        auto key = new RegistryKey(fimEntryTest);
        delete key;
    });
}

TEST_F(RegistryKeyTest, registryKeyConstructorFromJSON)
{

    EXPECT_NO_THROW({
        auto keyTest = new RegistryKey(inputJson);
        delete keyTest;
    });
}

TEST_F(RegistryKeyTest, getFIMEntryWithFimCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    auto keyEntry = key->toFimEntry();
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->checksum, fimEntryTest->registry_entry.key->checksum), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->gid, fimEntryTest->registry_entry.key->gid), 0);
    ASSERT_EQ(fimEntryTest->registry_entry.key->architecture, fimEntryTest->registry_entry.key->architecture);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->path, fimEntryTest->registry_entry.key->path), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->group, fimEntryTest->registry_entry.key->group), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->mtime, fimEntryTest->registry_entry.key->mtime);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->permissions, fimEntryTest->registry_entry.key->permissions), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->uid, fimEntryTest->registry_entry.key->uid), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->owner, fimEntryTest->registry_entry.key->owner), 0);

    delete key;
}

TEST_F(RegistryKeyTest, getFIMEntryWithJSONCtr)
{

    auto key = new RegistryKey(inputJson);
    auto keyEntry = key->toFimEntry();
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->checksum, fimEntryTest->registry_entry.key->checksum), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->gid, fimEntryTest->registry_entry.key->gid), 0);
    ASSERT_EQ(fimEntryTest->registry_entry.key->architecture, fimEntryTest->registry_entry.key->architecture);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->path, fimEntryTest->registry_entry.key->path), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->group, fimEntryTest->registry_entry.key->group), 0);
    ASSERT_EQ(keyEntry->registry_entry.key->mtime, fimEntryTest->registry_entry.key->mtime);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->permissions, fimEntryTest->registry_entry.key->permissions), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->uid, fimEntryTest->registry_entry.key->uid), 0);
    ASSERT_EQ(std::strcmp(keyEntry->registry_entry.key->owner, fimEntryTest->registry_entry.key->owner), 0);

    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithFimCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    ASSERT_TRUE(*key->toJSON() == expectedValue);
    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithJSONCtr)
{
    auto key = new RegistryKey(fimEntryTest);
    ASSERT_TRUE(*key->toJSON() == expectedValue);
    delete key;
}

TEST_F(RegistryKeyTest, getJSONWithJSONCtrReportOldData)
{
    const nlohmann::json oldDataJson = R"(
            {
                "data":[{"architecture":"[x64]","checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a","gid":"0","group_":"root",
                "mtime":1578075431,"path":"HKEY_LOCAL_MACHINE\\SOFTWARE","permissions":"-rw-rw-r--","uid":"0", "owner":"fakeUser"}],
                "table":"registry_key","options":{"return_old_data": true}
            }
        )"_json;
    auto key = new RegistryKey(fimEntryTest, true);
    ASSERT_TRUE(*key->toJSON() == oldDataJson);
    delete key;
}
