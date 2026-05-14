/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryValue.hpp"
#include "dbRegistryValueTest.h"
#include "syscheck.h"

void RegistryValueTest::SetUp()
{
    fimEntryTest = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_registry_value_data* value = reinterpret_cast<fim_registry_value_data*>(std::calloc(1, sizeof(fim_registry_value_data)));

    fimEntryTest->type = FIM_TYPE_REGISTRY;
    std::snprintf(value->checksum, sizeof(value->checksum), "a2fbef8f81af27155dcee5e3927ff6243593b91a");
    std::snprintf(value->hash_md5, sizeof(value->hash_md5), "4b531524aa13c8a54614100b570b3dc7");
    std::snprintf(value->hash_sha1, sizeof(value->hash_sha1), "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b");
    std::snprintf(value->hash_sha256, sizeof(value->hash_sha256), "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a");
    value->last_event = 1596489275;
    value->mode = FIM_SCHEDULED;
    value->name = const_cast<char*>("testRegistry");
    value->scanned = 1;
    value->size = 4925;
    value->type = 0;
    value->path = const_cast<char*>("pathTestRegistry");
    value->hash_full_path = const_cast<char*>("00a7ee53218b25b5364c8773f37a38c93eae3880");
    value->arch = 0;
    fimEntryTest->registry_entry.value = value;
}

void RegistryValueTest::TearDown()
{
    free(fimEntryTest->registry_entry.value);
    free(fimEntryTest);
}

TEST_F(RegistryValueTest, registryValueConstructorFromFIM)
{
    EXPECT_NO_THROW(
    {
        auto value = new RegistryValue(fimEntryTest);
        auto scanned = value->state();
        EXPECT_TRUE(scanned);
        delete value;
    });
}

TEST_F(RegistryValueTest, registryValueConstructorFromJSON)
{

    EXPECT_NO_THROW(
    {
        auto value = new RegistryValue(inputJson);
        auto scanned = value->state();
        EXPECT_TRUE(scanned);
        delete value;
    });
}

TEST_F(RegistryValueTest, getFIMEntryWithFimCtr)
{
    auto value = new RegistryValue(fimEntryTest);
    auto registryEntry = value->toFimEntry();
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->checksum, fimEntryTest->registry_entry.value->checksum), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_md5, fimEntryTest->registry_entry.value->hash_md5), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha1, fimEntryTest->registry_entry.value->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha256, fimEntryTest->registry_entry.value->hash_sha256), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->last_event, fimEntryTest->registry_entry.value->last_event);
    ASSERT_EQ(registryEntry->registry_entry.value->mode, fimEntryTest->registry_entry.value->mode);
    ASSERT_EQ(registryEntry->registry_entry.value->scanned, fimEntryTest->registry_entry.value->scanned);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->name, fimEntryTest->registry_entry.value->name), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_full_path, fimEntryTest->registry_entry.value->hash_full_path), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->size, fimEntryTest->registry_entry.value->size);
    ASSERT_EQ(registryEntry->registry_entry.value->type, fimEntryTest->registry_entry.value->type);

    delete value;
}

TEST_F(RegistryValueTest, getFIMEntryWithJSONCtr)
{

    auto value = new RegistryValue(inputJson);
    auto registryEntry = value->toFimEntry();
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->checksum, fimEntryTest->registry_entry.value->checksum), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_md5, fimEntryTest->registry_entry.value->hash_md5), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha1, fimEntryTest->registry_entry.value->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha256, fimEntryTest->registry_entry.value->hash_sha256), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->last_event, fimEntryTest->registry_entry.value->last_event);
    ASSERT_EQ(registryEntry->registry_entry.value->mode, fimEntryTest->registry_entry.value->mode);
    ASSERT_EQ(registryEntry->registry_entry.value->scanned, fimEntryTest->registry_entry.value->scanned);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->name, fimEntryTest->registry_entry.value->name), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_full_path, fimEntryTest->registry_entry.value->hash_full_path), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->size, fimEntryTest->registry_entry.value->size);
    ASSERT_EQ(registryEntry->registry_entry.value->type, fimEntryTest->registry_entry.value->type);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithFimCtr)
{
    auto value = new RegistryValue(fimEntryTest);
    ASSERT_TRUE(*value->toJSON() == expectedValue);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithJSONCtr)
{

    auto value = new RegistryValue(inputJson);
    ASSERT_TRUE(*value->toJSON() == expectedValue);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithJSONCtrOldData)
{
    auto oldData = R"(
            {
            "data":[{"arch":"[x32]","checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a","hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880","hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a","last_event":1596489275,
            "name":"testRegistry","path":"pathTestRegistry","scanned":1,"size":4925,"type":0}],"table":"registry_data",
            "options":{"return_old_data": true, "ignore":["last_event"]}
            }
        )"_json;
    auto value = new RegistryValue(fimEntryTest, true);
    ASSERT_TRUE(*value->toJSON() == oldData);

    delete value;
}
