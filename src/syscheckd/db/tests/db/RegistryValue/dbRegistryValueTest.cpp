/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
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
    std::strncpy(value->checksum, "a2fbef8f81af27155dcee5e3927ff6243593b91a", sizeof(value->checksum));
    std::strncpy(value->hash_md5, "4b531524aa13c8a54614100b570b3dc7", sizeof(value->hash_md5));
    std::strncpy(value->hash_sha1, "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b", sizeof(value->hash_sha1));
    std::strncpy(value->hash_sha256, "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", sizeof(value->hash_sha256));
    value->id = 20;
    value->last_event = 1596489275;
    value->mode = FIM_SCHEDULED;
    value->name = const_cast<char*>("testRegistry");
    value->scanned = 1;
    value->size = 4925;
    value->type = 0;
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

TEST_F(RegistryValueTest, registryValueConstructorFromParameters)
{
    EXPECT_NO_THROW(
    {
        auto value = new RegistryValue("testRegistry", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, FIM_SCHEDULED,
                                       0, 20, "4b531524aa13c8a54614100b570b3dc7", "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
                                       "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", 4925, 0);
        auto scanned = value->state();
        EXPECT_TRUE(scanned);
        delete value;
    });
}

TEST_F(RegistryValueTest, registryValueConstructorFromJSON)
{
    const auto json = R"(
        {
            "id":20, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "type":0, "size":4925, "name":"testRegistry",
            "last_event":1596489275, "mode":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "scanned":1
        }
    )"_json;
    EXPECT_NO_THROW(
    {
        auto value = new RegistryValue(json);
        auto scanned = value->state();
        EXPECT_TRUE(scanned);
        delete value;
    });
}

TEST_F(RegistryValueTest, getFIMEntryWithParametersCtr)
{
    auto value = new RegistryValue("testRegistry", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, FIM_SCHEDULED,
                                   0, 20, "4b531524aa13c8a54614100b570b3dc7", "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
                                   "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", 4925, 0);
    auto registryEntry = value->toFimEntry();
    ASSERT_EQ(registryEntry->registry_entry.value->id, fimEntryTest->registry_entry.value->id);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->checksum, fimEntryTest->registry_entry.value->checksum), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_md5, fimEntryTest->registry_entry.value->hash_md5), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha1, fimEntryTest->registry_entry.value->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha256, fimEntryTest->registry_entry.value->hash_sha256), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->last_event, fimEntryTest->registry_entry.value->last_event);
    ASSERT_EQ(registryEntry->registry_entry.value->mode, fimEntryTest->registry_entry.value->mode);
    ASSERT_EQ(registryEntry->registry_entry.value->scanned, fimEntryTest->registry_entry.value->scanned);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->name, fimEntryTest->registry_entry.value->name), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->size, fimEntryTest->registry_entry.value->size);
    ASSERT_EQ(registryEntry->registry_entry.value->type, fimEntryTest->registry_entry.value->type);

    delete value;
}

TEST_F(RegistryValueTest, getFIMEntryWithFimCtr)
{
    auto value = new RegistryValue(fimEntryTest);
    auto registryEntry = value->toFimEntry();
    ASSERT_EQ(registryEntry->registry_entry.value->id, fimEntryTest->registry_entry.value->id);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->checksum, fimEntryTest->registry_entry.value->checksum), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_md5, fimEntryTest->registry_entry.value->hash_md5), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha1, fimEntryTest->registry_entry.value->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha256, fimEntryTest->registry_entry.value->hash_sha256), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->last_event, fimEntryTest->registry_entry.value->last_event);
    ASSERT_EQ(registryEntry->registry_entry.value->mode, fimEntryTest->registry_entry.value->mode);
    ASSERT_EQ(registryEntry->registry_entry.value->scanned, fimEntryTest->registry_entry.value->scanned);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->name, fimEntryTest->registry_entry.value->name), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->size, fimEntryTest->registry_entry.value->size);
    ASSERT_EQ(registryEntry->registry_entry.value->type, fimEntryTest->registry_entry.value->type);

    delete value;
}

TEST_F(RegistryValueTest, getFIMEntryWithJSONCtr)
{
    const auto json = R"(
        {
            "id":20, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "type":0, "size":4925, "name":"testRegistry",
            "last_event":1596489275, "mode":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "scanned":1
        }
    )"_json;
    auto value = new RegistryValue(json);
    auto registryEntry = value->toFimEntry();
    ASSERT_EQ(registryEntry->registry_entry.value->id, fimEntryTest->registry_entry.value->id);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->checksum, fimEntryTest->registry_entry.value->checksum), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_md5, fimEntryTest->registry_entry.value->hash_md5), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha1, fimEntryTest->registry_entry.value->hash_sha1), 0);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->hash_sha256, fimEntryTest->registry_entry.value->hash_sha256), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->last_event, fimEntryTest->registry_entry.value->last_event);
    ASSERT_EQ(registryEntry->registry_entry.value->mode, fimEntryTest->registry_entry.value->mode);
    ASSERT_EQ(registryEntry->registry_entry.value->scanned, fimEntryTest->registry_entry.value->scanned);
    ASSERT_EQ(std::strcmp(registryEntry->registry_entry.value->name, fimEntryTest->registry_entry.value->name), 0);
    ASSERT_EQ(registryEntry->registry_entry.value->size, fimEntryTest->registry_entry.value->size);
    ASSERT_EQ(registryEntry->registry_entry.value->type, fimEntryTest->registry_entry.value->type);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithParametersCtr)
{
    const auto expectedValue = R"(
        {
            "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",  "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b", "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
            "id":20, "last_event":1596489275, "mode":0, "name":"testRegistry", "scanned":1, "type":0, "size":4925
        }
    )"_json;
    auto value = new RegistryValue("testRegistry", "a2fbef8f81af27155dcee5e3927ff6243593b91a", 1596489275, 1, FIM_SCHEDULED,
                                   0, 20, "4b531524aa13c8a54614100b570b3dc7", "7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
                                   "e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", 4925, 0);
    ASSERT_TRUE(*value->toJSON() == expectedValue);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithFimCtr)
{
    auto value = new RegistryValue(fimEntryTest);
    const auto expectedValue = R"(
        {
            "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",  "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b", "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
            "id":20, "last_event":1596489275, "mode":0, "name":"testRegistry", "scanned":1, "type":0, "size":4925
        }
    )"_json;
    ASSERT_TRUE(*value->toJSON() == expectedValue);

    delete value;
}

TEST_F(RegistryValueTest, getJSONWithJSONCtr)
{
    const auto expectedValue = R"(
        {
            "id":20, "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "type":0, "size":4925, "name":"testRegistry",
            "last_event":1596489275, "mode":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "scanned":1
        }
    )"_json;
    auto value = new RegistryValue(expectedValue);
    ASSERT_TRUE(*value->toJSON() == expectedValue);

    delete value;
}
