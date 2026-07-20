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

#include "db.h"
#include "db.hpp"
#include "dbTest.h"

const auto insertRegistryKeyStatement1 = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_":"root", "architecture":1,
        "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\regtest1", "permissions":"-rw-rw-r--",
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0
    }
)"_json;

const auto insertRegistryValueStatement1 = R"({
        "value":"testRegistry1", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "architecture":0, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\regtest1", "version":1, "sync":0
    }
)"_json;

const auto insertRegistryKeyStatement2 = R"({
        "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_":"root", "architecture":1,
        "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\regtest2", "permissions":"-rw-rw-r--",
        "uid":"0", "owner":"fakeUser", "version":1, "sync":0
    }
)"_json;

const auto insertRegistryValueStatement2 = R"({
        "value":"testRegistry2", "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
        "size":4925, "type":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
        "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
        "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
        "architecture":0, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\regtest2", "version":1, "sync":0
    }
)"_json;

void transaction_callback(__attribute__((unused)) ReturnTypeCallback resultType,
                          __attribute__((unused)) const cJSON* result_json,
                          __attribute__((unused)) void* user_data)
{
}

TEST_F(DBTestFixture, TestFimDBGetCountRegistryEntry)
{
    EXPECT_NO_THROW({
        auto result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 0);

        // FIRST "SCAN"
        // Transaction start
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        // First update
        const auto registryKeyFIMTest1 {std::make_unique<RegistryKey>(insertRegistryKeyStatement1)};
        result = fim_db_transaction_sync_row(handler, registryKeyFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 1);

        // Second update
        const auto registryKeyFIMTest2 {std::make_unique<RegistryKey>(insertRegistryKeyStatement2)};
        result = fim_db_transaction_sync_row(handler, registryKeyFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 2);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 2);

        // SECOND "SCAN"
        // Transaction start
        handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 2);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_key();
        ASSERT_EQ(result, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetCountRegistryValueEntry)
{
    EXPECT_NO_THROW({
        auto result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 0);

        // FIRST "SCAN"
        // Transaction start
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        // First update
        const auto registryValueFIMTest1 {std::make_unique<RegistryValue>(insertRegistryValueStatement1)};
        result = fim_db_transaction_sync_row(handler, registryValueFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 1);

        // Second update
        const auto registryValueFIMTest2 {std::make_unique<RegistryValue>(insertRegistryValueStatement2)};
        result = fim_db_transaction_sync_row(handler, registryValueFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 2);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 2);

        // SECOND "SCAN"
        // Transaction start
        handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 2);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        result = fim_db_get_count_registry_data();
        ASSERT_EQ(result, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionRegistryEmptyDB)
{
    EXPECT_NO_THROW({
        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 0);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionRegistryWithKeyEntries)
{
    EXPECT_NO_THROW({
        auto result = fim_db_get_max_version_registry();
        ASSERT_EQ(result, 0);

        // Transaction start
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        // Insert registry keys
        const auto registryKeyFIMTest1 {std::make_unique<RegistryKey>(insertRegistryKeyStatement1)};
        result = fim_db_transaction_sync_row(handler, registryKeyFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        const auto registryKeyFIMTest2 {std::make_unique<RegistryKey>(insertRegistryKeyStatement2)};
        result = fim_db_transaction_sync_row(handler, registryKeyFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_registry(5);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 5);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionRegistryWithValueEntries)
{
    EXPECT_NO_THROW({
        auto result = fim_db_get_max_version_registry();
        ASSERT_EQ(result, 0);

        // Transaction start
        auto handler = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handler);

        // Insert registry values
        const auto registryValueFIMTest1 {std::make_unique<RegistryValue>(insertRegistryValueStatement1)};
        result = fim_db_transaction_sync_row(handler, registryValueFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        const auto registryValueFIMTest2 {std::make_unique<RegistryValue>(insertRegistryValueStatement2)};
        result = fim_db_transaction_sync_row(handler, registryValueFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handler, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_registry(7);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 7);
    });
}

TEST_F(DBTestFixture, TestFimDBGetMaxVersionRegistryWithBothTables)
{
    EXPECT_NO_THROW({
        auto result = fim_db_get_max_version_registry();
        ASSERT_EQ(result, 0);

        // Transaction start for registry keys
        auto handlerKey = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handlerKey);

        // Insert registry key
        const auto registryKeyFIMTest1 {std::make_unique<RegistryKey>(insertRegistryKeyStatement1)};
        result = fim_db_transaction_sync_row(handlerKey, registryKeyFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handlerKey, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        // Transaction start for registry values
        auto handlerValue = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handlerValue);

        // Insert registry value
        const auto registryValueFIMTest1 {std::make_unique<RegistryValue>(insertRegistryValueStatement1)};
        result = fim_db_transaction_sync_row(handlerValue, registryValueFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handlerValue, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_registry(10);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 10);
    });
}

TEST_F(DBTestFixture, TestFimDBSetVersionRegistry)
{
    EXPECT_NO_THROW({
        // Transaction start for registry keys
        auto handlerKey = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handlerKey);

        // Insert registry key
        const auto registryKeyFIMTest1 {std::make_unique<RegistryKey>(insertRegistryKeyStatement1)};
        auto result = fim_db_transaction_sync_row(handlerKey, registryKeyFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handlerKey, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_registry(15);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 15);
    });
}

TEST_F(DBTestFixture, TestFimDBSetVersionRegistryMultipleTimes)
{
    EXPECT_NO_THROW({
        // Transaction start for registry keys
        auto handlerKey = fim_db_transaction_start(FIMDB_REGISTRY_KEY_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handlerKey);

        // Insert registry keys
        const auto registryKeyFIMTest1 {std::make_unique<RegistryKey>(insertRegistryKeyStatement1)};
        auto result = fim_db_transaction_sync_row(handlerKey, registryKeyFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        const auto registryKeyFIMTest2 {std::make_unique<RegistryKey>(insertRegistryKeyStatement2)};
        result = fim_db_transaction_sync_row(handlerKey, registryKeyFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handlerKey, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        // Transaction start for registry values
        auto handlerValue = fim_db_transaction_start(FIMDB_REGISTRY_VALUE_TXN_TABLE, transaction_callback, &txn_ctx);
        ASSERT_TRUE(handlerValue);

        // Insert registry values
        const auto registryValueFIMTest1 {std::make_unique<RegistryValue>(insertRegistryValueStatement1)};
        result = fim_db_transaction_sync_row(handlerValue, registryValueFIMTest1->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        const auto registryValueFIMTest2 {std::make_unique<RegistryValue>(insertRegistryValueStatement2)};
        result = fim_db_transaction_sync_row(handlerValue, registryValueFIMTest2->toFimEntry());
        ASSERT_EQ(result, FIMDB_OK);

        // End of transaction
        result = fim_db_transaction_deleted_rows(handlerValue, transaction_callback, &txn_ctx);
        ASSERT_EQ(result, FIMDB_OK);

        auto maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 1);

        auto setResult = fim_db_set_version_registry(5);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 5);

        setResult = fim_db_set_version_registry(20);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 20);

        setResult = fim_db_set_version_registry(35);
        ASSERT_EQ(setResult, 0);

        maxVersion = fim_db_get_max_version_registry();
        ASSERT_EQ(maxVersion, 35);
    });
}
