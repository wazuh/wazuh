/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <base/utils/rocksDBWrapper.hpp>
#include <base/utils/rsaHelper.hpp>

#include "keyStore.hpp"

/**
 * @brief KeyStoreComponentTest class.
 *
 */
class KeyStoreComponentTest : public ::testing::Test
{
protected:
    KeyStoreComponentTest() = default;
    ~KeyStoreComponentTest() override = default;
    void SetUp() override;
};

void KeyStoreComponentTest::SetUp()
{
    logging::testInit();
}

constexpr auto TEST_KEYSTORE_PATH {"./keystore"};
constexpr auto KS_VERSION {"1"};
constexpr auto KS_VERSION_FIELD {"version"};

std::string getKeystoreVersion()
{
    auto keystoreDB = utils::rocksdb::RocksDBWrapper(TEST_KEYSTORE_PATH, false);
    std::string value;
    keystoreDB.get(KS_VERSION_FIELD, value, "default");
    return value;
}

TEST_F(KeyStoreComponentTest, TestPutGet)
{
    std::filesystem::remove_all(TEST_KEYSTORE_PATH);

    // Check that the keystore version is empty when the database is empty
    ASSERT_EQ(getKeystoreVersion(), "");

    // Put a value in the keystore and check that the version is updated
    Keystore::put("default", "key1", "value1", TEST_KEYSTORE_PATH);
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);
    Keystore::put("default", "key2", "value2", TEST_KEYSTORE_PATH);

    // Get the value from the keystore and check that it is the same as the one put
    std::string out;
    Keystore::get("default", "key1", out, TEST_KEYSTORE_PATH);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out, TEST_KEYSTORE_PATH);
    ASSERT_EQ(out, "value2");
}
