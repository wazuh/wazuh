/*
 * Wazuh keystore
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "keyStoreComponent_test.hpp"
#include "include/keyStore.hpp"
#include "rocksDBWrapper.hpp"
#include <filesystem>

constexpr auto DATABASE_PATH {"queue/keystore"};
constexpr auto KS_VERSION {"2"};
constexpr auto KS_VERSION_FIELD {"version"};

std::string getKeystoreVersion()
{
    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);
    std::string value;
    keystoreDB.get(KS_VERSION_FIELD, value, "default");
    return value;
}

TEST(KeyStoreComponentTest, TestPutGet)
{
    std::filesystem::remove_all(DATABASE_PATH);

    // Check that the keystore version is empty when the database is empty
    ASSERT_EQ(getKeystoreVersion(), "");

    // Put a value in the keystore and check that the version is updated
    Keystore::put("default", "key1", "value1");
    ASSERT_EQ(getKeystoreVersion(), KS_VERSION);
    Keystore::put("default", "key2", "value2");

    // Get the value from the keystore and check that it is the same as the one put
    std::string out;
    Keystore::get("default", "key1", out);
    ASSERT_EQ(out, "value1");
    Keystore::get("default", "key2", out);
    ASSERT_EQ(out, "value2");
}

TEST(KeyStoreComponentTest, TestGetDoesNotCreateColumnFamily)
{
    std::filesystem::remove_all(DATABASE_PATH);

    std::string out;
    Keystore::get("missing", "key1", out);
    ASSERT_EQ(out, "");
    ASSERT_EQ(Keystore::get("missing", "key1"), "");

    auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);
    ASSERT_FALSE(keystoreDB.columnExists("missing"));
}
