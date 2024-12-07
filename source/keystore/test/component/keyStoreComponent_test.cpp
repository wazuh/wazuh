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

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

#include <base/logging.hpp>

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

constexpr auto TEST_KEYSTORE_PATH {"./keys.keystore"};

TEST_F(KeyStoreComponentTest, TestPutGet)
{
    std::filesystem::remove_all(TEST_KEYSTORE_PATH);

    // Put a value in the keystore
    Keystore::put("key1", "value1", TEST_KEYSTORE_PATH);
    Keystore::put("key2", "value2", TEST_KEYSTORE_PATH);

    // Get the value from the keystore and check that it is the same as the one put
    std::string out;
    Keystore::get("key1", out, TEST_KEYSTORE_PATH);
    ASSERT_EQ(out, "value1");
    Keystore::get("key2", out, TEST_KEYSTORE_PATH);
    ASSERT_EQ(out, "value2");
}

TEST_F(KeyStoreComponentTest, CreationAndPermissions)
{
    std::filesystem::remove_all(TEST_KEYSTORE_PATH);
    std::string out;
    Keystore::get("key1", out, TEST_KEYSTORE_PATH);

    auto status = std::filesystem::status(TEST_KEYSTORE_PATH);
    auto perms = status.permissions();

    ASSERT_TRUE(std::filesystem::exists(TEST_KEYSTORE_PATH));
    ASSERT_TRUE(std::filesystem::is_regular_file(TEST_KEYSTORE_PATH));
    ASSERT_TRUE((perms & std::filesystem::perms::owner_read) != std::filesystem::perms::none);
    ASSERT_TRUE((perms & std::filesystem::perms::owner_write) != std::filesystem::perms::none);
    ASSERT_TRUE((perms & std::filesystem::perms::group_read) != std::filesystem::perms::none);

    ASSERT_FALSE((perms & std::filesystem::perms::owner_exec) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::group_write) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::group_exec) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_read) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_write) != std::filesystem::perms::none);
    ASSERT_FALSE((perms & std::filesystem::perms::others_exec) != std::filesystem::perms::none);
}
