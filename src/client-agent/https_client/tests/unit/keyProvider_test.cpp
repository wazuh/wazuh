/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keyProvider.hpp"

#include <gtest/gtest.h>

TEST(ConfigKeyProviderTest, DecodesASixtyFourHexSecretIntoThirtyTwoBytes)
{
    const ConfigKeyProvider provider {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
    const auto key = provider.signingKey();
    ASSERT_TRUE(key.has_value());
    ASSERT_EQ(32u, key->size());
    EXPECT_EQ(0x00, (*key)[0]);
    EXPECT_EQ(0x1f, (*key)[31]);
}

TEST(ConfigKeyProviderTest, RejectsEveryOtherShape)
{
    // The bearer profile's key is exactly the 32 bytes of a 64-hex secret, lowercase (the manager's
    // keystore agrees).
    EXPECT_FALSE(ConfigKeyProvider {""}.signingKey().has_value());
    EXPECT_FALSE(ConfigKeyProvider {std::string(32, 'a')}.signingKey().has_value()); // 16 bytes.
    EXPECT_FALSE(ConfigKeyProvider {std::string(48, 'b')}.signingKey().has_value()); // 24 bytes.
    EXPECT_FALSE(ConfigKeyProvider {std::string(63, 'c')}.signingKey().has_value()); // Odd length.
    EXPECT_FALSE(ConfigKeyProvider {std::string(66, 'c')}.signingKey().has_value()); // 33 bytes.
    EXPECT_FALSE(ConfigKeyProvider {std::string(64, 'A')}.signingKey().has_value()); // Uppercase.
    EXPECT_FALSE(ConfigKeyProvider {"g" + std::string(63, 'a')}.signingKey().has_value());
}

TEST(ConfigKeyProviderTest, SetKeySwapsOnlyValidMaterial)
{
    ConfigKeyProvider provider {std::string(64, 'a')};
    ASSERT_TRUE(provider.signingKey().has_value());

    EXPECT_FALSE(provider.setKey("zz"));
    EXPECT_FALSE(provider.setKey(std::string(32, 'b')));
    EXPECT_EQ(0xaa, (*provider.signingKey())[0]); // The previous key stayed in place.

    EXPECT_TRUE(provider.setKey(std::string(64, 'b')));
    EXPECT_EQ(0xbb, (*provider.signingKey())[0]);
}
