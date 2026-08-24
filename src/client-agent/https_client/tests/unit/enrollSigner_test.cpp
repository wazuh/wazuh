/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollSigner.hpp"

#include <gtest/gtest.h>

namespace
{
    std::string toHex(const std::vector<uint8_t>& bytes)
    {
        static const char* digits = "0123456789abcdef";
        std::string hex;
        hex.reserve(2 * bytes.size());

        for (const auto byte : bytes)
        {
            hex.push_back(digits[byte >> 4]);
            hex.push_back(digits[byte & 0x0f]);
        }

        return hex;
    }

    // The #38438 "Wire examples / Known-answer vector" section, verified
    // independently against the raw issue text (not retyped from memory) with
    // Python's hmac/hashlib (HKDF) and the `cryptography` package (CMAC)
    // before this test was written.
    const std::string KAT_PASSWORD = "MyEnrollmentSecret123";
    const std::string KAT_DERIVED_KEY_HEX =
        "2ea29504f294bce5039bdb4fb78747dec59866204dc2588dc59f3b8cd5875a9e";
    const std::string KAT_METHOD = "POST";
    const std::string KAT_TARGET = "/enroll";
    const std::time_t KAT_TIMESTAMP = 1739999999;
    const std::string KAT_BODY =
        R"({"name":"web-server-01","version":"5.0.0","groups":"default,web-servers","ip":"10.0.0.15"})";
    const std::string KAT_MAC_HEX = "dc07d78fc156a1944f4fb02b91da7d01";
} // namespace

TEST(EnrollSignerTest, DeriveKeyMatchesTheContractKnownAnswerVector)
{
    const auto key = EnrollSigner::deriveKey(KAT_PASSWORD);
    ASSERT_TRUE(key.has_value());
    ASSERT_EQ(32u, key->size());
    EXPECT_EQ(KAT_DERIVED_KEY_HEX, toHex(*key));
}

TEST(EnrollSignerTest, SignMatchesTheContractKnownAnswerVectorEndToEnd)
{
    const auto headers = EnrollSigner::sign(
                             KAT_PASSWORD, KAT_METHOD, KAT_TARGET,
                             reinterpret_cast<const uint8_t*>(KAT_BODY.data()), KAT_BODY.size(), KAT_TIMESTAMP);

    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);
    EXPECT_EQ("Authorization: WazuhEnroll " + std::to_string(KAT_TIMESTAMP) + ":" + KAT_MAC_HEX,
              headers->authorization);
}

TEST(EnrollSignerTest, DeriveKeyIsDeterministic)
{
    const auto first = EnrollSigner::deriveKey(KAT_PASSWORD);
    const auto second = EnrollSigner::deriveKey(KAT_PASSWORD);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(*first, *second);
}

TEST(EnrollSignerTest, DifferentPasswordsDeriveDifferentKeys)
{
    const auto first = EnrollSigner::deriveKey("password-one");
    const auto second = EnrollSigner::deriveKey("password-two");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(*first, *second);
}

TEST(EnrollSignerTest, DifferentTimestampChangesTheMac)
{
    const uint8_t body[] = "abc";
    const auto first = EnrollSigner::sign(KAT_PASSWORD, "POST", "/enroll", body, 3, 1700000000);
    const auto second = EnrollSigner::sign(KAT_PASSWORD, "POST", "/enroll", body, 3, 1700000001);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->authorization, second->authorization);
}

TEST(EnrollSignerTest, DifferentBodyChangesTheMac)
{
    const uint8_t bodyA[] = "abc";
    const uint8_t bodyB[] = "xyz";
    const auto first = EnrollSigner::sign(KAT_PASSWORD, "POST", "/enroll", bodyA, 3, 1700000000);
    const auto second = EnrollSigner::sign(KAT_PASSWORD, "POST", "/enroll", bodyB, 3, 1700000000);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->authorization, second->authorization);
}

TEST(EnrollSignerTest, EmptyBodyStillSigns)
{
    const auto headers = EnrollSigner::sign(KAT_PASSWORD, "POST", "/enroll", nullptr, 0, 1700000000);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);
}
