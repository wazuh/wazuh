/*
 * Wazuh remoted module - wazuh-enroll+jwt key derivation tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/testVectors.hpp"

using namespace jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors::enroll;

TEST(EnrollKeyDerivation, MatchesTheFrozenKnownAnswerVector)
{
    // HKDF-SHA256(password, salt = 32 x 0x00, info = "WAZUH-ENROLL-JWT-KEY" || 0x01, L = 32),
    // computed independently with Python's stdlib (jwt_vectors.json "enroll.hkdf").
    const auto key = enroll::deriveEnrollKey(tv::kPassword);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->size(), kKeyBytes);
    const auto expected = JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(expected.has_value());
    EXPECT_TRUE(*key == *expected);
}

TEST(EnrollKeyDerivation, DeterministicAndPasswordSensitive)
{
    const auto a = enroll::deriveEnrollKey("correct horse battery staple");
    const auto b = enroll::deriveEnrollKey("correct horse battery staple");
    const auto c = enroll::deriveEnrollKey("correct horse battery stapl");
    ASSERT_TRUE(a && b && c);
    EXPECT_TRUE(*a == *b);
    EXPECT_TRUE(*a != *c);
}

TEST(EnrollKeyDerivation, EmptyPasswordYieldsNoKey)
{
    EXPECT_FALSE(enroll::deriveEnrollKey("").has_value());
}

// ---------------------------------------------------------------- `kid` forms (issue #38993)

namespace
{
    namespace tt = jwt_profile::v1::test_vectors::enroll_token;

    SecureBytes fromHex(std::string_view hex)
    {
        SecureBytes out(hex.size() / 2);
        for (std::size_t i = 0; i < out.size(); ++i)
        {
            out.data()[i] = static_cast<std::uint8_t>(std::stoul(std::string {hex.substr(2 * i, 2)}, nullptr, 16));
        }
        return out;
    }
} // namespace

TEST(EnrollKeyDerivation, TokenAndReenrollKeysMatchTheirVectors)
{
    // Same HKDF construction, different `info` labels: computed independently with Python's stdlib
    // (jwt_vectors.json "enroll_token.hkdf_token" / "enroll_token.hkdf_reenroll").
    const auto tokenKey = enroll::deriveEnrollTokenKey(fromHex(tt::kSecretHex));
    ASSERT_TRUE(tokenKey.has_value());
    EXPECT_TRUE(*tokenKey == *JwtKeyDecoder::decode(tt::kTokenKeyHex));

    const auto reenrollKey = enroll::deriveReenrollKey(fromHex(tt::kReenrollSecretHex));
    ASSERT_TRUE(reenrollKey.has_value());
    EXPECT_TRUE(*reenrollKey == *JwtKeyDecoder::decode(tt::kReenrollKeyHex));

    // The three labels separate the domains: the same 32 bytes never yield the same key twice.
    const auto asReenroll = enroll::deriveReenrollKey(*JwtKeyDecoder::decode(tt::kReenrollSecretHex));
    ASSERT_TRUE(asReenroll.has_value());
    EXPECT_TRUE(*asReenroll == *reenrollKey);
    EXPECT_TRUE(*tokenKey != *reenrollKey);
    // And the shared-key vector is untouched by the refactor.
    EXPECT_TRUE(*enroll::deriveEnrollKey(tv::kPassword) == *JwtKeyDecoder::decode(tv::kKeyHex));
}

TEST(EnrollKeyDerivation, WrongSizedSecretsYieldNoKey)
{
    EXPECT_FALSE(enroll::deriveEnrollTokenKey(SecureBytes(15)).has_value());
    EXPECT_FALSE(enroll::deriveEnrollTokenKey(SecureBytes(17)).has_value());
    EXPECT_FALSE(enroll::deriveEnrollTokenKey(SecureBytes(32)).has_value()); // a reenroll secret is not a token secret
    EXPECT_FALSE(enroll::deriveEnrollTokenKey(SecureBytes {}).has_value());
    EXPECT_FALSE(enroll::deriveReenrollKey(SecureBytes(31)).has_value());
    EXPECT_FALSE(enroll::deriveReenrollKey(SecureBytes(33)).has_value());
    EXPECT_FALSE(enroll::deriveReenrollKey(SecureBytes(16)).has_value());
    EXPECT_FALSE(enroll::deriveReenrollKey(SecureBytes {}).has_value());
    EXPECT_TRUE(enroll::deriveEnrollTokenKey(SecureBytes(16)).has_value()); // all-zero secret is still a secret
}
