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
