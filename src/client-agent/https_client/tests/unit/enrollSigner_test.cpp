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

#include "jwt/jwtEnrollTokenVerifier.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/testVectors.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <set>
#include <string>

namespace
{
    namespace tv = jwt_profile::v1::test_vectors::enroll;
    using jwt_profile::v1::TimePolicy;
    using jwt_profile::v1::VerifyError;
    using jwt_profile::v1::enroll::JwtEnrollTokenVerifier;

    const std::string BEARER_PREFIX = "Authorization: Bearer ";

    std::chrono::system_clock::time_point at(std::time_t ts)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {ts}};
    }

    std::string tokenOf(const EnrollSignedHeaders& headers)
    {
        EXPECT_EQ(0u, headers.authorization.rfind(BEARER_PREFIX, 0));
        return headers.authorization.substr(BEARER_PREFIX.size());
    }
} // namespace

TEST(EnrollSignerTest, DeriveKeyMatchesTheFrozenKnownAnswerVector)
{
    // The same HKDF the manager's PasswordKeySource runs (jwt/enrollKeyDerivation.hpp), pinned to
    // the vector every implementation shares (jwt_vectors.json "enroll.hkdf", stdlib oracle).
    const auto key = EnrollSigner::deriveKey(std::string {tv::kPassword});
    ASSERT_TRUE(key.has_value());
    const auto expected = jwt_profile::v1::JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(expected.has_value());
    EXPECT_TRUE(*key == *expected);
}

TEST(EnrollSignerTest, SignMintsABearerTheSharedVerifierAcceptsWithTheVectorKey)
{
    const auto headers = EnrollSigner::sign(std::string {tv::kPassword}, tv::kIat);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);

    const std::string token = tokenOf(*headers);
    // Header segment identical to the frozen vector's (no kid, exact {alg, typ}); the payload
    // only differs by the fresh jti.
    const std::string vector {tv::kToken};
    EXPECT_EQ(vector.substr(0, vector.find('.')), token.substr(0, token.find('.')));

    const auto key = jwt_profile::v1::JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(VerifyError::None, JwtEnrollTokenVerifier::verify(token, *key, TimePolicy {}, at(tv::kIat + 10)));
    EXPECT_EQ(VerifyError::StaleToken, JwtEnrollTokenVerifier::verify(token, *key, TimePolicy {}, at(tv::kIat + 91)));
}

TEST(EnrollSignerTest, WrongPasswordDoesNotVerify)
{
    const auto headers = EnrollSigner::sign("WrongPassword", tv::kIat);
    ASSERT_TRUE(headers.has_value());
    const auto key = jwt_profile::v1::JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(VerifyError::InvalidSignature,
              JwtEnrollTokenVerifier::verify(tokenOf(*headers), *key, TimePolicy {}, at(tv::kIat + 10)));
}

TEST(EnrollSignerTest, EveryAttemptGetsAFreshToken)
{
    std::set<std::string> tokens;

    for (int i = 0; i < 20; ++i)
    {
        const auto headers = EnrollSigner::sign(std::string {tv::kPassword}, tv::kIat);
        ASSERT_TRUE(headers.has_value());
        tokens.insert(tokenOf(*headers));
    }

    EXPECT_EQ(20u, tokens.size());
}

TEST(EnrollSignerTest, TimestampDrivesIatAndExp)
{
    const auto first = EnrollSigner::sign(std::string {tv::kPassword}, 1700000000);
    ASSERT_TRUE(first.has_value());
    const auto key = jwt_profile::v1::JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key.has_value());
    // Valid inside the accepted window around its own timestamp, stale far outside it.
    EXPECT_EQ(VerifyError::None, JwtEnrollTokenVerifier::verify(tokenOf(*first), *key, TimePolicy {}, at(1700000030)));
    EXPECT_EQ(VerifyError::StaleToken,
              JwtEnrollTokenVerifier::verify(tokenOf(*first), *key, TimePolicy {}, at(1700000200)));
}

TEST(EnrollSignerTest, EmptyPasswordYieldsNothing)
{
    EXPECT_FALSE(EnrollSigner::deriveKey("").has_value());
    EXPECT_FALSE(EnrollSigner::sign("", 1700000000).has_value());
}
