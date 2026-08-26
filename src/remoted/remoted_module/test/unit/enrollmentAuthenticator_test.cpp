/*
 * Wazuh remoted module - agent enrollment authenticator tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit tests of EnrollmentAuthenticator: the protocol-version and body-cap gates every mode
// enforces, the Open-mode pass-through, and the `wazuh-enroll+jwt` bearer check of Password mode
// (the token grammar itself is the shared verifier's job -- jwtEnrollSignVerify_test.cpp -- so
// here the negatives are the ones the authenticator's own wiring can get wrong: scheme, key
// availability, time policy, hot-reloaded password, cross-profile token).

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>

#include "enrollment/enrollmentAuthenticator.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/testVectors.hpp"

using namespace remoted::enrollment;
using jwt_profile::v1::SecureBytes;
using jwt_profile::v1::TimePolicy;
using jwt_profile::v1::enroll::JwtEnrollTokenSigner;
using remoted::auth::AuthError;
using remoted::auth::PasswordKeySource;
namespace tv = jwt_profile::v1::test_vectors::enroll;

namespace
{
    // 10 s after the frozen vector's iat, so the vector tokens are valid "now".
    constexpr std::int64_t kNow = tv::kIat + 10;
    constexpr std::string_view kVersion = remoted::auth::kSupportedProtocolVersion;
    constexpr std::size_t kSmallBody = 2;

    std::string writePasswordFile(const std::string& password, const char* tag = "")
    {
        const std::string path = "/tmp/enrollmentAuthenticator_test_" + std::to_string(getpid()) + tag + ".pass";
        std::ofstream file(path);
        file << password << "\n";
        return path;
    }

    std::chrono::system_clock::time_point at(std::int64_t ts)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {ts}};
    }

    std::string bearer(const SecureBytes& key, std::int64_t ts)
    {
        const auto token = JwtEnrollTokenSigner::sign(key, at(ts));
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }

    struct PasswordFixture : public ::testing::Test
    {
        std::string path = writePasswordFile(std::string {tv::kPassword});
        std::shared_ptr<PasswordKeySource> keySource = std::make_shared<PasswordKeySource>(path);
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

        void TearDown() override
        {
            std::remove(path.c_str());
        }

        std::string validBearer(std::int64_t ts = kNow)
        {
            const auto key = keySource->currentKey();
            EXPECT_TRUE(key.has_value());
            return bearer(*key, ts);
        }

        std::optional<AuthError> run(std::string_view authorization, std::int64_t now = kNow)
        {
            return authenticator.authenticate(kVersion, authorization, kSmallBody, now);
        }
    };
} // namespace

// -----------------------------------------------------------------------------
// Password mode: `Bearer <wazuh-enroll+jwt>` keyed by the HKDF of authd.pass.
// -----------------------------------------------------------------------------

TEST_F(PasswordFixture, ValidBearerIsAccepted)
{
    EXPECT_EQ(run(validBearer()), std::nullopt);
}

TEST_F(PasswordFixture, TheFrozenVectorTokenIsAcceptedWithTheVectorPassword)
{
    // Interop pin: the manager's HKDF + verifier accept the token every other implementation
    // (agent, Python tools) reproduces byte for byte from jwt_vectors.json.
    EXPECT_EQ(run("Bearer " + std::string {tv::kToken}), std::nullopt);
}

TEST_F(PasswordFixture, MissingAuthorizationHeaderIsRejected)
{
    const auto err = run("");
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingAuthorization);
}

TEST_F(PasswordFixture, NonBearerSchemesAreRejectedAsMalformed)
{
    for (const auto* header : {"Wazuh 001:1784238000:00112233445566778899aabbccddeeff",
                               "Basic dXNlcjpwYXNz",
                               "bearer abc.def.ghi",
                               "Bearer",
                               "Bearer "})
    {
        const auto err = run(header);
        ASSERT_TRUE(err.has_value()) << header;
        EXPECT_EQ(*err, AuthError::MalformedAuthorization) << header;
    }
}

TEST_F(PasswordFixture, GarbageTokenIsRejectedAsInvalidToken)
{
    const auto err = run("Bearer not.a.token");
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidToken);
}

TEST_F(PasswordFixture, WrongPasswordIsRejectedAsInvalidSignature)
{
    const auto err = run("Bearer " + std::string {tv::kWrongPasswordToken});
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidSignature);
}

TEST_F(PasswordFixture, AnAgentProfileTokenIsRejected)
{
    // A `wazuh-agent+jwt` minted with the SAME key bytes: rejected on the exact header set (`kid`,
    // `typ`), before its signature is even considered -- the two profiles never cross over.
    const auto key = keySource->currentKey();
    ASSERT_TRUE(key.has_value());
    const auto agentToken =
        jwt_profile::v1::JwtRequestTokenSigner::sign(*jwt_profile::v1::CanonicalAgentId::parse("001"), *key, at(kNow));
    ASSERT_TRUE(agentToken.has_value());
    const auto err = run("Bearer " + *agentToken);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidToken);
}

TEST_F(PasswordFixture, KidInTheHeaderIsRejected)
{
    const auto err = run("Bearer " + std::string {tv::kKidHeaderToken});
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidToken);
}

TEST_F(PasswordFixture, TokenOlderThanTheAcceptedAgeIsStale)
{
    // Default policy: 60 s age + 30 s skew.
    EXPECT_EQ(run(validBearer(kNow - 90)), std::nullopt);
    const auto err = run(validBearer(kNow - 91));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::StaleToken);
}

TEST_F(PasswordFixture, TokenIssuedBeyondTheSkewInTheFutureIsStale)
{
    EXPECT_EQ(run(validBearer(kNow + 30)), std::nullopt);
    const auto err = run(validBearer(kNow + 31));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::StaleToken);
}

TEST_F(PasswordFixture, ConfiguredTimePolicyNarrowsTheWindow)
{
    // remoted.jwt_max_age=10 / remoted.jwt_clock_skew=0 reach /enroll through the same TimePolicy
    // the agent<->manager profile uses.
    EnrollmentAuthConfig config {true};
    config.timePolicy = TimePolicy {10, 0};
    EnrollmentAuthenticator narrow {config, keySource};

    EXPECT_EQ(narrow.authenticate(kVersion, validBearer(kNow - 10), kSmallBody, kNow), std::nullopt);
    const auto tooOld = narrow.authenticate(kVersion, validBearer(kNow - 11), kSmallBody, kNow);
    ASSERT_TRUE(tooOld.has_value());
    EXPECT_EQ(*tooOld, AuthError::StaleToken);
    const auto future = narrow.authenticate(kVersion, validBearer(kNow + 1), kSmallBody, kNow);
    ASSERT_TRUE(future.has_value());
    EXPECT_EQ(*future, AuthError::StaleToken);
}

TEST_F(PasswordFixture, RotatingThePasswordInvalidatesTokensOfTheOldOne)
{
    const std::string oldBearer = validBearer();
    EXPECT_EQ(run(oldBearer), std::nullopt);

    {
        std::ofstream file(path);
        file << "SomeOtherSecret456\n";
    }
    ASSERT_TRUE(keySource->reload());

    const auto err = run(oldBearer);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidSignature);
    EXPECT_EQ(run(validBearer()), std::nullopt); // minted with the new key
}

TEST(EnrollmentAuthenticatorTest, PasswordModeMissingKeyFileFailsClosed)
{
    // Points at a file that was never written: PasswordKeySource::currentKey() stays nullopt.
    // Fail-closed is security-critical here -- must be rejected/401, never treated as Open mode.
    // EnrollmentKeyUnavailable, deliberately NOT MissingKey: MissingKey means an already-enrolled
    // agent's client.keys entry doesn't decode (logRejection() tells the operator to "re-enroll"
    // for that) -- nonsensical here, where no agent and no client.keys entry exist yet at all.
    auto keySource = std::make_shared<PasswordKeySource>("/tmp/enrollmentAuthenticator_test_absent.pass");
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    const auto err = authenticator.authenticate(kVersion, "Bearer " + std::string {tv::kToken}, kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::EnrollmentKeyUnavailable);
}

TEST(EnrollmentAuthenticatorTest, PasswordModeWithoutAKeySourceFailsClosed)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, nullptr};
    const auto err = authenticator.authenticate(kVersion, "Bearer " + std::string {tv::kToken}, kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::EnrollmentKeyUnavailable);
}

// -----------------------------------------------------------------------------
// requirePassword=false: passes unconditionally, regardless of whether the listener separately
// requires a client certificate ("mTLS-only") or not ("Open") -- this class has no notion of
// mTLS at all, since a client certificate is the TLS listener's concern, never this one's (see
// the class comment in enrollmentAuthenticator.hpp).
// -----------------------------------------------------------------------------

TEST(EnrollmentAuthenticatorTest, RequirePasswordFalseAlwaysPasses)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    EXPECT_EQ(authenticator.authenticate(kVersion, "", kSmallBody, kNow), std::nullopt);
    EXPECT_EQ(authenticator.authenticate(kVersion, "garbage", kSmallBody, kNow), std::nullopt);
}

// -----------------------------------------------------------------------------
// protocol-version -- validated FIRST, in every mode, exactly as AuthMiddleware does for every
// other authenticated route. Regression guard: /enroll used to skip this check entirely, so a
// wrong or missing version surfaced as an opaque 401 (or, in Open mode, was accepted outright)
// instead of a 400.
// -----------------------------------------------------------------------------

TEST(EnrollmentAuthenticatorTest, MissingProtocolVersionIsRejectedInOpenMode)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    const auto err = authenticator.authenticate("", "", kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingProtocolVersion);
}

TEST(EnrollmentAuthenticatorTest, UnsupportedProtocolVersionIsRejectedInOpenMode)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    const auto err = authenticator.authenticate("2", "", kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::UnsupportedProtocolVersion);
}

TEST_F(PasswordFixture, MissingProtocolVersionIsRejectedBeforeTheBearerIsChecked)
{
    // A perfectly valid bearer, but no protocol-version: the version rejection must win, or the
    // check isn't really first.
    const auto err = authenticator.authenticate("", validBearer(), kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingProtocolVersion);
}

TEST_F(PasswordFixture, UnsupportedProtocolVersionIsRejectedBeforeTheBearerIsChecked)
{
    const auto err = authenticator.authenticate("99", validBearer(), kSmallBody, kNow);
    ASSERT_TRUE(err.has_value());
    // NOT a credential error: a version mismatch must surface as its own 400, not as an opaque
    // failure the operator cannot tell apart from a wrong password.
    EXPECT_EQ(*err, AuthError::UnsupportedProtocolVersion);
}

TEST(EnrollmentAuthenticatorTest, ProtocolVersionIsRejectedBeforeTheBodySizeCap)
{
    // Both wrong: no version AND an oversized body. The version check runs first, so that is the
    // error -- matching AuthMiddleware, where protocol-version is step 1.
    EnrollmentAuthConfig config {false};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    const auto err = authenticator.authenticate("", "", 11, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingProtocolVersion);
}

// -----------------------------------------------------------------------------
// maxBodySize -- checked once the protocol version is accepted, in every mode. Regression guard:
// this class used to have no body-size cap at all, so an unauthenticated peer could make the
// endpoint hold an arbitrarily large body (up to the transport's own cap) before being rejected.
// -----------------------------------------------------------------------------

TEST(EnrollmentAuthenticatorTest, OversizedBodyIsRejectedBeforeTheCredentialCheckInOpenMode)
{
    EnrollmentAuthConfig config {false};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    const auto err = authenticator.authenticate(kVersion, "", 11, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::BodyTooLarge);
}

TEST(EnrollmentAuthenticatorTest, BodyAtOrUnderTheCapIsNotRejectedOnSizeAloneInOpenMode)
{
    EnrollmentAuthConfig config {false};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    EXPECT_EQ(authenticator.authenticate(kVersion, "", 10, kNow), std::nullopt);
}

TEST(EnrollmentAuthenticatorTest, OversizedBodyIsRejectedBeforeTheBearerIsCheckedInPasswordMode)
{
    // No Authorization header at all, AND an oversized body: if this returned
    // MissingAuthorization instead, the size check would be running after (or not at all before)
    // the rest of authenticatePassword() -- BodyTooLarge proves it runs first.
    EnrollmentAuthConfig config {true};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    const auto err = authenticator.authenticate(kVersion, "", 11, kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::BodyTooLarge);
}
