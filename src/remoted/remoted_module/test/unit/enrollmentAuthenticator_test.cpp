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
// enforces, the Open-mode pass-through, the `wazuh-enroll+jwt` bearer check of Password mode
// (the token grammar itself is the shared verifier's job -- jwtEnrollSignVerify_test.cpp -- so
// here the negatives are the ones the authenticator's own wiring can get wrong: scheme, key
// availability, time policy, hot-reloaded password, cross-profile token), and the enrollment-token
// path (issue #38993): a `kid` naming a token id resolves its key from TokenKeySource, is verified
// in EVERY mode, and answers the token's own state after the signature. Last, the re-enrollment
// path: a `kid` naming an agent travels to the master with its signature unchecked, but only after
// its MESSAGE passes the checks that need no secret (claim set + time rules).

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>
#include <variant>

#include <gtest/gtest.h>

#include "auth/tokenKeySource.hpp"
#include "enrollment/enrollmentAuthenticator.hpp"
#include "jwt/base64Url.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/testVectors.hpp"

using namespace remoted::enrollment;
using jwt_profile::v1::SecureBytes;
using jwt_profile::v1::TimePolicy;
using jwt_profile::v1::enroll::JwtEnrollTokenSigner;
using remoted::auth::AuthError;
using remoted::auth::PasswordKeySource;
using remoted::auth::TokenKeySource;
namespace tv = jwt_profile::v1::test_vectors::enroll;
namespace tvt = jwt_profile::v1::test_vectors::enroll_token;

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

    // The decision as the pre-token tests read it: the rejection, or nullopt when granted. Every
    // existing case keeps its shape through this one helper; the token cases look at the grant.
    std::optional<AuthError> errorOf(const EnrollmentDecision& decision)
    {
        if (const auto* err = std::get_if<AuthError>(&decision))
        {
            return *err;
        }
        return std::nullopt;
    }

    std::optional<ReenrollmentRequested> reenrollOf(const EnrollmentDecision& decision)
    {
        if (const auto* reenroll = std::get_if<ReenrollmentRequested>(&decision))
        {
            return *reenroll;
        }
        return std::nullopt;
    }

    // The verdict of a re-enrollment bearer remoted refused itself (ReenrollmentRejected), or
    // nullopt when the decision is anything else -- including a plain AuthError, which for a
    // re-enrollment bearer would mean the rejection lost its "this was a re-enrollment" attribution
    // (and with it the endpoint's remoted.enroll.reenroll.* cell).
    std::optional<AuthError> reenrollRejectionOf(const EnrollmentDecision& decision)
    {
        if (const auto* rejected = std::get_if<ReenrollmentRejected>(&decision))
        {
            return rejected->error;
        }
        return std::nullopt;
    }

    std::optional<std::string> tokenIdOf(const EnrollmentDecision& decision)
    {
        const auto* granted = std::get_if<EnrollmentGranted>(&decision);
        EXPECT_NE(granted, nullptr) << "rejected: "
                                    << (granted ? "" : remoted::auth::toString(std::get<AuthError>(decision)));
        return granted ? granted->tokenId : std::nullopt;
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
            return errorOf(authenticator.authenticate(kVersion, authorization, kSmallBody, now));
        }
    };

    // ---- enrollment tokens (issue #38993): a TokenKeySource over a store holding the vector token.

    constexpr std::int64_t kFarFuture = 4102444800;
    // Another canonical 22-char token id (16 zero bytes): well-formed, never minted.
    constexpr std::string_view kOtherKid = "AAAAAAAAAAAAAAAAAAAAAA";

    std::string writeTokenStore(std::int64_t expires = kFarFuture, bool revoked = false, const char* tag = "")
    {
        const std::string path = "/tmp/enrollmentAuthenticator_test_" + std::to_string(getpid()) + tag + ".tokens.json";
        std::ofstream file(path);
        file << R"({"version":1,"tokens":[{"id":")" << tvt::kIdB64Url << R"(","secret":")" << tvt::kSecretB64Url
             << R"(","adr":"siem.example.local","pin":")" << tvt::kPinB64Url
             << R"(","ca":null,"created":1700000000,"expires":)" << expires << R"(,"max_uses":0,"uses":0,"revoked":)"
             << (revoked ? "true" : "false") << R"(,"description":null}]})";
        return path;
    }

    SecureBytes vectorTokenKey()
    {
        SecureBytes secret(jwt_profile::v1::enroll::kTokenSecretBytes);
        for (std::size_t i = 0; i < secret.size(); ++i)
        {
            secret.data()[i] = static_cast<std::uint8_t>(0x10 + i); // kSecretHex: 0x10..0x1f
        }
        auto key = jwt_profile::v1::enroll::deriveEnrollTokenKey(secret);
        EXPECT_TRUE(key.has_value());
        return std::move(*key);
    }

    std::string tokenBearer(const SecureBytes& key, std::string_view kid, std::int64_t ts)
    {
        const auto token = JwtEnrollTokenSigner::signWithKid(key, at(ts), kid);
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }

    struct TokenFixture : public ::testing::Test
    {
        std::string storePath = writeTokenStore();
        std::shared_ptr<TokenKeySource> tokenSource = std::make_shared<TokenKeySource>(storePath);
        SecureBytes key = vectorTokenKey();

        void TearDown() override
        {
            std::remove(storePath.c_str());
        }

        std::string validTokenBearer(std::int64_t ts = kNow)
        {
            return tokenBearer(key, tvt::kIdB64Url, ts);
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

TEST_F(PasswordFixture, KidNamingAnAgentIsAReenrollmentNotAPasswordBearer)
{
    // Correct password key and signature, but the header carries `kid` = "001": that is the
    // re-enrollment form (issue #38993), so it is NOT accepted as a password bearer (the shared-key
    // verifier keeps refusing the extra header -- jwtEnrollSignVerify_test pins that) and not rejected
    // here either: it goes to authd unverified, and authd, holding the agent's secret, refuses it (9027).
    const auto decision =
        authenticator.authenticate(kVersion, "Bearer " + std::string {tv::kKidHeaderToken}, kSmallBody, kNow);
    EXPECT_EQ(errorOf(decision), std::nullopt);
    EXPECT_FALSE(std::holds_alternative<EnrollmentGranted>(decision));
    const auto reenroll = reenrollOf(decision);
    ASSERT_TRUE(reenroll.has_value());
    EXPECT_EQ(reenroll->agentId, "001");
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

    EXPECT_EQ(errorOf(narrow.authenticate(kVersion, validBearer(kNow - 10), kSmallBody, kNow)), std::nullopt);
    const auto tooOld = errorOf(narrow.authenticate(kVersion, validBearer(kNow - 11), kSmallBody, kNow));
    ASSERT_TRUE(tooOld.has_value());
    EXPECT_EQ(*tooOld, AuthError::StaleToken);
    const auto future = errorOf(narrow.authenticate(kVersion, validBearer(kNow + 1), kSmallBody, kNow));
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

    const auto err =
        errorOf(authenticator.authenticate(kVersion, "Bearer " + std::string {tv::kToken}, kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::EnrollmentKeyUnavailable);
}

TEST(EnrollmentAuthenticatorTest, PasswordModeWithoutAKeySourceFailsClosed)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, nullptr};
    const auto err =
        errorOf(authenticator.authenticate(kVersion, "Bearer " + std::string {tv::kToken}, kSmallBody, kNow));
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
    EXPECT_EQ(errorOf(authenticator.authenticate(kVersion, "", kSmallBody, kNow)), std::nullopt);
    EXPECT_EQ(errorOf(authenticator.authenticate(kVersion, "garbage", kSmallBody, kNow)), std::nullopt);
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
    const auto err = errorOf(authenticator.authenticate("", "", kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingProtocolVersion);
}

TEST(EnrollmentAuthenticatorTest, UnsupportedProtocolVersionIsRejectedInOpenMode)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    const auto err = errorOf(authenticator.authenticate("2", "", kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::UnsupportedProtocolVersion);
}

TEST_F(PasswordFixture, MissingProtocolVersionIsRejectedBeforeTheBearerIsChecked)
{
    // A perfectly valid bearer, but no protocol-version: the version rejection must win, or the
    // check isn't really first.
    const auto err = errorOf(authenticator.authenticate("", validBearer(), kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingProtocolVersion);
}

TEST_F(PasswordFixture, UnsupportedProtocolVersionIsRejectedBeforeTheBearerIsChecked)
{
    const auto err = errorOf(authenticator.authenticate("99", validBearer(), kSmallBody, kNow));
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

    const auto err = errorOf(authenticator.authenticate("", "", 11, kNow));
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

    const auto err = errorOf(authenticator.authenticate(kVersion, "", 11, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::BodyTooLarge);
}

TEST(EnrollmentAuthenticatorTest, BodyAtOrUnderTheCapIsNotRejectedOnSizeAloneInOpenMode)
{
    EnrollmentAuthConfig config {false};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    EXPECT_EQ(errorOf(authenticator.authenticate(kVersion, "", 10, kNow)), std::nullopt);
}

TEST(EnrollmentAuthenticatorTest, OversizedBodyIsRejectedBeforeTheBearerIsCheckedInPasswordMode)
{
    // No Authorization header at all, AND an oversized body: if this returned
    // MissingAuthorization instead, the size check would be running after (or not at all before)
    // the rest of authenticatePassword() -- BodyTooLarge proves it runs first.
    EnrollmentAuthConfig config {true};
    config.maxBodySize = 10;
    EnrollmentAuthenticator authenticator {config, nullptr};

    const auto err = errorOf(authenticator.authenticate(kVersion, "", 11, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::BodyTooLarge);
}

// -----------------------------------------------------------------------------
// Enrollment tokens (issue #38993): `kid` = token id. Verified in EVERY mode -- a presented
// credential is never ignored -- against the key TokenKeySource derived from the store; then the
// token's own state, in the order lookup -> signature -> expiry -> revocation.
// -----------------------------------------------------------------------------

TEST_F(TokenFixture, TokenBearerIsAcceptedEvenWhenPasswordIsNotRequired)
{
    // Open mode (or mTLS-only): a token bearer is still checked, and the grant carries its id.
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto decision = open.authenticate(kVersion, validTokenBearer(), kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::string {tvt::kIdB64Url});
}

TEST_F(TokenFixture, TokenBearerIsAcceptedInPasswordMode)
{
    // Password mode with NO password file at all: the token path does not need the password key.
    EnrollmentAuthenticator password {EnrollmentAuthConfig {true}, nullptr, tokenSource};
    const auto decision = password.authenticate(kVersion, validTokenBearer(), kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::string {tvt::kIdB64Url});
}

TEST_F(TokenFixture, TheFrozenVectorTokenKidJwtIsAccepted)
{
    // Interop pin across the whole chain: store record -> HKDF (matching authd's C) -> verifyWithKid
    // accepts the token every other implementation (Go sender, Python tools) reproduces byte for
    // byte from jwt_vectors.json.
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto decision = open.authenticate(kVersion, "Bearer " + std::string {tvt::kTokenKidJwt}, kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::string {tvt::kIdB64Url});
}

TEST_F(TokenFixture, UnknownTokenIdIsTokenUnknown)
{
    // Correctly signed with the vector key, but the header names an id the store never minted:
    // the lookup fails first (and the forced re-read finds nothing either).
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto err = errorOf(open.authenticate(kVersion, tokenBearer(key, kOtherKid, kNow), kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::TokenUnknown);
}

TEST_F(TokenFixture, WrongTokenSecretIsInvalidSignature)
{
    // The right `kid`, a token signed with some other key: the signature check fails BEFORE the
    // token's status is looked at.
    SecureBytes wrongKey(32);
    for (std::size_t i = 0; i < wrongKey.size(); ++i)
    {
        wrongKey.data()[i] = static_cast<std::uint8_t>(0xa5);
    }
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto err =
        errorOf(open.authenticate(kVersion, tokenBearer(wrongKey, tvt::kIdB64Url, kNow), kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidSignature);
}

TEST(EnrollmentAuthenticatorTokenTest, ExpiredTokenIsTokenExpired)
{
    // `now >= expires` is expired -- the same boundary authd's consume applies -- and only a
    // correctly signed bearer learns it (signature first).
    const std::string path = writeTokenStore(kNow, false, "_expired");
    auto tokenSource = std::make_shared<TokenKeySource>(path);
    const auto key = vectorTokenKey();
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};

    const auto atBoundary =
        errorOf(open.authenticate(kVersion, tokenBearer(key, tvt::kIdB64Url, kNow), kSmallBody, kNow));
    ASSERT_TRUE(atBoundary.has_value());
    EXPECT_EQ(*atBoundary, AuthError::TokenExpired);

    // One second earlier the token is still usable.
    EXPECT_EQ(tokenIdOf(open.authenticate(kVersion, tokenBearer(key, tvt::kIdB64Url, kNow - 1), kSmallBody, kNow - 1)),
              std::string {tvt::kIdB64Url});

    // Expired but ALSO wrongly signed: the signature verdict wins (nothing about the token's state
    // is revealed to a caller that does not hold its secret).
    SecureBytes wrongKey(32);
    const auto wrong =
        errorOf(open.authenticate(kVersion, tokenBearer(wrongKey, tvt::kIdB64Url, kNow), kSmallBody, kNow));
    ASSERT_TRUE(wrong.has_value());
    EXPECT_EQ(*wrong, AuthError::InvalidSignature);

    std::remove(path.c_str());
}

TEST(EnrollmentAuthenticatorTokenTest, RevokedTokenIsTokenRevoked)
{
    const std::string path = writeTokenStore(kFarFuture, true, "_revoked");
    auto tokenSource = std::make_shared<TokenKeySource>(path);
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};

    const auto err =
        errorOf(open.authenticate(kVersion, tokenBearer(vectorTokenKey(), tvt::kIdB64Url, kNow), kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::TokenRevoked);

    std::remove(path.c_str());
}

// -----------------------------------------------------------------------------
// Re-enrollment (issue #38993): `kid` = canonical agent id. Recognised by shape in every mode and
// handed back with its SIGNATURE unverified -- the secret that signs it is the master's alone, so
// authd verifies that (its 9026/9027/9028 become the endpoint's uniform 401). What remoted does
// check, because it costs no secret, is the MESSAGE: the exact claim set and the time rules
// (precheckMessage()). So a bearer signed with garbage is still forwarded, while one whose claims
// are absent, malformed or stale -- the frozen vector at a `now` years later, say -- is refused
// here, with the very verdict the master would have sent.
// -----------------------------------------------------------------------------

TEST_F(TokenFixture, AgentKidIsForwardedAsReenrollmentInOpenMode)
{
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto reenroll =
        reenrollOf(open.authenticate(kVersion, "Bearer " + std::string {tvt::kAgentKidJwt}, kSmallBody, kNow));
    ASSERT_TRUE(reenroll.has_value());
    EXPECT_EQ(reenroll->agentId, std::string {tvt::kAgentKid});
    EXPECT_EQ(reenroll->bearer, std::string {tvt::kAgentKidJwt}); // verbatim: what authd verifies
}

TEST_F(TokenFixture, AgentKidIsForwardedAsReenrollmentInPasswordModeWithoutThePasswordKey)
{
    // Password mode with no password file at all: the agent bearer is not a password bearer, so
    // neither the key nor its absence (EnrollmentKeyUnavailable) is consulted.
    EnrollmentAuthenticator password {EnrollmentAuthConfig {true}, nullptr, tokenSource};
    const auto reenroll =
        reenrollOf(password.authenticate(kVersion, "Bearer " + std::string {tvt::kAgentKidJwt}, kSmallBody, kNow));
    ASSERT_TRUE(reenroll.has_value());
    EXPECT_EQ(reenroll->agentId, std::string {tvt::kAgentKid});
}

TEST(EnrollmentAuthenticatorTest, AgentKidIsForwardedWithoutATokenSourceAndWhateverTheSignature)
{
    // No token replica (it is about enrollment tokens, not agents), and a bearer whose signature is
    // garbage: still forwarded -- remoted has no key to check it with; authd does.
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr};
    const std::string vector {tvt::kAgentKidJwt};
    const std::string garbageSignature =
        vector.substr(0, vector.rfind('.') + 1) + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const auto reenroll = reenrollOf(open.authenticate(kVersion, "Bearer " + garbageSignature, kSmallBody, kNow));
    ASSERT_TRUE(reenroll.has_value());
    EXPECT_EQ(reenroll->agentId, "001");
    EXPECT_EQ(reenroll->bearer, garbageSignature);

    // The gates that ARE remoted's still apply to it: protocol version and body cap.
    EXPECT_EQ(errorOf(open.authenticate("", "Bearer " + vector, kSmallBody, kNow)), AuthError::MissingProtocolVersion);
    EnrollmentAuthConfig capped;
    capped.maxBodySize = 10;
    EnrollmentAuthenticator small {capped, nullptr};
    EXPECT_EQ(errorOf(small.authenticate(kVersion, "Bearer " + vector, 11, kNow)), AuthError::BodyTooLarge);
}

// The finding this pre-filter exists for: 130 constant bytes, no credential of any kind, and before
// it they bought an authd connection per request -- plus, on a worker, a clustered hop to the master
// with up to 10 attempts and 1 s sleeps on a degraded link. /enroll has no rate limiter, so the only
// thing between that and the AuthdClient's 256-deep queue was the master's own verdict. That the
// request no longer reaches authd at all is asserted on the mock in enrollmentEndpoint_test.cpp;
// here, that the authenticator refuses it.
TEST(EnrollmentAuthenticatorReenrollTest, AMessageThatIsNotEvenJsonIsRefusedInEveryMode)
{
    // {"alg":"HS256","kid":"001","typ":"wazuh-enroll+jwt"} . base64url(one byte) . 32 zero bytes:
    // canonical grammar and an Agent-shaped `kid`, so peekKid() classifies it -- and the payload is
    // not JSON at all.
    constexpr std::string_view kNotJson =
        "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.AA."
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    // In Open mode and in Password mode alike -- the mode never mattered on this path, and does not
    // now: the message is refused before either is consulted.
    for (const bool requirePassword : {false, true})
    {
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {requirePassword}, nullptr};
        const auto decision = authenticator.authenticate(kVersion, kNotJson, kSmallBody, kNow);
        EXPECT_FALSE(reenrollOf(decision).has_value()) << "forwarded with requirePassword=" << requirePassword;
        // Refused as a re-enrollment (so the endpoint counts it in remoted.enroll.reenroll.*), with
        // the AuthError whose public class is the one authd's 9027 maps to: `invalid_signature`.
        EXPECT_EQ(reenrollRejectionOf(decision), AuthError::InvalidToken);
    }
}

TEST(EnrollmentAuthenticatorReenrollTest, StaleAndMalformedClaimsAreRefusedWithTheMastersOwnVerdicts)
{
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr};
    const auto reenrollBearer = [](std::int64_t ts)
    {
        // Any key at all: this path never checks the signature, so what is under test is the message.
        const auto token = JwtEnrollTokenSigner::signWithKid(SecureBytes(32), at(ts), "001");
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    };
    const auto run = [&](std::string_view authorization, std::int64_t now = kNow)
    {
        return open.authenticate(kVersion, authorization, kSmallBody, now);
    };

    // Fresh: forwarded, as before. On the edge of the accepted age (60 s + 30 s skew): still forwarded.
    EXPECT_TRUE(reenrollOf(run(reenrollBearer(kNow))).has_value());
    EXPECT_TRUE(reenrollOf(run(reenrollBearer(kNow - 90))).has_value());
    // One second past it, and one issued beyond the skew ahead: StaleToken -> `stale_token`, the
    // class authd's 9028 maps to, so the agent is told the same thing ("fix the clock") either way.
    EXPECT_EQ(reenrollRejectionOf(run(reenrollBearer(kNow - 91))), AuthError::StaleToken);
    EXPECT_EQ(reenrollRejectionOf(run(reenrollBearer(kNow + 31))), AuthError::StaleToken);
    // The frozen vector, replayed years later: the shape a captured bearer has. Refused here now.
    EXPECT_EQ(reenrollRejectionOf(run("Bearer " + std::string {tvt::kAgentKidJwt}, kNow + 9999)),
              AuthError::StaleToken);

    // A claim set that is well-formed JSON but not this profile's: an extra `sub`, signed so the
    // grammar and header are beyond reproach.
    const std::string header {tvt::kAgentKidHeaderJson};
    const std::string payload =
        R"({"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000,"sub":"001"})";
    const auto signingInput =
        jwt_profile::v1::base64UrlEncode(header) + "." + jwt_profile::v1::base64UrlEncode(payload);
    jwt_profile::v1::HmacSha256Digest mac {};
    ASSERT_TRUE(jwt_profile::v1::hmacSha256(SecureBytes(32), signingInput, mac));
    const auto extraClaim = signingInput + "." + jwt_profile::v1::base64UrlEncode(mac.data(), mac.size());
    EXPECT_EQ(reenrollRejectionOf(run("Bearer " + extraClaim)), AuthError::InvalidToken);
}

TEST(EnrollmentAuthenticatorReenrollTest, ThePolicyThePreFilterAppliesIsTheConfiguredOne)
{
    // The pre-filter must never be stricter than the master's own check: both read the same
    // remoted.jwt_max_age / remoted.jwt_clock_skew policy (authd reads remoted's internal options
    // for w_reenroll_verify()), so a manager configured with a wide skew keeps forwarding what that
    // skew allows.
    EnrollmentAuthConfig wide;
    wide.timePolicy = *jwt_profile::v1::TimePolicy::tryMake(jwt_profile::v1::kDefaultAgeSec, 120);
    EnrollmentAuthenticator tolerant {wide, nullptr};
    EnrollmentAuthenticator strict {EnrollmentAuthConfig {false}, nullptr};

    const std::string bearer = "Bearer " + std::string {tvt::kAgentKidJwt};
    EXPECT_EQ(reenrollRejectionOf(strict.authenticate(kVersion, bearer, kSmallBody, tv::kIat + 91)),
              AuthError::StaleToken);
    EXPECT_TRUE(reenrollOf(tolerant.authenticate(kVersion, bearer, kSmallBody, tv::kIat + 91)).has_value());
}

TEST_F(TokenFixture, NoTokenSourceRejectsTokensAsUnknown)
{
    // Fail closed: without a replica every token bearer is unknown -- NOT granted by falling
    // through to Open mode.
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, nullptr};
    const auto err = errorOf(open.authenticate(kVersion, validTokenBearer(), kSmallBody, kNow));
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::TokenUnknown);
}

TEST_F(TokenFixture, UnknownKidForcesOneReReadOfTheStore)
{
    // P35b: the token was minted after this node last read the store (the file is rewritten under
    // a source whose poll would not notice it for an hour, and whose inotify watch was never armed
    // because the file did not exist at construction) -- the first request for it must still succeed.
    const std::string path = "/tmp/enrollmentAuthenticator_test_" + std::to_string(getpid()) + "_late.tokens.json";
    std::remove(path.c_str());
    auto lateSource = std::make_shared<TokenKeySource>(path, /*refreshIntervalSeconds=*/3600);
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, lateSource};

    {
        std::ofstream file(path);
        file << R"({"version":1,"tokens":[{"id":")" << tvt::kIdB64Url << R"(","secret":")" << tvt::kSecretB64Url
             << R"(","expires":4102444800,"revoked":false}]})";
    }
    const auto decision = open.authenticate(kVersion, validTokenBearer(), kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::string {tvt::kIdB64Url});

    std::remove(path.c_str());
}

TEST_F(TokenFixture, SharedKeyBearerInOpenModeIsIgnoredAsBefore)
{
    // Regression guard: a `kid`-less (password-form) bearer in Open mode is not a token credential,
    // so it is ignored exactly as before tokens existed -- granted, with no token id.
    EnrollmentAuthenticator open {EnrollmentAuthConfig {false}, nullptr, tokenSource};
    const auto decision =
        open.authenticate(kVersion, "Bearer " + std::string {tv::kWrongPasswordToken}, kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::nullopt);
}

TEST_F(PasswordFixture, PasswordBearerGrantsWithoutATokenId)
{
    // The password path never names a token: authd's `add` stays byte-identical for it.
    const auto decision = authenticator.authenticate(kVersion, validBearer(), kSmallBody, kNow);
    EXPECT_EQ(tokenIdOf(decision), std::nullopt);
}
