/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Exercises AuthMiddleware in isolation -- no sockets, no transport -- against a REAL Keystore
// parsed from a scratch client.keys: the `Bearer <wazuh-agent+jwt>` path end to end, every
// AuthError the request path can produce, and the client.keys ip column. Token-level negatives
// (grammar, claims, time rules) are exhaustively covered in jwtVerify_test.cpp; here each class is
// checked once to pin how it maps to AuthError.
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

#include "auth/authMiddleware.hpp"
#include "auth/keystore.hpp"
#include "jwt/base64Url.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/testVectors.hpp"

using namespace remoted::auth;
namespace jwt1 = jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors;

namespace
{

    constexpr std::int64_t kNow = 1'784'238'000;

    // The agent's 64-hex client.keys secret (the frozen vector key: binary, leading 0x00).
    const std::string kKeyHex {tv::kKeyHex};
    // A second, unrelated 32-byte key for "signed with the wrong key" cases.
    const std::string kOtherKeyHex = "ff30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6100";

    // The peer address most tests run from. The fixture registers the agent as `any`, so the value
    // only has to be a valid address; tests that exercise the ip column set their own.
    constexpr const char* kPeerIp = "10.0.0.7";

    jwt1::SecureBytes keyFromHex(const std::string& hex)
    {
        auto key = jwt1::JwtKeyDecoder::decode(hex);
        EXPECT_TRUE(key) << hex;
        return key ? std::move(*key) : jwt1::SecureBytes {};
    }

    // Writes a one-agent client.keys to a scratch path so Keystore has something real to parse,
    // instead of a stub built just for tests.
    std::string writeClientKeysFile(const std::string& agentId,
                                    const std::string& keyHex,
                                    const std::string& ip = "any",
                                    const std::string& suffix = "")
    {
        const std::string path = "/tmp/authMiddleware_test_" + std::to_string(getpid()) + suffix + ".keys";
        std::ofstream file(path);
        file << agentId << " test-agent " << ip << " " << keyHex << "\n";
        return path;
    }

    std::chrono::system_clock::time_point at(std::int64_t epoch)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epoch}};
    }

    /// A well-formed bearer for `agentId`, minted with the production signer.
    std::string bearer(const std::string& agentId, const std::string& keyHex = kKeyHex, std::int64_t iat = kNow)
    {
        const auto key = keyFromHex(keyHex);
        const auto token = jwt1::JwtRequestTokenSigner::sign(*jwt1::CanonicalAgentId::parse(agentId), key, at(iat));
        EXPECT_TRUE(token);
        return "Bearer " + (token ? *token : std::string {});
    }

    /// A bearer assembled from arbitrary header/payload JSON (for claim-level mutations the signer
    /// would never emit), signed with `keyHex`.
    std::string
    rawBearer(const std::string& headerJson, const std::string& payloadJson, const std::string& keyHex = kKeyHex)
    {
        const auto key = keyFromHex(keyHex);
        std::string signingInput = jwt1::base64UrlEncode(headerJson) + "." + jwt1::base64UrlEncode(payloadJson);
        jwt1::HmacSha256Digest mac {};
        EXPECT_TRUE(jwt1::hmacSha256(key, signingInput, mac));
        return "Bearer " + signingInput + "." + jwt1::base64UrlEncode(mac.data(), mac.size());
    }

    std::string header(const std::string& kid)
    {
        return R"({"alg":"HS256","kid":")" + kid + R"(","typ":"wazuh-agent+jwt"})";
    }

    std::string payload(const std::string& sub, const std::string& issId, std::int64_t iat = kNow)
    {
        return R"({"exp":)" + std::to_string(iat + 60) + R"(,"iat":)" + std::to_string(iat) +
               R"(,"iss":"wazuh-agent/)" + issId + R"(","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":)" + std::to_string(iat) +
               R"(,"sub":")" + sub + R"("})";
    }

    struct Fixture
    {
        std::string path = writeClientKeysFile("001", kKeyHex);
        std::shared_ptr<Keystore> keyStore = std::make_shared<Keystore>(path);
        AuthMiddleware middleware {AuthConfig {}, keyStore};

        ~Fixture()
        {
            std::remove(path.c_str());
        }

        std::variant<VerifiedAgent, AuthError> run(std::string_view protocolVersion,
                                                   std::string_view authorization,
                                                   std::int64_t now = kNow,
                                                   std::string_view peerIp = kPeerIp)
        {
            return middleware.authenticate(protocolVersion, authorization, peerIp, now);
        }
    };

    AuthError errorOf(const std::variant<VerifiedAgent, AuthError>& result)
    {
        return std::holds_alternative<AuthError>(result) ? std::get<AuthError>(result) : AuthError::None;
    }

    // Same as Fixture, but the agent is registered with a specific ip column instead of `any`. Its
    // scratch file gets its own name so it never collides with a Fixture living in the same test.
    struct FixedAddressFixture
    {
        std::string path;
        std::shared_ptr<Keystore> keyStore;
        AuthMiddleware middleware;

        explicit FixedAddressFixture(const std::string& ip)
            : path {writeClientKeysFile("001", kKeyHex, ip, "_fixed")}
            , keyStore {std::make_shared<Keystore>(path)}
            , middleware {AuthConfig {}, keyStore}
        {
        }

        ~FixedAddressFixture()
        {
            std::remove(path.c_str());
        }

        // Runs a valid bearer from `peerIp`, so the only variable under test is the address the
        // request arrives from.
        std::variant<VerifiedAgent, AuthError> runFrom(std::string_view peerIp)
        {
            return middleware.authenticate("1", bearer("001"), peerIp, kNow);
        }
    };

    // --- ip column -------------------------------------------------------------------------------

    TEST(MiddlewareAddress, AnyRegistrationAcceptsAnyPeer)
    {
        Fixture f;
        for (const auto* peer : {"10.0.0.7", "203.0.113.9", "2001:db8::1"})
        {
            const auto result = f.run("1", bearer("001"), kNow, peer);
            EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(result)) << peer << ": " << toString(errorOf(result));
        }
    }

    TEST(MiddlewareAddress, FixedRegistrationAcceptsTheRegisteredPeer)
    {
        FixedAddressFixture f {"10.0.0.5"};
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.runFrom("10.0.0.5")));
    }

    TEST(MiddlewareAddress, FixedRegistrationRejectsAnotherPeer)
    {
        FixedAddressFixture f {"10.0.0.5"};
        EXPECT_EQ(errorOf(f.runFrom("10.0.0.6")), AuthError::AddressNotAllowed);
    }

    TEST(MiddlewareAddress, RangeRegistrationAcceptsAPeerInTheRange)
    {
        FixedAddressFixture f {"10.0.0.0/24"};
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.runFrom("10.0.0.200")));
        EXPECT_EQ(errorOf(f.runFrom("10.0.1.1")), AuthError::AddressNotAllowed);
    }

    // The address is never part of the token: a NAT rewrite must not invalidate a token, and the
    // same token is valid from every address the registration allows.
    TEST(MiddlewareAddress, ThePeerAddressIsNotPartOfTheToken)
    {
        FixedAddressFixture f {"10.0.0.0/24"};
        const auto token = bearer("001");
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.middleware.authenticate("1", token, "10.0.0.1", kNow)));
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.middleware.authenticate("1", token, "10.0.0.2", kNow)));
    }

    // A disallowed peer is answered before any HMAC runs: even a token with a broken signature gets
    // AddressNotAllowed, not InvalidSignature.
    TEST(MiddlewareAddress, AddressIsCheckedBeforeTheSignature)
    {
        FixedAddressFixture f {"10.0.0.5"};
        const auto result = f.middleware.authenticate("1", bearer("001", kOtherKeyHex), "10.0.0.6", kNow);
        EXPECT_EQ(errorOf(result), AuthError::AddressNotAllowed);
    }

    TEST(MiddlewareAddress, RejectionIsIndistinguishableFromAnUnknownAgent)
    {
        const auto denied = publicErrorFor(AuthError::AddressNotAllowed);
        const auto unknown = publicErrorFor(AuthError::UnknownAgent);
        EXPECT_EQ(denied.status, 401);
        EXPECT_EQ(denied.status, unknown.status);
        EXPECT_STREQ(denied.message, unknown.message);
    }

    TEST(MiddlewareAddress, ErrorHasItsOwnLogTag)
    {
        EXPECT_STREQ(toString(AuthError::AddressNotAllowed), "address_not_allowed");
    }

    // --- happy path ------------------------------------------------------------------------------

    TEST(Middleware, ValidBearerAuthenticatesTheCanonicalAgent)
    {
        Fixture f;
        const auto result = f.run("1", bearer("001"));
        ASSERT_TRUE(std::holds_alternative<VerifiedAgent>(result)) << toString(errorOf(result));
        EXPECT_EQ(std::get<VerifiedAgent>(result).agentId, "001");
    }

    TEST(Middleware, TheFrozenVectorAuthenticatesAtItsOwnTime)
    {
        Fixture f;
        const auto result = f.run("1", "Bearer " + std::string(tv::kToken), tv::kIat + 5);
        ASSERT_TRUE(std::holds_alternative<VerifiedAgent>(result)) << toString(errorOf(result));
        EXPECT_EQ(std::get<VerifiedAgent>(result).agentId, "001");
    }

    // An agent configured as "1" signs as "001": the signer canonicalises, the token carries the
    // canonical id, and the identity that comes out is the client.keys spelling.
    TEST(Middleware, TheSignerCanonicalisesAndTheIdentityIsCanonical)
    {
        Fixture f;
        for (const auto* configured : {"1", "01", "001", "0001"})
        {
            const auto result = f.run("1", bearer(configured));
            ASSERT_TRUE(std::holds_alternative<VerifiedAgent>(result)) << configured;
            EXPECT_EQ(std::get<VerifiedAgent>(result).agentId, "001") << configured;
        }
    }

    // A token whose `kid`/`sub` spell the id non-canonically is a protocol violation, not an
    // alias: the profile fixes the spelling.
    TEST(Middleware, ANonCanonicalKidIsRejected)
    {
        Fixture f;
        for (const auto* kid : {"1", "01", "0001"})
        {
            EXPECT_EQ(errorOf(f.run("1", rawBearer(header(kid), payload(kid, kid)))), AuthError::InvalidToken) << kid;
        }
    }

    // Identity only: the same token authenticates any number of requests within its life (no replay
    // store by design -- TLS + the 60 s life bound replay; see the plan's deferred items).
    TEST(Middleware, TheSameTokenAuthenticatesRepeatedly)
    {
        Fixture f;
        const auto token = bearer("001");
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.run("1", token)));
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.run("1", token, kNow + 30)));
    }

    // --- protocol-version / Authorization framing --------------------------------------------------

    TEST(Middleware, MissingProtocolVersionIsRejected)
    {
        Fixture f;
        EXPECT_EQ(errorOf(f.run("", bearer("001"))), AuthError::MissingProtocolVersion);
    }

    TEST(Middleware, UnsupportedProtocolVersionIsRejected)
    {
        Fixture f;
        for (const auto* pv : {"2", "0", "1 ", " 1", "1.0", "one"})
        {
            EXPECT_EQ(errorOf(f.run(pv, bearer("001"))), AuthError::UnsupportedProtocolVersion) << pv;
        }
    }

    TEST(Middleware, MissingAuthorizationIsRejected)
    {
        Fixture f;
        EXPECT_EQ(errorOf(f.run("1", "")), AuthError::MissingAuthorization);
    }

    TEST(Middleware, ANonBearerSchemeIsMalformed)
    {
        Fixture f;
        const std::string token = bearer("001").substr(7);
        const std::vector<std::string> malformed {
            "Wazuh 001:1784238000:00112233445566778899aabbccddeeff", // an unknown scheme
            "bearer " + token,                                       // wrong case
            "BEARER " + token,
            "Bearer",
            "Bearer ",
            "Basic " + token,
            token,
            " Bearer " + token};
        for (const auto& authz : malformed)
        {
            EXPECT_EQ(errorOf(f.run("1", authz)), AuthError::MalformedAuthorization) << authz;
        }
    }

    // Once the scheme is right, everything about the token is the verifier's verdict.
    TEST(Middleware, GarbageAfterTheSchemeIsAnInvalidToken)
    {
        Fixture f;
        const std::string token = bearer("001").substr(7);
        const std::vector<std::string> tails {
            "not-a-jwt", "a.b.c", "Bearer " + token, " " + token, token + " ", token + ".x"};
        for (const auto& tail : tails)
        {
            EXPECT_EQ(errorOf(f.run("1", "Bearer " + tail)), AuthError::InvalidToken) << tail;
        }
    }

    // --- keystore --------------------------------------------------------------------------------

    TEST(Middleware, UnknownAgentIsRejected)
    {
        Fixture f;
        EXPECT_EQ(errorOf(f.run("1", bearer("002"))), AuthError::UnknownAgent);
        EXPECT_EQ(errorOf(f.run("1", bearer("4294967295"))), AuthError::UnknownAgent);
    }

    // The profile's HS256 key is exactly the 32 bytes of a 64-hex secret. An agent whose entry holds
    // a short or corrupt key is told MissingKey (re-enroll), never checked against.
    TEST(Middleware, ShortOrCorruptKeysAreUnusable)
    {
        for (const auto* keyHex : {"2b7e151628aed2a6abf7158809cf4f3c",                 // 16 bytes
                                   "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6", // 24 bytes
                                   "not-hex-at-all",
                                   "0030557A9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83A8CDF2173C61FF"}) // uppercase
        {
            const std::string path = writeClientKeysFile("001", keyHex, "any", "_short");
            auto keyStore = std::make_shared<Keystore>(path);
            AuthMiddleware middleware {AuthConfig {}, keyStore};
            // The token itself is fine (signed with a proper 32-byte key); the entry is what's broken.
            const auto result = middleware.authenticate("1", bearer("001", kOtherKeyHex), kPeerIp, kNow);
            EXPECT_EQ(errorOf(result), AuthError::MissingKey) << keyHex;
            std::remove(path.c_str());
        }
    }

    // --- token verdicts --------------------------------------------------------------------------

    TEST(Middleware, WrongKeyIsAnInvalidSignature)
    {
        Fixture f;
        EXPECT_EQ(errorOf(f.run("1", bearer("001", kOtherKeyHex))), AuthError::InvalidSignature);
        // The ascii-key vector: signed with the hex TEXT of the right key.
        EXPECT_EQ(errorOf(f.run("1", "Bearer " + std::string(tv::kAsciiKeyToken), tv::kIat + 5)),
                  AuthError::InvalidSignature);
    }

    TEST(Middleware, TamperedPayloadIsAnInvalidSignature)
    {
        Fixture f;
        std::string authz = bearer("001");
        const auto dot1 = authz.find('.');
        const auto dot2 = authz.find('.', dot1 + 1);
        authz.replace(dot1 + 1, dot2 - dot1 - 1, jwt1::base64UrlEncode(payload("001", "001", kNow + 1)));
        EXPECT_EQ(errorOf(f.run("1", authz)), AuthError::InvalidSignature);
    }

    TEST(Middleware, ExpiredAndFutureTokensAreStale)
    {
        Fixture f;
        const auto token = bearer("001"); // iat = kNow, exp = kNow + 60
        // Default policy: usable from iat - 30 (skew) to exp + 30, inclusive.
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.run("1", token, kNow - 30)));
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(f.run("1", token, kNow + 90)));
        EXPECT_EQ(errorOf(f.run("1", token, kNow - 31)), AuthError::StaleToken);
        EXPECT_EQ(errorOf(f.run("1", token, kNow + 91)), AuthError::StaleToken);
    }

    TEST(Middleware, TheConfiguredTimePolicyIsHonoured)
    {
        Fixture f;
        AuthConfig tight;
        tight.timePolicy = jwt1::TimePolicy {10, 0};
        AuthMiddleware middleware {tight, f.keyStore};
        const auto token = bearer("001");
        EXPECT_TRUE(std::holds_alternative<VerifiedAgent>(middleware.authenticate("1", token, kPeerIp, kNow + 10)));
        EXPECT_EQ(errorOf(middleware.authenticate("1", token, kPeerIp, kNow + 11)), AuthError::StaleToken);
        EXPECT_EQ(errorOf(middleware.authenticate("1", token, kPeerIp, kNow - 1)), AuthError::StaleToken);
    }

    TEST(Middleware, KidSubIssDisagreementIsAnIdentityMismatch)
    {
        Fixture f;
        // kid names the known agent (so the key resolves), sub / iss name another.
        EXPECT_EQ(errorOf(f.run("1", rawBearer(header("001"), payload("002", "001")))), AuthError::IdentityMismatch);
        EXPECT_EQ(errorOf(f.run("1", rawBearer(header("001"), payload("001", "002")))), AuthError::IdentityMismatch);
    }

    TEST(Middleware, AnAudClaimIsAnInvalidToken)
    {
        Fixture f;
        EXPECT_EQ(errorOf(f.run("1", "Bearer " + std::string(tv::kAudToken), tv::kIat + 5)), AuthError::InvalidToken);
    }

    TEST(Middleware, StructuralTimeRuleViolationsAreInvalidTokens)
    {
        Fixture f;
        // A 61 s declared lifetime, correctly signed: rejected as InvalidToken (not Stale).
        std::string p = payload("001", "001");
        p.replace(p.find(std::to_string(kNow + 60)), std::to_string(kNow + 60).size(), std::to_string(kNow + 61));
        EXPECT_EQ(errorOf(f.run("1", rawBearer(header("001"), p))), AuthError::InvalidToken);
    }

    // --- public mapping ----------------------------------------------------------------------------

    TEST(Middleware, EveryCredentialFailureCollapsesToTheSameGeneric401)
    {
        const auto reference = publicErrorFor(AuthError::UnknownAgent);
        EXPECT_EQ(reference.status, 401);
        for (const auto err : {AuthError::MissingAuthorization,
                               AuthError::MalformedAuthorization,
                               AuthError::UnknownAgent,
                               AuthError::MissingKey,
                               AuthError::AddressNotAllowed,
                               AuthError::InvalidToken,
                               AuthError::InvalidSignature,
                               AuthError::StaleToken,
                               AuthError::IdentityMismatch,
                               AuthError::EnrollmentKeyUnavailable})
        {
            const auto pub = publicErrorFor(err);
            EXPECT_EQ(pub.status, 401) << toString(err);
            EXPECT_STREQ(pub.message, reference.message) << toString(err);
        }
        EXPECT_EQ(publicErrorFor(AuthError::MissingProtocolVersion).status, 400);
        EXPECT_EQ(publicErrorFor(AuthError::UnsupportedProtocolVersion).status, 400);
    }

    TEST(AuthErrorToString, CoversEveryEnumerator)
    {
        const AuthError all[] = {AuthError::None,
                                 AuthError::MissingProtocolVersion,
                                 AuthError::UnsupportedProtocolVersion,
                                 AuthError::MissingAuthorization,
                                 AuthError::MalformedAuthorization,
                                 AuthError::UnknownAgent,
                                 AuthError::MissingKey,
                                 AuthError::AddressNotAllowed,
                                 AuthError::InvalidToken,
                                 AuthError::InvalidSignature,
                                 AuthError::StaleToken,
                                 AuthError::IdentityMismatch,
                                 AuthError::PayloadAgentMismatch,
                                 AuthError::BodyTooLarge,
                                 AuthError::UnsupportedContentEncoding,
                                 AuthError::MalformedContentEncoding,
                                 AuthError::EnrollmentKeyUnavailable};

        std::set<std::string> seen;
        for (const auto err : all)
        {
            const char* tag = toString(err);
            ASSERT_NE(tag, nullptr);
            EXPECT_STRNE(tag, "unknown") << "missing switch case for " << static_cast<int>(err);
            EXPECT_TRUE(seen.insert(tag).second) << "duplicate tag '" << tag << "'";
        }
        EXPECT_EQ(seen.size(), std::size(all));
    }

} // namespace
