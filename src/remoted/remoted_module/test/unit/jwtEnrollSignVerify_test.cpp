/*
 * Wazuh remoted module - wazuh-enroll+jwt signer/verifier tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Frozen vector + the negative matrix of the closed `wazuh-enroll+jwt` profile (issue #38582,
// jwt/jwtEnrollProfileV1.hpp). The grammar/time core is shared with `wazuh-agent+jwt`
// (jwtVerify_test.cpp covers it exhaustively); here the enroll-specific surface: exact 2-field
// header, exact 4-claim payload, no kid, cross-profile rejection in both directions, HKDF key.

#include <gtest/gtest.h>

#include "jwt/base64Url.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/jwtEnrollTokenVerifier.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/jwtRequestTokenVerifier.hpp"
#include "jwt/testVectors.hpp"

#include <chrono>
#include <set>
#include <string>

using namespace jwt_profile::v1;
using jwt_profile::v1::enroll::JwtEnrollTokenSigner;
using jwt_profile::v1::enroll::JwtEnrollTokenVerifier;
namespace tv = jwt_profile::v1::test_vectors::enroll;
namespace agent_tv = jwt_profile::v1::test_vectors;

namespace
{
    std::chrono::system_clock::time_point at(std::int64_t epoch)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epoch}};
    }

    SecureBytes vectorKey()
    {
        auto key = enroll::deriveEnrollKey(tv::kPassword);
        EXPECT_TRUE(key.has_value());
        return std::move(*key);
    }

    constexpr std::int64_t kNow = tv::kIat + 10;

    VerifyError verifyAt(std::string_view token, std::int64_t now = kNow, const TimePolicy& policy = TimePolicy {})
    {
        return JwtEnrollTokenVerifier::verify(token, vectorKey(), policy, at(now));
    }

    // Mints `<b64(header)>.<b64(payload)>.<hs256>` for arbitrary JSON texts -- the only way to
    // produce the structurally wrong tokens the strict verifier must reject.
    std::string mint(std::string_view headerJson, std::string_view payloadJson)
    {
        std::string signingInput = base64UrlEncode(headerJson) + "." + base64UrlEncode(payloadJson);
        HmacSha256Digest mac {};
        EXPECT_TRUE(hmacSha256(vectorKey(), signingInput, mac));
        return signingInput + "." + base64UrlEncode(mac.data(), mac.size());
    }

    std::string payload(std::int64_t iat, std::int64_t nbf, std::int64_t exp, std::string_view jti = tv::kJti)
    {
        return R"({"exp":)" + std::to_string(exp) + R"(,"iat":)" + std::to_string(iat) + R"(,"jti":")" +
               std::string {jti} + R"(","nbf":)" + std::to_string(nbf) + "}";
    }
} // namespace

// ---------------------------------------------------------------------------- signer

TEST(EnrollSigner, ReproducesTheFrozenVectorByteForByte)
{
    EXPECT_EQ(JwtEnrollTokenSigner::headerJson(), tv::kHeaderJson);
    EXPECT_EQ(JwtEnrollTokenSigner::payloadJson(tv::kIat, tv::kJti), tv::kPayloadJson);
    const auto token = JwtEnrollTokenSigner::sign(vectorKey(), at(tv::kIat), tv::kJti);
    ASSERT_TRUE(token.has_value());
    EXPECT_EQ(*token, tv::kToken);
    EXPECT_EQ(token->substr(0, tv::kSigningInput.size()), tv::kSigningInput);
    EXPECT_EQ(token->substr(tv::kSigningInput.size() + 1), tv::kSignatureB64Url);
}

TEST(EnrollSigner, FreshTokensVerifyAndCarryDistinctJtis)
{
    const auto key = vectorKey();
    std::set<std::string> tokens;
    for (int i = 0; i < 50; ++i)
    {
        const auto token = JwtEnrollTokenSigner::sign(key, at(kNow));
        ASSERT_TRUE(token.has_value());
        EXPECT_EQ(JwtEnrollTokenVerifier::verify(*token, key, TimePolicy {}, at(kNow)), VerifyError::None);
        tokens.insert(*token);
    }
    EXPECT_EQ(tokens.size(), 50U);
}

TEST(EnrollSigner, RefusesAWrongSizedKeyAndANonCanonicalJti)
{
    EXPECT_FALSE(JwtEnrollTokenSigner::sign(SecureBytes(16), at(kNow)).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::sign(vectorKey(), at(kNow), "AAECAwQFBgcICQoLDA0OD=").has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::sign(vectorKey(), at(kNow), "short").has_value());
}

// ---------------------------------------------------------------------------- verifier

TEST(EnrollVerifier, AcceptsTheFrozenVector)
{
    EXPECT_EQ(verifyAt(tv::kToken), VerifyError::None);
}

TEST(EnrollVerifier, WrongPasswordIsAnInvalidSignature)
{
    EXPECT_EQ(verifyAt(tv::kWrongPasswordToken), VerifyError::InvalidSignature);
}

TEST(EnrollVerifier, TamperedSignatureAndPayloadAreInvalidSignatures)
{
    // Flip a character in the middle of the signature segment (the LAST char of a canonical
    // base64url segment carries padding bits, so flipping it is a grammar error, not a bad MAC).
    std::string token {tv::kToken};
    const auto sigStart = token.rfind('.') + 1;
    token[sigStart + 5] = token[sigStart + 5] == 'A' ? 'B' : 'A';
    EXPECT_EQ(verifyAt(token), VerifyError::InvalidSignature);

    std::string tampered {tv::kToken};
    const auto dot = tampered.find('.');
    tampered[dot + 5] = tampered[dot + 5] == 'A' ? 'B' : 'A'; // inside the payload segment
    EXPECT_EQ(verifyAt(tampered), VerifyError::InvalidSignature);
}

TEST(EnrollVerifier, HeaderMustBeExactlyAlgAndTyp)
{
    EXPECT_EQ(verifyAt(tv::kKidHeaderToken), VerifyError::InvalidToken); // extra kid, valid signature
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS256"})", tv::kPayloadJson)), VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(R"({"alg":"none","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson)),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS384","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson)),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS256","typ":"wazuh-agent+jwt"})", tv::kPayloadJson)),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS256","typ":"wazuh-enroll+jwt","typ":"x"})", tv::kPayloadJson)),
              VerifyError::InvalidToken); // duplicate member
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS256","typ":"wazuh-enroll+jwt","cty":"JWT"})", tv::kPayloadJson)),
              VerifyError::InvalidToken);
}

TEST(EnrollVerifier, RejectsNonAsciiTextInEitherSegment)
{
    // The profile text is ASCII; a truncated multi-byte lead at the end of a decoded segment is the
    // ASAN regression (bounded pre-parse), a complete UTF-8 sequence is simply not the profile.
    EXPECT_EQ(verifyAt(mint(R"({"alg":"HS256","typ":"wazuh-enroll+jwt)"
                            "\xF0",
                            tv::kPayloadJson)),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, std::string(tv::kPayloadJson).substr(0, 20) + "\xE2\x82")),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kExp, "AAECAwQFBgcICQoLDA0OD\xC3\xA9"))),
              VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(mint("\xEF\xBB\xBF" + std::string(tv::kHeaderJson), tv::kPayloadJson)),
              VerifyError::InvalidToken);
}

TEST(EnrollVerifier, ClaimsMustBeExactlyExpIatJtiNbf)
{
    const auto valid = payload(tv::kIat, tv::kIat, tv::kExp);
    ASSERT_EQ(verifyAt(mint(tv::kHeaderJson, valid)), VerifyError::None);

    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, R"({"exp":1700000060,"iat":1700000000,"nbf":1700000000})")),
              VerifyError::InvalidToken); // missing jti
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, R"({"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw"})")),
              VerifyError::InvalidToken); // missing nbf
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, agent_tv::kPayloadJson)),
              VerifyError::InvalidToken); // agent claims (iss/sub) under an enroll header
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, R"({"aud":"wazuh-manager",)" + valid.substr(1))),
              VerifyError::InvalidToken); // extra aud
    EXPECT_EQ(
        verifyAt(mint(tv::kHeaderJson,
                      R"({"exp":1700000060,"iat":"1700000000","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000})")),
        VerifyError::InvalidToken); // iat as string
    EXPECT_EQ(
        verifyAt(mint(
            tv::kHeaderJson,
            R"({"exp":1700000060,"iat":1700000000,"iat":1700000001,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000})")),
        VerifyError::InvalidToken); // duplicate iat
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kExp, "AAECAwQFBgcICQoLDA0OD"))),
              VerifyError::InvalidToken); // jti of 21 chars
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kExp, "AAECAwQFBgcICQoLDA0ODx"))),
              VerifyError::InvalidToken); // non-canonical trailing bits
}

TEST(EnrollVerifier, StructuralTimeRulesAreProfileConstants)
{
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat + 1, tv::kExp))),
              VerifyError::InvalidToken); // nbf != iat
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kIat + 61))),
              VerifyError::InvalidToken); // > 60 s
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kIat))),
              VerifyError::InvalidToken); // exp == iat
    EXPECT_EQ(verifyAt(mint(tv::kHeaderJson, payload(tv::kIat, tv::kIat, tv::kIat + 30))),
              VerifyError::None); // shorter is fine
}

TEST(EnrollVerifier, ClockRulesFollowTheTimePolicy)
{
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat + 90), VerifyError::None);       // 60 + 30 skew
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat + 91), VerifyError::StaleToken); // expired
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat - 30), VerifyError::None);       // future within skew
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat - 31), VerifyError::StaleToken); // issued in the future
    const TimePolicy narrow {10, 0};
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat + 10, narrow), VerifyError::None);
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat + 11, narrow), VerifyError::StaleToken);
    EXPECT_EQ(verifyAt(tv::kToken, tv::kIat - 1, narrow), VerifyError::StaleToken);
}

TEST(EnrollVerifier, CompactGrammarIsEnforcedBeforeDecoding)
{
    const std::string token {tv::kToken};
    EXPECT_EQ(verifyAt(""), VerifyError::InvalidToken);
    EXPECT_EQ(verifyAt(token.substr(0, token.rfind('.'))), VerifyError::InvalidToken); // 2 segments
    EXPECT_EQ(verifyAt(token + ".x"), VerifyError::InvalidToken);                      // 4 segments
    EXPECT_EQ(verifyAt(token + "="), VerifyError::InvalidToken);                       // padding
    EXPECT_EQ(verifyAt(token + std::string(4096, 'A')), VerifyError::InvalidToken);    // over the cap
    std::string plusAlphabet {tv::kToken};
    plusAlphabet[plusAlphabet.find('-')] = '+'; // standard base64 alphabet
    EXPECT_EQ(verifyAt(plusAlphabet), VerifyError::InvalidToken);
}

TEST(EnrollVerifier, ProfilesNeverCrossOver)
{
    // Same 32-byte key on both sides: the agent token fails here on typ, and the enroll token
    // fails on the agent verifier on its header set -- before any signature is considered.
    const auto key = vectorKey();
    const auto agentToken = JwtRequestTokenSigner::sign(*CanonicalAgentId::parse("001"), key, at(kNow), agent_tv::kJti);
    ASSERT_TRUE(agentToken.has_value());
    EXPECT_EQ(JwtEnrollTokenVerifier::verify(*agentToken, key, TimePolicy {}, at(kNow)), VerifyError::InvalidToken);

    const auto enrollToken = JwtEnrollTokenSigner::sign(key, at(kNow));
    ASSERT_TRUE(enrollToken.has_value());
    EXPECT_FALSE(JwtRequestTokenVerifier::verify(*enrollToken, key, TimePolicy {}, at(kNow)).ok());
    EXPECT_FALSE(JwtRequestTokenVerifier::peekKid(*enrollToken).has_value());
}
