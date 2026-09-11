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
// Then the `kid` forms of issue #38993 (peekKid/verifyWithKid) and precheckMessage(), the
// key-independent filter remoted applies to a re-enrollment bearer it cannot verify.

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

// ---------------------------------------------------------------------------- `kid` forms (issue #38993)
// The shared-key surface above is untouched: a `kid` is still InvalidToken for verify(). The two
// `kid` forms -- enrollment token id (22 base64url chars) and canonical agent id -- are classified
// by shape with peekKid() and verified with verifyWithKid() against the key the caller resolved.

namespace
{
    namespace tt = jwt_profile::v1::test_vectors::enroll_token;
    using KidKind = JwtEnrollTokenVerifier::KidKind;

    SecureBytes fromHex(std::string_view hex)
    {
        SecureBytes out(hex.size() / 2);
        for (std::size_t i = 0; i < out.size(); ++i)
        {
            out.data()[i] = static_cast<std::uint8_t>(std::stoul(std::string {hex.substr(2 * i, 2)}, nullptr, 16));
        }
        return out;
    }

    SecureBytes tokenKey()
    {
        auto key = enroll::deriveEnrollTokenKey(fromHex(tt::kSecretHex));
        EXPECT_TRUE(key.has_value());
        return std::move(*key);
    }

    SecureBytes reenrollKey()
    {
        auto key = enroll::deriveReenrollKey(fromHex(tt::kReenrollSecretHex));
        EXPECT_TRUE(key.has_value());
        return std::move(*key);
    }

    VerifyError verifyKidAt(std::string_view token,
                            std::string_view kid,
                            const SecureBytes& key,
                            std::int64_t now = kNow,
                            const TimePolicy& policy = TimePolicy {})
    {
        return JwtEnrollTokenVerifier::verifyWithKid(token, kid, key, policy, at(now));
    }
} // namespace

TEST(EnrollSigner, ReproducesTheTokenKidVectorByteForByte)
{
    const auto token = JwtEnrollTokenSigner::signWithKid(tokenKey(), at(tv::kIat), tt::kIdB64Url, tv::kJti);
    ASSERT_TRUE(token.has_value());
    EXPECT_EQ(*token, tt::kTokenKidJwt);
    EXPECT_EQ(token->size(), 251U);
    EXPECT_EQ(JwtEnrollTokenSigner::headerJson(tt::kIdB64Url), tt::kTokenKidHeaderJson);
}

TEST(EnrollSigner, ReproducesTheAgentKidVectorAndRefusesOtherKids)
{
    const auto token = JwtEnrollTokenSigner::signWithKid(reenrollKey(), at(tv::kIat), tt::kAgentKid, tv::kJti);
    ASSERT_TRUE(token.has_value());
    EXPECT_EQ(*token, tt::kAgentKidJwt);
    EXPECT_EQ(token->size(), 226U);
    EXPECT_EQ(JwtEnrollTokenSigner::headerJson(tt::kAgentKid), tt::kAgentKidHeaderJson);

    // Neither shape: a non-canonical agent id, 21 chars, padding, non-zero trailing bits, empty.
    const auto key = tokenKey();
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), "1", tv::kJti).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), "AAECAwQFBgcICQoLDA0OD", tv::kJti).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), "AAECAwQFBgcICQoLDA0ODw==", tv::kJti).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), "AAECAwQFBgcICQoLDA0ODx", tv::kJti).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), "", tv::kJti).has_value());
    // The shared-key rules still apply underneath.
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(SecureBytes(16), at(kNow), tt::kIdB64Url).has_value());
    EXPECT_FALSE(JwtEnrollTokenSigner::signWithKid(key, at(kNow), tt::kIdB64Url, "short").has_value());
}

TEST(EnrollVerifier, PeekKidTellsTokenAgentOrNone)
{
    const auto none = JwtEnrollTokenVerifier::peekKid(tv::kToken);
    ASSERT_TRUE(none.has_value());
    EXPECT_EQ(none->kind, KidKind::None);
    EXPECT_TRUE(none->text.empty());

    const auto token = JwtEnrollTokenVerifier::peekKid(tt::kTokenKidJwt);
    ASSERT_TRUE(token.has_value());
    EXPECT_EQ(token->kind, KidKind::Token);
    EXPECT_EQ(token->text, tt::kIdB64Url);

    const auto agent = JwtEnrollTokenVerifier::peekKid(tt::kAgentKidJwt);
    ASSERT_TRUE(agent.has_value());
    EXPECT_EQ(agent->kind, KidKind::Agent);
    EXPECT_EQ(agent->text, tt::kAgentKid);

    // Pre-signature: the password-signed kid header of the negative vector still peeks as Agent
    // "001" -- peekKid() only names the candidate key, verifyWithKid() decides.
    const auto unsigned_ = JwtEnrollTokenVerifier::peekKid(tv::kKidHeaderToken);
    ASSERT_TRUE(unsigned_.has_value());
    EXPECT_EQ(unsigned_->kind, KidKind::Agent);

    // Not this profile at all: a kid of neither shape, an extra member, another typ, garbage.
    EXPECT_FALSE(
        JwtEnrollTokenVerifier::peekKid(mint(R"({"alg":"HS256","kid":"1","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson))
            .has_value());
    EXPECT_FALSE(
        JwtEnrollTokenVerifier::peekKid(
            mint(R"({"alg":"HS256","kid":"AAECAwQFBgcICQoLDA0ODw==","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson))
            .has_value());
    EXPECT_FALSE(JwtEnrollTokenVerifier::peekKid(
                     mint(R"({"alg":"HS256","typ":"wazuh-enroll+jwt","cty":"JWT"})", tv::kPayloadJson))
                     .has_value());
    EXPECT_FALSE(
        JwtEnrollTokenVerifier::peekKid(
            mint(R"({"alg":"HS256","kid":"AAECAwQFBgcICQoLDA0ODw","typ":"wazuh-agent+jwt"})", tv::kPayloadJson))
            .has_value());
    EXPECT_FALSE(JwtEnrollTokenVerifier::peekKid("").has_value());
    EXPECT_FALSE(JwtEnrollTokenVerifier::peekKid("a.b").has_value());
}

TEST(EnrollVerifier, VerifyWithKidAcceptsItsVectorAndRejectsTheRest)
{
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kIdB64Url, tokenKey()), VerifyError::None);
    EXPECT_EQ(verifyKidAt(tt::kAgentKidJwt, tt::kAgentKid, reenrollKey()), VerifyError::None);

    // Right header, wrong key (the shared password key): a signature failure, nothing else leaks.
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kIdB64Url, vectorKey()), VerifyError::InvalidSignature);
    // Token names another key than the one resolved: rejected before any HMAC.
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kAgentKid, tokenKey()), VerifyError::InvalidToken);
    // A shared-key token (no kid) never verifies through the kid path.
    EXPECT_EQ(verifyKidAt(tv::kToken, tt::kIdB64Url, tokenKey()), VerifyError::InvalidToken);
    // A kid of neither shape is rejected even if the caller asks for it verbatim.
    EXPECT_EQ(
        verifyKidAt(mint(R"({"alg":"HS256","kid":"1","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson), "1", vectorKey()),
        VerifyError::InvalidToken);
    // Time rules are the shared ones (60 s lifetime + 30 s skew).
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kIdB64Url, tokenKey(), tv::kIat + 90), VerifyError::None);
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kIdB64Url, tokenKey(), tv::kIat + 91), VerifyError::StaleToken);
    // Fresh tokens of both forms round-trip.
    const auto fresh = JwtEnrollTokenSigner::signWithKid(tokenKey(), at(kNow), tt::kIdB64Url);
    ASSERT_TRUE(fresh.has_value());
    EXPECT_EQ(verifyKidAt(*fresh, tt::kIdB64Url, tokenKey()), VerifyError::None);
}

TEST(EnrollVerifier, SharedKeyVerifierStillRejectsAnyKid)
{
    EXPECT_EQ(verifyAt(tv::kKidHeaderToken), VerifyError::InvalidToken);
    EXPECT_EQ(JwtEnrollTokenVerifier::verify(tt::kTokenKidJwt, tokenKey(), TimePolicy {}, at(kNow)),
              VerifyError::InvalidToken);
    EXPECT_EQ(JwtEnrollTokenVerifier::verify(tt::kAgentKidJwt, reenrollKey(), TimePolicy {}, at(kNow)),
              VerifyError::InvalidToken);
}

TEST(EnrollVerifier, KidFormsAreDisjointAndCrossKeysFail)
{
    // Shapes never collide: no canonical 22-char base64url string is a digit string, and no
    // canonical agent id has 22 chars.
    EXPECT_TRUE(JwtEnrollTokenSigner::isValidKid(tt::kIdB64Url));
    EXPECT_TRUE(JwtEnrollTokenSigner::isValidKid("001"));
    EXPECT_TRUE(JwtEnrollTokenSigner::isValidKid("4294967295"));
    EXPECT_FALSE(JwtEnrollTokenSigner::isValidKid("0000000000000000000000")); // 22 digits: neither shape
    EXPECT_FALSE(JwtEnrollTokenSigner::isValidKid("01"));
    EXPECT_FALSE(JwtEnrollTokenSigner::isValidKid("AAECAwQFBgcICQoLDA0ODwA")); // 23 chars
    // A token of one form verified with the other form's key is a plain signature failure.
    EXPECT_EQ(verifyKidAt(tt::kAgentKidJwt, tt::kAgentKid, tokenKey()), VerifyError::InvalidSignature);
    EXPECT_EQ(verifyKidAt(tt::kTokenKidJwt, tt::kIdB64Url, reenrollKey()), VerifyError::InvalidSignature);
}

// ------------------------------------------------------- precheckMessage (issue #38993 review)
// The key-independent half of verifyWithKid(): everything except the HMAC, for the caller that
// cannot hold the key (remoted forwarding a re-enrollment bearer to the master). Two properties
// matter and both are pinned here: (1) it never accepts a message verifyWithKid() would refuse for
// a key-independent reason, and it answers with the SAME VerifyError, so a pre-filtering caller
// cannot be told apart from the key holder; (2) it is NOT verification -- a message with any
// signature at all passes as long as its claims hold.

namespace
{
    VerifyError precheckAt(std::string_view token,
                           std::string_view kid,
                           std::int64_t now = kNow,
                           const TimePolicy& policy = TimePolicy {})
    {
        return JwtEnrollTokenVerifier::precheckMessage(token, kid, policy, at(now));
    }

    // The same message with the signature segment replaced by 32 zero bytes: canonical grammar, a
    // MAC no key produced.
    std::string withGarbageSignature(std::string_view token)
    {
        const std::string text {token};
        return text.substr(0, text.rfind('.') + 1) + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
} // namespace

TEST(EnrollPrecheck, AcceptsAWellFormedMessageWhateverTheSignature)
{
    // The frozen agent-kid vector, and the same message signed with nothing that verifies: both
    // pass, because the signature is exactly what this function does not look at.
    EXPECT_EQ(precheckAt(tt::kAgentKidJwt, tt::kAgentKid), VerifyError::None);
    EXPECT_EQ(precheckAt(withGarbageSignature(tt::kAgentKidJwt), tt::kAgentKid), VerifyError::None);
    // ...while the key holder still refuses the second one. Precheck is a filter, not a verdict.
    EXPECT_EQ(verifyKidAt(withGarbageSignature(tt::kAgentKidJwt), tt::kAgentKid, reenrollKey()),
              VerifyError::InvalidSignature);
    // The enrollment-token form goes through the same door (nothing here is agent-specific).
    EXPECT_EQ(precheckAt(tt::kTokenKidJwt, tt::kIdB64Url), VerifyError::None);
}

TEST(EnrollPrecheck, RejectsTheReplayableMessageOfTheReviewFinding)
{
    // The 130 bytes of the finding: a valid {alg, kid: "001", typ} header, a payload that is
    // canonical base64url of ONE byte -- not JSON at all -- and 43 canonical signature chars. It
    // satisfies splitCompact() and peekKid(), which is why it used to reach authd and, on a worker,
    // the master; the claim set is what stops it now, at zero cost.
    constexpr std::string_view replay = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.AA."
                                        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const auto peeked = JwtEnrollTokenVerifier::peekKid(replay);
    ASSERT_TRUE(peeked.has_value()); // the shape still classifies: that was never the leak
    EXPECT_EQ(peeked->kind, KidKind::Agent);
    EXPECT_EQ(precheckAt(replay, "001"), VerifyError::InvalidToken);
}

TEST(EnrollPrecheck, RejectsEveryClaimSetTheKeyHolderWouldRejectAndAnswersAlike)
{
    // Each case: what precheckMessage() says without a key, and what verifyWithKid() says holding
    // the right one. They must agree value for value -- that is what makes the pre-filter invisible.
    const auto expectAgreement = [](const std::string& message, VerifyError expected, std::int64_t now = kNow)
    {
        EXPECT_EQ(precheckAt(message, tt::kAgentKid, now), expected);
        EXPECT_EQ(verifyKidAt(message, tt::kAgentKid, reenrollKey(), now), expected);
    };
    // A signature the reenroll key produces, so verifyWithKid() gets past the HMAC and lands on the
    // very claim rule under test.
    const auto signedWithReenrollKey = [](std::string_view headerJson, std::string_view payloadJson)
    {
        std::string signingInput = base64UrlEncode(headerJson) + "." + base64UrlEncode(payloadJson);
        HmacSha256Digest mac {};
        EXPECT_TRUE(hmacSha256(reenrollKey(), signingInput, mac));
        return signingInput + "." + base64UrlEncode(mac.data(), mac.size());
    };
    const std::string header {tt::kAgentKidHeaderJson};

    // Not JSON, an empty object, a missing claim, an extra claim, a claim of the wrong type.
    expectAgreement(signedWithReenrollKey(header, "not json"), VerifyError::InvalidToken);
    expectAgreement(signedWithReenrollKey(header, "{}"), VerifyError::InvalidToken);
    expectAgreement(signedWithReenrollKey(header, R"({"exp":1700000060,"iat":1700000000,"nbf":1700000000})"),
                    VerifyError::InvalidToken);
    expectAgreement(
        signedWithReenrollKey(
            header,
            R"({"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000,"sub":"001"})"),
        VerifyError::InvalidToken);
    expectAgreement(
        signedWithReenrollKey(
            header, R"({"exp":"1700000060","iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000})"),
        VerifyError::InvalidToken);
    // A jti that is not 16 canonical base64url bytes.
    expectAgreement(signedWithReenrollKey(header, payload(tv::kIat, tv::kIat, tv::kExp, "AAECAwQFBgcICQoLDA0OD")),
                    VerifyError::InvalidToken);
    // The structural time rules: nbf != iat, exp <= iat, a lifetime over the profile's 60 s.
    expectAgreement(signedWithReenrollKey(header, payload(tv::kIat, tv::kIat + 1, tv::kExp)),
                    VerifyError::InvalidToken);
    expectAgreement(signedWithReenrollKey(header, payload(tv::kIat, tv::kIat, tv::kIat)), VerifyError::InvalidToken);
    expectAgreement(signedWithReenrollKey(header, payload(tv::kIat, tv::kIat, tv::kIat + 61)),
                    VerifyError::InvalidToken);
    // The clock-relative ones: older than the accepted age, and issued beyond the skew ahead.
    expectAgreement(std::string {tt::kAgentKidJwt}, VerifyError::None, tv::kIat + 90);
    expectAgreement(std::string {tt::kAgentKidJwt}, VerifyError::StaleToken, tv::kIat + 91);
    expectAgreement(signedWithReenrollKey(header, payload(kNow + 31, kNow + 31, kNow + 91)), VerifyError::StaleToken);
}

TEST(EnrollPrecheck, RejectsAnythingThatDoesNotNameThisKid)
{
    // Another `kid` than the caller resolved, the shared-key (kid-less) form, a `kid` of neither
    // shape, another profile's typ, and plain garbage: all InvalidToken, before the payload is read.
    EXPECT_EQ(precheckAt(tt::kAgentKidJwt, "002"), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(tt::kAgentKidJwt, tt::kIdB64Url), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(tt::kTokenKidJwt, tt::kAgentKid), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(tv::kToken, tt::kAgentKid), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(mint(R"({"alg":"HS256","kid":"1","typ":"wazuh-enroll+jwt"})", tv::kPayloadJson), "1"),
              VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(mint(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})", tv::kPayloadJson), "001"),
              VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(agent_tv::kToken, "001"), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt("", "001"), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt("a.b", "001"), VerifyError::InvalidToken);
    EXPECT_EQ(precheckAt(std::string(kMaxTokenBytes + 1, 'A'), "001"), VerifyError::InvalidToken);
}

TEST(EnrollPrecheck, ReadsTheSameTimePolicyTheVerifierDoes)
{
    // A wider skew (remoted.jwt_clock_skew) makes the same message acceptable again, in both
    // functions alike: the pre-filter cannot be stricter than the verifier the operator configured.
    const auto wide = TimePolicy::tryMake(kDefaultAgeSec, 120);
    ASSERT_TRUE(wide.has_value());
    EXPECT_EQ(precheckAt(tt::kAgentKidJwt, tt::kAgentKid, tv::kIat + 91), VerifyError::StaleToken);
    EXPECT_EQ(precheckAt(tt::kAgentKidJwt, tt::kAgentKid, tv::kIat + 91, *wide), VerifyError::None);
    EXPECT_EQ(verifyKidAt(tt::kAgentKidJwt, tt::kAgentKid, reenrollKey(), tv::kIat + 91, *wide), VerifyError::None);
}
