/*
 * Wazuh shared modules utils - JWT agent authentication profile - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// JwtRequestTokenVerifier: the frozen vector and Signer output are accepted; every row of the
// profile's negative matrix (doc spec §11.2) is rejected with the right VerifyError; peekKid()
// exposes only the header-derived kid and never depends on the signature; a short fuzz pass shows
// nothing throws or crashes on hostile input.
#include <gtest/gtest.h>

#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/jwtRequestTokenVerifier.hpp"
#include "jwt/testVectors.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <random>
#include <string>
#include <vector>

using namespace jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors;

namespace
{
    std::chrono::system_clock::time_point at(std::int64_t epoch)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epoch}};
    }

    SecureBytes vectorKey()
    {
        auto key = JwtKeyDecoder::decode(tv::kKeyHex);
        EXPECT_TRUE(key);
        return std::move(*key);
    }

    constexpr std::int64_t kNow = tv::kIat + 10;

    std::vector<std::string> split(std::string_view token)
    {
        std::vector<std::string> out;
        std::size_t start = 0;
        for (;;)
        {
            const auto dot = token.find('.', start);
            out.emplace_back(token.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start));
            if (dot == std::string_view::npos)
            {
                return out;
            }
            start = dot + 1;
        }
    }

    /// Compact JWS from arbitrary header/payload text, signed with `key` (the library's own HMAC:
    /// jwtHmacSha256_test.cpp proves it against RFC 4231 and the vector).
    std::string signedToken(std::string_view headerJson, std::string_view payloadJson, const SecureBytes& key)
    {
        std::string signingInput = base64UrlEncode(headerJson) + "." + base64UrlEncode(payloadJson);
        HmacSha256Digest mac {};
        EXPECT_TRUE(hmacSha256(key, signingInput, mac));
        return signingInput + "." + base64UrlEncode(mac.data(), mac.size());
    }

    std::string replaceOnce(std::string text, std::string_view from, std::string_view to)
    {
        const auto pos = text.find(from);
        EXPECT_NE(pos, std::string::npos) << "fixture does not contain: " << from;
        if (pos != std::string::npos)
        {
            text.replace(pos, from.size(), to);
        }
        return text;
    }

    /// Mutates the payload text of the vector and re-signs with the correct key.
    std::string withPayload(std::string_view payloadJson, const SecureBytes& key)
    {
        return signedToken(tv::kHeaderJson, payloadJson, key);
    }
    std::string withHeader(std::string_view headerJson, const SecureBytes& key)
    {
        return signedToken(headerJson, tv::kPayloadJson, key);
    }
    std::string payloadReplacing(std::string_view from, std::string_view to, const SecureBytes& key)
    {
        return withPayload(replaceOnce(std::string(tv::kPayloadJson), from, to), key);
    }
    std::string headerReplacing(std::string_view from, std::string_view to, const SecureBytes& key)
    {
        return withHeader(replaceOnce(std::string(tv::kHeaderJson), from, to), key);
    }

    VerifyResult run(std::string_view token,
                     const SecureBytes& key,
                     std::int64_t now = kNow,
                     const TimePolicy& policy = TimePolicy {})
    {
        return JwtRequestTokenVerifier::verify(token, key, policy, at(now));
    }

    const char* name(VerifyError e)
    {
        switch (e)
        {
            case VerifyError::None: return "None";
            case VerifyError::InvalidToken: return "InvalidToken";
            case VerifyError::InvalidSignature: return "InvalidSignature";
            case VerifyError::StaleToken: return "StaleToken";
            case VerifyError::IdentityMismatch: return "IdentityMismatch";
        }
        return "?";
    }

#define EXPECT_REJECTED(result, expectedError, why)                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto r_ = (result);                                                                                      \
        EXPECT_FALSE(r_.ok()) << why;                                                                                  \
        EXPECT_STREQ(name(r_.error()), name(expectedError)) << why;                                                    \
    } while (0)

    /// Sets the lowest unused bit of a segment's last char so the text is no longer canonical.
    std::string dirtyLastChar(std::string segment)
    {
        static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        EXPECT_NE(segment.size() % 4, 0u) << "segment has no unused trailing bits";
        const int sextet = base64UrlSextet(segment.back());
        segment.back() = kAlphabet[sextet | 1];
        return segment;
    }
} // namespace

// --- positives ------------------------------------------------------------------------------------
TEST(JwtVerify, AcceptsTheFrozenVector)
{
    const auto key = vectorKey();
    const auto result = run(tv::kToken, key);
    ASSERT_TRUE(result.ok()) << name(result.error());
    EXPECT_EQ(result.agent().text(), "001");
    EXPECT_EQ(result.error(), VerifyError::None);
}

TEST(JwtVerify, AcceptsSignerOutputRoundTrip)
{
    const auto key = vectorKey();
    const auto agent = *CanonicalAgentId::parse("42");
    const auto token = JwtRequestTokenSigner::sign(agent, key, at(1'800'000'000));
    ASSERT_TRUE(token);
    const auto result = run(*token, key, 1'800'000'000);
    ASSERT_TRUE(result.ok()) << name(result.error());
    EXPECT_EQ(result.agent().text(), "042");
    EXPECT_EQ(result.agent(), agent);
}

TEST(JwtVerify, AcceptsWideAgentIds)
{
    const auto key = vectorKey();
    const auto agent = *CanonicalAgentId::parse("4294967295");
    const auto token = JwtRequestTokenSigner::sign(agent, key, at(kNow));
    ASSERT_TRUE(token);
    const auto result = run(*token, key);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.agent().text(), "4294967295");
}

TEST(JwtVerify, TimePolicyBoundsAreInclusive)
{
    const auto key = vectorKey();
    // Default policy (maxAge 60, skew 30): iat may be up to 30 s in the future...
    EXPECT_TRUE(run(tv::kToken, key, tv::kIat - 30).ok());
    EXPECT_REJECTED(run(tv::kToken, key, tv::kIat - 31), VerifyError::StaleToken, "iat 31 s in the future");
    // ...and the token is usable until exp + skew == iat + 90 (age 90 == maxAge + skew).
    EXPECT_TRUE(run(tv::kToken, key, tv::kExp + 30).ok());
    EXPECT_REJECTED(run(tv::kToken, key, tv::kExp + 31), VerifyError::StaleToken, "expired beyond skew");

    // Lowered policy (maxAge 10, skew 0): a 60 s token is only accepted while now - iat <= 10.
    const TimePolicy tight {10, 0};
    EXPECT_TRUE(run(tv::kToken, key, tv::kIat, tight).ok());
    EXPECT_TRUE(run(tv::kToken, key, tv::kIat + 10, tight).ok());
    EXPECT_REJECTED(run(tv::kToken, key, tv::kIat + 11, tight), VerifyError::StaleToken, "older than maxAge");
    EXPECT_REJECTED(run(tv::kToken, key, tv::kIat - 1, tight), VerifyError::StaleToken, "future with skew 0");

    // Skew alone widens both ends without touching the declared lifetime.
    const TimePolicy skewOnly {60, 5};
    EXPECT_TRUE(run(tv::kToken, key, tv::kIat - 5, skewOnly).ok());
    EXPECT_REJECTED(run(tv::kToken, key, tv::kIat - 6, skewOnly), VerifyError::StaleToken, "future beyond 5 s");
    EXPECT_TRUE(run(tv::kToken, key, tv::kExp + 5, skewOnly).ok());
    EXPECT_REJECTED(run(tv::kToken, key, tv::kExp + 6, skewOnly), VerifyError::StaleToken, "expired beyond 5 s");
}

TEST(JwtVerify, PeekKidReturnsTheHeaderAgentWithoutTouchingTheSignature)
{
    const auto parts = split(tv::kToken);
    ASSERT_EQ(parts.size(), 3u);
    const auto kid = JwtRequestTokenVerifier::peekKid(tv::kToken);
    ASSERT_TRUE(kid);
    EXPECT_EQ(kid->text(), "001");

    // Garbage (but grammatically valid) signature and a tampered payload still yield the kid: the
    // peek authenticates nothing, it only names the candidate key.
    EXPECT_TRUE(JwtRequestTokenVerifier::peekKid(parts[0] + "." + parts[1] + "." + std::string(43, 'A')));
    EXPECT_TRUE(
        JwtRequestTokenVerifier::peekKid(parts[0] + "." + base64UrlEncode(R"({"sub":"002"})") + "." + parts[2]));
    // The same tokens do NOT verify.
    const auto key = vectorKey();
    EXPECT_REJECTED(run(parts[0] + "." + parts[1] + "." + std::string(43, 'A'), key),
                    VerifyError::InvalidSignature,
                    "garbage signature");
}

// --- header: alg / typ / kid / extras --------------------------------------------------------------
TEST(JwtVerify, RejectsAlgNoneAndEveryOtherAlgorithm)
{
    const auto key = vectorKey();
    for (const char* alg : {"none", "None", "HS384", "HS512", "RS256", "ES256", "hs256", "HS256 ", ""})
    {
        const auto token = headerReplacing(R"("alg":"HS256")", std::string(R"("alg":")") + alg + '"', key);
        EXPECT_REJECTED(run(token, key), VerifyError::InvalidToken, alg);
        EXPECT_FALSE(JwtRequestTokenVerifier::peekKid(token)) << alg;
    }
    // alg as a non-string, and missing altogether.
    EXPECT_REJECTED(
        run(headerReplacing(R"("alg":"HS256")", R"("alg":256)", key), key), VerifyError::InvalidToken, "int");
    EXPECT_REJECTED(run(withHeader(R"({"kid":"001","typ":"wazuh-agent+jwt"})", key), key),
                    VerifyError::InvalidToken,
                    "missing alg");
    // alg=none with an empty signature: rejected by the grammar (signature must be 32 bytes).
    const auto parts = split(tv::kToken);
    EXPECT_REJECTED(
        run(base64UrlEncode(R"({"alg":"none","kid":"001","typ":"wazuh-agent+jwt"})") + "." + parts[1] + ".", key),
        VerifyError::InvalidToken,
        "alg none, empty signature");
}

TEST(JwtVerify, RejectsTypMissingOrDifferent)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(
        run(withHeader(R"({"alg":"HS256","kid":"001"})", key), key), VerifyError::InvalidToken, "missing typ");
    for (const char* typ :
         {"JWT", "wazuh-enroll+jwt", "Wazuh-Agent+JWT", "wazuh-agent+jwt ", "", "application/wazuh-agent+jwt"})
    {
        EXPECT_REJECTED(
            run(headerReplacing(R"("typ":"wazuh-agent+jwt")", std::string(R"("typ":")") + typ + '"', key), key),
            VerifyError::InvalidToken,
            typ);
    }
}

TEST(JwtVerify, RejectsKidMissingNonCanonicalTraversalOrTooLong)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(run(withHeader(R"({"alg":"HS256","typ":"wazuh-agent+jwt"})", key), key),
                    VerifyError::InvalidToken,
                    "missing kid");
    for (const char* kid : {"1",
                            "0001",
                            "01",
                            "",
                            " 001",
                            "001 ",
                            "-1",
                            "+1",
                            "../001",
                            "001/../002",
                            "00a",
                            "12345678901",
                            "4294967296",
                            "0x1",
                            "1e0"})
    {
        const auto token = headerReplacing(R"("kid":"001")", std::string(R"("kid":")") + kid + '"', key);
        EXPECT_REJECTED(run(token, key), VerifyError::InvalidToken, kid);
        EXPECT_FALSE(JwtRequestTokenVerifier::peekKid(token)) << kid;
    }
    EXPECT_REJECTED(
        run(headerReplacing(R"("kid":"001")", R"("kid":1)", key), key), VerifyError::InvalidToken, "kid int");
    EXPECT_REJECTED(
        run(headerReplacing(R"("kid":"001")", R"("kid":["001"])", key), key), VerifyError::InvalidToken, "kid array");
}

TEST(JwtVerify, RejectsAnyExtraOrDuplicateHeaderParameter)
{
    const auto key = vectorKey();
    for (const char* extra : {R"("jku":"https://x/")",
                              R"("x5u":"https://x/")",
                              R"("jwk":{"kty":"oct","k":"AA"})",
                              R"("crit":["exp"])",
                              R"("cty":"JWT")",
                              R"("x5c":["MII"])",
                              R"("zip":"DEF")",
                              R"("alg":"HS256")", // duplicate, same value
                              R"("alg":"none")",  // duplicate, different value
                              R"("kid":"002")",   // duplicate kid
                              R"("aud":"x")"})
    {
        const auto header = std::string(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt",)") + extra + "}";
        EXPECT_REJECTED(run(withHeader(header, key), key), VerifyError::InvalidToken, extra);
        EXPECT_FALSE(JwtRequestTokenVerifier::peekKid(withHeader(header, key))) << extra;
    }
    // Duplicate first, valid last (last-wins parsers would accept this).
    EXPECT_REJECTED(run(withHeader(R"({"alg":"none","kid":"001","typ":"wazuh-agent+jwt","alg":"HS256"})", key), key),
                    VerifyError::InvalidToken,
                    "alg none then HS256");
}

// --- identity -------------------------------------------------------------------------------------
TEST(JwtVerify, RejectsIdentityMismatchBetweenKidSubAndIss)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(
        run(payloadReplacing(R"("sub":"001")", R"("sub":"002")", key), key), VerifyError::IdentityMismatch, "sub");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", R"("sub":"1")", key), key),
                    VerifyError::IdentityMismatch,
                    "sub non-canonical");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"wazuh-agent/002")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss other agent");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"wazuh-manager/001")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss other prefix");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"001")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss bare id");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"wazuh-agent/0011")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss longer id");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"wazuh-agent/001/")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss trailing slash");
    EXPECT_REJECTED(run(payloadReplacing(R"("iss":"wazuh-agent/001")", R"("iss":"")", key), key),
                    VerifyError::IdentityMismatch,
                    "iss empty");
    // kid names another agent than sub/iss (signed with the same key: pure identity check).
    EXPECT_REJECTED(
        run(headerReplacing(R"("kid":"001")", R"("kid":"002")", key), key), VerifyError::IdentityMismatch, "kid");
}

// --- claim set / types ----------------------------------------------------------------------------
TEST(JwtVerify, RejectsAudAsStringOrArray)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(run(tv::kAudToken, key), VerifyError::InvalidToken, "frozen aud vector");
    EXPECT_REJECTED(run(withPayload(tv::kAudPayloadJson, key), key), VerifyError::InvalidToken, "aud string");
    EXPECT_REJECTED(
        run(withPayload(
                replaceOnce(std::string(tv::kAudPayloadJson), R"("aud":"wazuh-manager")", R"("aud":["wazuh-manager"])"),
                key),
            key),
        VerifyError::InvalidToken,
        "aud array");
}

TEST(JwtVerify, RejectsMissingDuplicateOrExtraClaims)
{
    const auto key = vectorKey();
    const std::map<std::string, std::string> members {{"exp", R"("exp":1700000060,)"},
                                                      {"iat", R"("iat":1700000000,)"},
                                                      {"iss", R"("iss":"wazuh-agent/001",)"},
                                                      {"jti", R"("jti":"AAECAwQFBgcICQoLDA0ODw",)"},
                                                      {"nbf", R"("nbf":1700000000,)"},
                                                      {"sub", R"(,"sub":"001")"}};
    for (const auto& [claim, text] : members)
    {
        EXPECT_REJECTED(run(payloadReplacing(text, "", key), key), VerifyError::InvalidToken, "missing " + claim);
    }
    EXPECT_REJECTED(run(withPayload("{}", key), key), VerifyError::InvalidToken, "empty object");

    // Duplicates (identical and conflicting values).
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", R"("sub":"001","sub":"001")", key), key),
                    VerifyError::InvalidToken,
                    "dup sub same");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", R"("sub":"002","sub":"001")", key), key),
                    VerifyError::InvalidToken,
                    "dup sub conflicting");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1700000060,"exp":1700000060)", key), key),
                    VerifyError::InvalidToken,
                    "dup exp");

    // Extra members, however innocuous.
    for (const char* extra :
         {R"("foo":1)", R"("scope":"read")", R"("azp":"001")", R"("nonce":"x")", R"("cnf":{"jkt":"x"})"})
    {
        EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", std::string(R"("sub":"001",)") + extra, key), key),
                        VerifyError::InvalidToken,
                        extra);
    }
}

TEST(JwtVerify, RejectsNumericDatesThatAreNotNonNegativeIntegers)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(run(payloadReplacing(R"("iat":1700000000)", R"("iat":1700000000.0)", key), key),
                    VerifyError::InvalidToken,
                    "iat float");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1700000060.5)", key), key),
                    VerifyError::InvalidToken,
                    "exp fractional");
    EXPECT_REJECTED(run(payloadReplacing(R"("iat":1700000000)", R"("iat":1.7e9)", key), key),
                    VerifyError::InvalidToken,
                    "iat exponent");
    EXPECT_REJECTED(run(payloadReplacing(R"("iat":1700000000)", R"("iat":"1700000000")", key), key),
                    VerifyError::InvalidToken,
                    "iat string");
    EXPECT_REJECTED(run(payloadReplacing(R"("nbf":1700000000)", R"("nbf":"1700000000")", key), key),
                    VerifyError::InvalidToken,
                    "nbf string");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":-1700000060)", key), key),
                    VerifyError::InvalidToken,
                    "exp negative");
    EXPECT_REJECTED(run(payloadReplacing(R"("iat":1700000000)", R"("iat":-1)", key), key),
                    VerifyError::InvalidToken,
                    "iat negative");
    EXPECT_REJECTED(
        run(payloadReplacing(R"("iat":1700000000)", R"("iat":true)", key), key), VerifyError::InvalidToken, "iat bool");
    EXPECT_REJECTED(
        run(payloadReplacing(R"("iat":1700000000)", R"("iat":null)", key), key), VerifyError::InvalidToken, "iat null");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":9223372036854775808)", key), key),
                    VerifyError::InvalidToken,
                    "exp > INT64_MAX");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":18446744073709551616)", key), key),
                    VerifyError::InvalidToken,
                    "exp > UINT64_MAX");
    EXPECT_REJECTED(run(payloadReplacing(R"("jti":"AAECAwQFBgcICQoLDA0ODw")", R"("jti":16)", key), key),
                    VerifyError::InvalidToken,
                    "jti int");
    EXPECT_REJECTED(
        run(payloadReplacing(R"("sub":"001")", R"("sub":1)", key), key), VerifyError::InvalidToken, "sub int");
}

TEST(JwtVerify, RejectsStructuralTimeRelationsAndOverflowSafely)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(run(payloadReplacing(R"("nbf":1700000000)", R"("nbf":1700000001)", key), key),
                    VerifyError::InvalidToken,
                    "nbf != iat");
    EXPECT_REJECTED(run(payloadReplacing(R"("nbf":1700000000)", R"("nbf":1699999999)", key), key),
                    VerifyError::InvalidToken,
                    "nbf < iat");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1700000000)", key), key),
                    VerifyError::InvalidToken,
                    "exp == iat");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1699999999)", key), key),
                    VerifyError::InvalidToken,
                    "exp < iat");
    EXPECT_REJECTED(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1700000061)", key), key),
                    VerifyError::InvalidToken,
                    "lifetime 61");
    // Shorter declared lifetimes are structurally fine (only the maximum is a constant).
    EXPECT_TRUE(run(payloadReplacing(R"("exp":1700000060)", R"("exp":1700000001)", key), key).ok());

    // Values at the int64 edge: structurally valid (exp - iat == 60) but issued far in the future;
    // the future check fires before any sum that could overflow.
    const std::string edge =
        R"({"exp":9223372036854775807,"iat":9223372036854775747,"iss":"wazuh-agent/001","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":9223372036854775747,"sub":"001"})";
    EXPECT_REJECTED(run(withPayload(edge, key), key), VerifyError::StaleToken, "int64 edge");
    // The largest reading the clock can represent (a system_clock time_point counts nanoseconds, so
    // seconds near INT64_MAX are not constructible without overflowing the conversion).
    const auto clockMaxSeconds = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::time_point::max().time_since_epoch())
                                     .count();
    EXPECT_REJECTED(run(withPayload(edge, key), key, clockMaxSeconds), VerifyError::StaleToken, "clock at its maximum");
    // Zero timestamps: structurally fine, far in the past.
    const std::string zero =
        R"({"exp":60,"iat":0,"iss":"wazuh-agent/001","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":0,"sub":"001"})";
    EXPECT_TRUE(run(withPayload(zero, key), key, 30).ok());
    EXPECT_REJECTED(run(withPayload(zero, key), key), VerifyError::StaleToken, "epoch token now");
    // A clock before the epoch never accepts anything.
    EXPECT_REJECTED(run(withPayload(zero, key), key, -1), VerifyError::StaleToken, "negative clock");
}

TEST(JwtVerify, RejectsJtiThatIsNotSixteenCanonicalBytes)
{
    const auto key = vectorKey();
    for (const char* jti : {"",
                            "AAECAwQFBgcICQoLDA0OD",             // 21 chars
                            "AAECAwQFBgcICQoLDA0ODwA",           // 23 chars
                            "AAECAwQFBgcICQoLDA0ODw==",          // padding
                            "AAECAwQFBgcICQoLDA0ODx",            // dirty trailing bits
                            "AAECAwQFBgcICQoLDA0OD+",            // standard alphabet
                            "AAECAwQFBgcICQoLDA0O%3d",           // percent fill
                            "0123456789abcdef0123456789abcdef"}) // 32 hex chars, not base64url of 16 bytes
    {
        EXPECT_REJECTED(
            run(payloadReplacing(R"("jti":"AAECAwQFBgcICQoLDA0ODw")", std::string(R"("jti":")") + jti + '"', key), key),
            VerifyError::InvalidToken,
            std::string("jti=") + jti);
    }
}

// --- signature ------------------------------------------------------------------------------------
TEST(JwtVerify, RejectsTamperedTruncatedExtendedOrForeignSignatures)
{
    const auto key = vectorKey();
    const auto parts = split(tv::kToken);
    ASSERT_EQ(parts.size(), 3u);
    const auto rebuild = [&](const std::string& sig)
    {
        return parts[0] + "." + parts[1] + "." + sig;
    };

    EXPECT_REJECTED(run(rebuild(parts[2].substr(0, 42)), key), VerifyError::InvalidToken, "truncated (31 bytes)");
    EXPECT_REJECTED(run(rebuild(parts[2] + "A"), key), VerifyError::InvalidToken, "extended (44 chars)");
    EXPECT_REJECTED(run(rebuild(""), key), VerifyError::InvalidToken, "empty signature");
    EXPECT_REJECTED(run(rebuild(parts[2] + "=="), key), VerifyError::InvalidToken, "padded signature");
    EXPECT_REJECTED(run(rebuild(dirtyLastChar(parts[2])), key), VerifyError::InvalidToken, "non-canonical signature");

    auto altered = parts[2];
    altered[10] = altered[10] == 'A' ? 'B' : 'A';
    EXPECT_REJECTED(run(rebuild(altered), key), VerifyError::InvalidSignature, "one char altered");
    EXPECT_REJECTED(run(rebuild(std::string(43, 'A')), key), VerifyError::InvalidSignature, "all-zero signature");

    // Tampered payload keeps the original (now invalid) signature.
    EXPECT_REJECTED(
        run(parts[0] + "." +
                base64UrlEncode(replaceOnce(std::string(tv::kPayloadJson), R"("sub":"001")", R"("sub":"002")")) + "." +
                parts[2],
            key),
        VerifyError::InvalidSignature,
        "payload tampered");

    // Wrong key: one bit flipped; a 31-byte key; an empty key; the ASCII text of the key.
    SecureBytes flipped {key.data(), key.size()};
    flipped.data()[0] ^= 0x01;
    EXPECT_REJECTED(run(tv::kToken, flipped), VerifyError::InvalidSignature, "flipped key bit");
    EXPECT_REJECTED(run(tv::kToken, SecureBytes {key.data(), 31}), VerifyError::InvalidSignature, "31-byte key");
    EXPECT_REJECTED(run(tv::kToken, SecureBytes {}), VerifyError::InvalidSignature, "empty key");
    EXPECT_REJECTED(run(tv::kAsciiKeyToken, key), VerifyError::InvalidSignature, "ascii-key vector");
    const SecureBytes ascii {reinterpret_cast<const std::uint8_t*>(tv::kKeyHex.data()), tv::kKeyHex.size()};
    EXPECT_REJECTED(run(tv::kToken, ascii), VerifyError::InvalidSignature, "verifying with the ascii key");
}

// --- grammar / encoding ---------------------------------------------------------------------------
TEST(JwtVerify, RejectsCompactGrammarViolations)
{
    const auto key = vectorKey();
    const auto parts = split(tv::kToken);
    const std::string token {tv::kToken};

    EXPECT_REJECTED(run("", key), VerifyError::InvalidToken, "empty");
    EXPECT_REJECTED(run(".", key), VerifyError::InvalidToken, "single dot");
    EXPECT_REJECTED(run("..", key), VerifyError::InvalidToken, "two dots");
    EXPECT_REJECTED(run(parts[0] + "." + parts[1], key), VerifyError::InvalidToken, "two segments");
    EXPECT_REJECTED(run(token + ".x", key), VerifyError::InvalidToken, "four segments");
    EXPECT_REJECTED(run(token + ".", key), VerifyError::InvalidToken, "trailing dot");
    EXPECT_REJECTED(run("." + token, key), VerifyError::InvalidToken, "leading dot");
    EXPECT_REJECTED(run("." + parts[1] + "." + parts[2], key), VerifyError::InvalidToken, "empty header");
    EXPECT_REJECTED(run(parts[0] + ".." + parts[2], key), VerifyError::InvalidToken, "empty payload");
    EXPECT_REJECTED(run(" " + token, key), VerifyError::InvalidToken, "leading space");
    EXPECT_REJECTED(run(token + "\n", key), VerifyError::InvalidToken, "trailing newline");
    EXPECT_REJECTED(run("Bearer " + token, key), VerifyError::InvalidToken, "scheme included");

    // base64url: padding, percent fill, standard alphabet, dirty trailing bits, len % 4 == 1.
    EXPECT_REJECTED(run(parts[0] + "=." + parts[1] + "." + parts[2], key), VerifyError::InvalidToken, "header padded");
    EXPECT_REJECTED(
        run(parts[0] + "." + parts[1] + "%3d." + parts[2], key), VerifyError::InvalidToken, "payload percent fill");
    ASSERT_NE(parts[2].find('_'), std::string::npos);
    EXPECT_REJECTED(run(parts[0] + "." + parts[1] + "." + replaceOnce(parts[2], "_", "/"), key),
                    VerifyError::InvalidToken,
                    "std alphabet");
    EXPECT_REJECTED(run(parts[0] + "." + dirtyLastChar(parts[1]) + "." + parts[2], key),
                    VerifyError::InvalidToken,
                    "payload dirty bits");
    std::string oddLength = parts[1];
    while (oddLength.size() % 4 != 1)
    {
        oddLength += 'A';
    }
    EXPECT_REJECTED(
        run(parts[0] + "." + oddLength + "." + parts[2], key), VerifyError::InvalidToken, "payload len % 4 == 1");

    // Size: anything over 4096 bytes is rejected before any parsing.
    EXPECT_REJECTED(run(std::string(4097, 'A'), key), VerifyError::InvalidToken, "4097 bytes");
    EXPECT_FALSE(JwtRequestTokenVerifier::peekKid(std::string(4097, 'A')));
    std::string huge = parts[0] + "." + parts[1] + std::string(4096, 'A') + "." + parts[2];
    EXPECT_REJECTED(run(huge, key), VerifyError::InvalidToken, "oversized valid-looking token");
}

TEST(JwtVerify, RejectsInvalidJsonUtf8AndNonObjectSegments)
{
    const auto key = vectorKey();
    EXPECT_REJECTED(run(withHeader(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt")", key), key),
                    VerifyError::InvalidToken,
                    "header unterminated");
    EXPECT_REJECTED(
        run(withHeader(R"(["HS256","001","wazuh-agent+jwt"])", key), key), VerifyError::InvalidToken, "header array");
    EXPECT_REJECTED(run(withHeader(R"("HS256")", key), key), VerifyError::InvalidToken, "header string");
    EXPECT_REJECTED(run(withHeader("", key), key), VerifyError::InvalidToken, "header empty json");
    EXPECT_REJECTED(run(withHeader(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"} x)", key), key),
                    VerifyError::InvalidToken,
                    "header trailing garbage");
    EXPECT_REJECTED(run(withHeader(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"}{})", key), key),
                    VerifyError::InvalidToken,
                    "two objects");
    EXPECT_REJECTED(run(withHeader(R"({'alg':'HS256','kid':'001','typ':'wazuh-agent+jwt'})", key), key),
                    VerifyError::InvalidToken,
                    "single quotes");
    EXPECT_REJECTED(run(withHeader(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt",})", key), key),
                    VerifyError::InvalidToken,
                    "trailing comma");

    // Non-ASCII bytes: the profile text is ASCII, and a truncated multi-byte lead at the very end of a
    // decoded segment is the ASAN regression (rapidjson's UTF-8 validation over a NUL-terminated
    // stream read past the buffer). Correct signature either way: the JSON pre-parse rejects them.
    const std::string headerHead = R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt)";
    EXPECT_REJECTED(
        run(withHeader(headerHead + "\xF0", key), key), VerifyError::InvalidToken, "header ends in a lead byte");
    EXPECT_REJECTED(
        run(withHeader(headerHead + "\xE2\x82", key), key), VerifyError::InvalidToken, "header ends mid-sequence");
    EXPECT_REJECTED(
        run(withHeader(headerHead + "\xC3\xA9\"}", key), key), VerifyError::InvalidToken, "valid UTF-8 in typ");
    EXPECT_REJECTED(
        run(payloadReplacing(R"("iss":"wazuh-agent/001")", "\"iss\":\"wazuh-agent/001\xC3\xA9\"", key), key),
        VerifyError::InvalidToken,
        "valid UTF-8 in iss");
    EXPECT_REJECTED(run(withPayload(std::string(tv::kPayloadJson).substr(0, 20) + "\xF0", key), key),
                    VerifyError::InvalidToken,
                    "payload ends in a lead byte");
    EXPECT_REJECTED(
        run(withHeader("\xEF\xBB\xBF" + std::string(tv::kHeaderJson), key), key), VerifyError::InvalidToken, "BOM");

    EXPECT_REJECTED(run(withPayload("[1]", key), key), VerifyError::InvalidToken, "payload array");
    EXPECT_REJECTED(run(withPayload("null", key), key), VerifyError::InvalidToken, "payload null");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", R"("sub":{"id":"001"})", key), key),
                    VerifyError::InvalidToken,
                    "nested object");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", R"("sub":["001"])", key), key),
                    VerifyError::InvalidToken,
                    "nested array");

    // Invalid UTF-8 inside a string, a raw NUL, and a raw control character.
    EXPECT_REJECTED(
        run(payloadReplacing(R"("iss":"wazuh-agent/001")", std::string("\"iss\":\"wazuh-agent/001\xff\""), key), key),
        VerifyError::InvalidToken,
        "invalid utf-8");
    EXPECT_REJECTED(
        run(payloadReplacing(R"("iss":"wazuh-agent/001")", std::string("\"iss\":\"wazuh-agent/001\xc3\""), key), key),
        VerifyError::InvalidToken,
        "truncated utf-8 sequence");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")",
                                         std::string("\"sub\":\"00\0"
                                                     "1\"",
                                                     12),
                                         key),
                        key),
                    VerifyError::InvalidToken,
                    "raw NUL");
    EXPECT_REJECTED(run(payloadReplacing(R"("sub":"001")", "\"sub\":\"00\n1\"", key), key),
                    VerifyError::InvalidToken,
                    "raw newline in string");
    // Escaped spellings of a canonical value are accepted (JSON, not text, is what the profile fixes).
    EXPECT_TRUE(run(payloadReplacing(R"("sub":"001")", R"("sub":"001")", key), key).ok());
}

// --- robustness -----------------------------------------------------------------------------------
TEST(JwtVerify, NeverThrowsOnRandomOrMutatedInput)
{
    const auto key = vectorKey();
    std::mt19937 rng {0x38582};
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=%+/ {}\"\\:,[]";
    std::map<std::string, int> outcomes;

    // Random strings of the token-ish alphabet, with a sprinkle of arbitrary bytes.
    for (int i = 0; i < 20'000; ++i)
    {
        const std::size_t len = rng() % 400;
        std::string input;
        for (std::size_t k = 0; k < len; ++k)
        {
            input += (rng() % 20 == 0) ? static_cast<char>(rng() % 256) : alphabet[rng() % alphabet.size()];
        }
        const auto result = run(input, key);
        EXPECT_FALSE(result.ok());
        ++outcomes[name(result.error())];
        (void)JwtRequestTokenVerifier::peekKid(input);
    }

    // Point mutations of the valid vector: 1-3 random positions replaced by random alphabet chars.
    int accepted = 0;
    for (int i = 0; i < 20'000; ++i)
    {
        std::string input {tv::kToken};
        const int flips = 1 + static_cast<int>(rng() % 3);
        for (int f = 0; f < flips; ++f)
        {
            input[rng() % input.size()] = alphabet[rng() % alphabet.size()];
        }
        const auto result = run(input, key);
        if (result.ok())
        {
            ++accepted;
            EXPECT_EQ(input, tv::kToken) << "a real mutation verified";
        }
        ++outcomes[name(result.error())];
        (void)JwtRequestTokenVerifier::peekKid(input);
    }
    for (const auto& [outcome, count] : outcomes)
    {
        RecordProperty(outcome.c_str(), count);
    }
    EXPECT_GT(outcomes["InvalidToken"], 0);
    EXPECT_GT(outcomes["InvalidSignature"], 0);
}
