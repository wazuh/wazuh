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

// JwtRequestTokenSigner: byte-exact against the frozen vector, byte-exact against an independent
// jwt-cpp (nlohmann traits) builder used purely as a test oracle, jti freshness/uniqueness/canonical
// form, and fail-closed on every bad input.
#include <gtest/gtest.h>

#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/testVectors.hpp"

#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <chrono>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors;

namespace
{
    std::chrono::system_clock::time_point at(std::int64_t epoch)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epoch}};
    }

    struct FixedClock
    {
        std::chrono::system_clock::time_point tp;
        std::chrono::system_clock::time_point now() const
        {
            return tp;
        }
    };

    SecureBytes vectorKey()
    {
        auto key = JwtKeyDecoder::decode(tv::kKeyHex);
        EXPECT_TRUE(key);
        return std::move(*key);
    }

    CanonicalAgentId vectorAgent()
    {
        return *CanonicalAgentId::parseCanonical(tv::kAgentId);
    }

    std::vector<std::string> split(const std::string& token)
    {
        std::vector<std::string> out;
        std::size_t start = 0;
        for (;;)
        {
            const auto dot = token.find('.', start);
            out.push_back(token.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
            if (dot == std::string::npos)
            {
                return out;
            }
            start = dot + 1;
        }
    }
} // namespace

TEST(JwtSigner, ReproducesTheFrozenVectorByteForByte)
{
    const auto key = vectorKey();
    const auto token = JwtRequestTokenSigner::sign(vectorAgent(), key, at(tv::kIat), tv::kJti);
    ASSERT_TRUE(token);
    EXPECT_EQ(*token, tv::kToken);
    EXPECT_EQ(token->size(), 272u);

    EXPECT_EQ(JwtRequestTokenSigner::headerJson(vectorAgent()), tv::kHeaderJson);
    EXPECT_EQ(JwtRequestTokenSigner::payloadJson(vectorAgent(), tv::kIat, tv::kJti), tv::kPayloadJson);
}

TEST(JwtSigner, SubSecondClockReadingsTruncateToWholeSeconds)
{
    const auto key = vectorKey();
    const auto token =
        JwtRequestTokenSigner::sign(vectorAgent(), key, at(tv::kIat) + std::chrono::milliseconds(999), tv::kJti);
    ASSERT_TRUE(token);
    EXPECT_EQ(*token, tv::kToken);
}

TEST(JwtSigner, MatchesAnIndependentJwtCppBuilder)
{
    // Oracle only: the production signer never touches jwt-cpp's builder or JSON traits. The key
    // goes into a std::string here because that is the oracle's API; the vector key is public.
    const auto key = vectorKey();
    const std::string keyText(reinterpret_cast<const char*>(key.data()), key.size());
    const auto oracle = jwt::create<jwt::default_clock, jwt::traits::nlohmann_json>(jwt::default_clock {})
                            .set_type(std::string(kTyp))
                            .set_key_id("001")
                            .set_issuer("wazuh-agent/001")
                            .set_subject("001")
                            .set_id(std::string(tv::kJti))
                            .set_issued_at(at(tv::kIat))
                            .set_not_before(at(tv::kIat))
                            .set_expires_at(at(tv::kIat + kLifetimeSec))
                            .sign(jwt::algorithm::hs256 {keyText});
    const auto ours = JwtRequestTokenSigner::sign(vectorAgent(), key, at(tv::kIat), tv::kJti);
    ASSERT_TRUE(ours);
    EXPECT_EQ(*ours, oracle);
}

TEST(JwtSigner, EmitsExactlyTheProfileHeaderAndClaims)
{
    const auto key = vectorKey();
    const auto agent = *CanonicalAgentId::parse("42");
    const auto token = JwtRequestTokenSigner::sign(agent, key, at(1'800'000'000));
    ASSERT_TRUE(token);

    const auto decoded = jwt::decode<jwt::traits::nlohmann_json>(*token);
    std::set<std::string> header;
    for (const auto& kv : decoded.get_header_json())
    {
        header.insert(kv.first);
    }
    EXPECT_EQ(header, (std::set<std::string> {"alg", "kid", "typ"}));
    EXPECT_EQ(decoded.get_algorithm(), "HS256");
    EXPECT_EQ(decoded.get_type(), "wazuh-agent+jwt");
    EXPECT_EQ(decoded.get_key_id(), "042");

    std::set<std::string> payload;
    for (const auto& kv : decoded.get_payload_json())
    {
        payload.insert(kv.first);
    }
    EXPECT_EQ(payload, (std::set<std::string> {"exp", "iat", "iss", "jti", "nbf", "sub"}));
    EXPECT_EQ(decoded.get_issuer(), "wazuh-agent/042");
    EXPECT_EQ(decoded.get_subject(), "042");
    const auto& claims = decoded.get_payload_json();
    EXPECT_TRUE(claims.at("iat").is_number_integer() || claims.at("iat").is_number_unsigned());
    EXPECT_EQ(claims.at("iat").get<std::int64_t>(), 1'800'000'000);
    EXPECT_EQ(claims.at("nbf").get<std::int64_t>(), 1'800'000'000);
    EXPECT_EQ(claims.at("exp").get<std::int64_t>(), 1'800'000'060);
    EXPECT_TRUE(JwtRequestTokenSigner::isCanonicalJti(decoded.get_id()));

    // Verifiable with the oracle too (alg allowlist + signature).
    const auto verifyWithOracle = [&]()
    {
        jwt::verify<FixedClock, jwt::traits::nlohmann_json>(FixedClock {at(1'800'000'010)})
            .allow_algorithm(jwt::algorithm::hs256 {std::string(reinterpret_cast<const char*>(key.data()), key.size())})
            .with_type(std::string(kTyp))
            .with_issuer("wazuh-agent/042")
            .verify(decoded);
    };
    EXPECT_NO_THROW(verifyWithOracle());
}

TEST(JwtSigner, TwoTokensInTheSameSecondDifferOnlyInJti)
{
    const auto key = vectorKey();
    const auto a = JwtRequestTokenSigner::sign(vectorAgent(), key, at(tv::kIat));
    const auto b = JwtRequestTokenSigner::sign(vectorAgent(), key, at(tv::kIat));
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_NE(*a, *b);
    const auto pa = split(*a);
    const auto pb = split(*b);
    ASSERT_EQ(pa.size(), 3u);
    EXPECT_EQ(pa[0], pb[0]); // same header
    EXPECT_NE(pa[1], pb[1]); // payload differs (jti)
    EXPECT_NE(pa[2], pb[2]); // hence the signature

    const auto ja = jwt::decode<jwt::traits::nlohmann_json>(*a).get_id();
    const auto jb = jwt::decode<jwt::traits::nlohmann_json>(*b).get_id();
    EXPECT_NE(ja, jb);
    EXPECT_TRUE(JwtRequestTokenSigner::isCanonicalJti(ja));
    EXPECT_TRUE(JwtRequestTokenSigner::isCanonicalJti(jb));
}

TEST(JwtSigner, RandomJtiIsCanonicalAndUniqueAtVolume)
{
    constexpr int kCount = 100'000;
    std::unordered_set<std::string> seen;
    seen.reserve(kCount);
    for (int i = 0; i < kCount; ++i)
    {
        const auto jti = JwtRequestTokenSigner::randomJti();
        ASSERT_TRUE(jti);
        ASSERT_EQ(jti->size(), kJtiChars);
        ASSERT_TRUE(JwtRequestTokenSigner::isCanonicalJti(*jti)) << *jti;
        ASSERT_TRUE(seen.insert(*jti).second) << "duplicate jti after " << i << " draws: " << *jti;
    }
}

TEST(JwtSigner, IsCanonicalJtiPinsTheGrammar)
{
    EXPECT_TRUE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0ODw"));
    EXPECT_TRUE(JwtRequestTokenSigner::isCanonicalJti("__________________-_-w"));
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti(""));
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0OD"));   // 21
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0ODwA")); // 23
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0ODw=="));
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0ODx")); // dirty trailing bits
    EXPECT_FALSE(JwtRequestTokenSigner::isCanonicalJti("AAECAwQFBgcICQoLDA0OD+")); // std alphabet
}

TEST(JwtSigner, FailsClosedOnBadInputs)
{
    const auto key = vectorKey();
    const auto agent = vectorAgent();

    // Key of the wrong size (a legacy 16-byte key, a 31-byte one, empty).
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, SecureBytes {key.data(), 16}, at(tv::kIat)));
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, SecureBytes {key.data(), 31}, at(tv::kIat)));
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, SecureBytes {}, at(tv::kIat)));

    // Clock before the epoch.
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, key, at(-1)));

    // Non-canonical jti overrides never reach the wire.
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, key, at(tv::kIat), "short"));
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, key, at(tv::kIat), "AAECAwQFBgcICQoLDA0ODw=="));
    EXPECT_FALSE(JwtRequestTokenSigner::sign(agent, key, at(tv::kIat), "AAECAwQFBgcICQoLDA0ODx"));

    // And the good path still works with the same inputs otherwise.
    EXPECT_TRUE(JwtRequestTokenSigner::sign(agent, key, at(tv::kIat)));
}
