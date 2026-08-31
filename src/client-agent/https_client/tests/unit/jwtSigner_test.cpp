/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "jwt/testVectors.hpp"
#include "jwtSigner.hpp"
#include "jwtTestSupport.hpp"

#include <gtest/gtest.h>

#include <set>

namespace tv = jwt_profile::v1::test_vectors;

namespace
{
    std::string tokenOf(const SignedHeaders& headers)
    {
        return headers.authorization.substr(std::string("Authorization: Bearer ").size());
    }
} // namespace

TEST(JwtSignerTest, ProducesTheTwoContractHeadersWithAVerifiableBearer)
{
    const ConfigKeyProvider provider {testAgentKeyHex()};
    const JwtSigner signer {"001", provider};

    const auto headers = signer.sign(1700000000);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);

    const auto decoded = decodeBearer(headers->authorization, testAgentKeyHex());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->signatureValid);
    EXPECT_EQ("HS256", decoded->header.at("alg"));
    EXPECT_EQ("wazuh-agent+jwt", decoded->header.at("typ"));
    EXPECT_EQ("001", decoded->header.at("kid"));
    EXPECT_EQ(3u, decoded->header.size());
    EXPECT_EQ("001", decoded->claims.at("sub"));
    EXPECT_EQ("wazuh-agent/001", decoded->claims.at("iss"));
    EXPECT_EQ(1700000000, decoded->claims.at("iat"));
    EXPECT_EQ(1700000000, decoded->claims.at("nbf"));
    EXPECT_EQ(1700000060, decoded->claims.at("exp"));
    EXPECT_EQ(22u, decoded->claims.at("jti").get<std::string>().size());
    EXPECT_EQ(6u, decoded->claims.size()); // exactly the profile's six, no aud
}

TEST(JwtSignerTest, MatchesTheFrozenVectorExceptForTheRandomJti)
{
    // The shared signer reproduces the vector byte for byte when given the vector's jti
    // (pinned in the manager's tests); through the agent's ISigner the jti is always fresh,
    // so the vector key/id/iat must yield the same header and the same claims minus jti.
    const ConfigKeyProvider provider {std::string(tv::kKeyHex)};
    const JwtSigner signer {std::string(tv::kAgentId), provider};

    const auto headers = signer.sign(tv::kIat);
    ASSERT_TRUE(headers.has_value());
    const auto token = tokenOf(*headers);
    const std::string vectorHeader = std::string(tv::kToken).substr(0, std::string(tv::kToken).find('.'));
    EXPECT_EQ(vectorHeader, token.substr(0, token.find('.')));

    const auto decoded = decodeBearer(headers->authorization, std::string(tv::kKeyHex));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->signatureValid);
    auto claims = decoded->claims;
    claims.erase("jti");
    auto expected = nlohmann::json::parse(std::string(tv::kPayloadJson));
    expected.erase("jti");
    EXPECT_EQ(expected, claims);
}

TEST(JwtSignerTest, TheConfiguredIdIsCanonicalised)
{
    const ConfigKeyProvider provider {testAgentKeyHex()};

    for (const auto* configured :
            {"1", "01", "001", "0001"
            })
    {
        const JwtSigner signer {configured, provider};
        const auto headers = signer.sign(1700000000);
        ASSERT_TRUE(headers.has_value()) << configured;
        const auto decoded = decodeBearer(headers->authorization, testAgentKeyHex());
        ASSERT_TRUE(decoded.has_value()) << configured;
        EXPECT_EQ("001", decoded->header.at("kid")) << configured;
        EXPECT_EQ("001", decoded->claims.at("sub")) << configured;
    }
}

TEST(JwtSignerTest, EveryCallMintsAFreshToken)
{
    const ConfigKeyProvider provider {testAgentKeyHex()};
    const JwtSigner signer {"001", provider};

    std::set<std::string> tokens;

    for (int i = 0; i < 50; i++)
    {
        const auto headers = signer.sign(1700000000); // same second on purpose
        ASSERT_TRUE(headers.has_value());
        EXPECT_TRUE(tokens.insert(tokenOf(*headers)).second) << "duplicate token";
    }

    const auto later = signer.sign(1700000001);
    ASSERT_TRUE(later.has_value());
    const auto decoded = decodeBearer(later->authorization, testAgentKeyHex());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(1700000001, decoded->claims.at("iat"));
    EXPECT_EQ(1700000061, decoded->claims.at("exp"));
}

TEST(JwtSignerTest, SetAgentIdChangesEverySubsequentToken)
{
    const ConfigKeyProvider provider {testAgentKeyHex()};
    JwtSigner signer {"001", provider};

    signer.setAgentId("042");
    const auto headers = signer.sign(1700000000);
    ASSERT_TRUE(headers.has_value());
    const auto decoded = decodeBearer(headers->authorization, testAgentKeyHex());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ("042", decoded->header.at("kid"));
    EXPECT_EQ("042", decoded->claims.at("sub"));
    EXPECT_EQ("wazuh-agent/042", decoded->claims.at("iss"));
}

TEST(JwtSignerTest, ASwappedKeySignsTheNextToken)
{
    ConfigKeyProvider provider {testAgentKeyHex()};
    const JwtSigner signer {"001", provider};
    const std::string otherKey {tv::kKeyHex};

    ASSERT_TRUE(provider.setKey(otherKey));
    const auto headers = signer.sign(1700000000);
    ASSERT_TRUE(headers.has_value());
    EXPECT_TRUE(decodeBearer(headers->authorization, otherKey)->signatureValid);
    EXPECT_FALSE(decodeBearer(headers->authorization, testAgentKeyHex())->signatureValid);
}

TEST(JwtSignerTest, UnusableKeyMaterialYieldsNoHeaders)
{
    const ConfigKeyProvider badProvider {"zz"};
    const JwtSigner signer {"001", badProvider};
    EXPECT_FALSE(signer.sign(1).has_value());

    // A 16-byte key is unusable: the profile key is exactly 32 bytes.
    const ConfigKeyProvider shortProvider {"000102030405060708090a0b0c0d0e0f"};
    const JwtSigner shortSigner {"001", shortProvider};
    EXPECT_FALSE(shortSigner.sign(1).has_value());
}

TEST(JwtSignerTest, NonNumericAgentIdYieldsNoHeaders)
{
    const ConfigKeyProvider provider {testAgentKeyHex()};
    const JwtSigner signer {"agent-001", provider};
    EXPECT_FALSE(signer.sign(1700000000).has_value());
}
