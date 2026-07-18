/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "canonicalRequest.hpp"
#include "cmacSigner.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

namespace
{
    // RFC 4493 test key: 2b7e151628aed2a6abf7158809cf4f3c.
    const std::vector<uint8_t> RFC4493_KEY = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
} // namespace

TEST(CmacSignerTest, Rfc4493EmptyMessageVector)
{
    const auto mac = CmacSigner::macHex(RFC4493_KEY, nullptr, 0);
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ("bb1d6929e95937287fa37d129b756746", *mac);
}

TEST(CmacSignerTest, Rfc4493SixteenByteMessageVector)
{
    const std::vector<uint8_t> message = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const auto mac = CmacSigner::macHex(RFC4493_KEY, message.data(), message.size());
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ("070a16b46b4d4144f79bdd9dd04a287c", *mac);
}

TEST(CmacSignerTest, RejectsWrongSizeKey)
{
    const std::vector<uint8_t> shortKey(8, 0xaa);
    EXPECT_FALSE(CmacSigner::macHex(shortKey, nullptr, 0).has_value());
}

TEST(CmacSignerTest, SignProducesTheTwoContractHeaders)
{
    const ConfigKeyProvider provider {"000102030405060708090a0b0c0d0e0f"};
    const CmacSigner signer {"001", provider};
    const uint8_t body[] = "abc";

    const auto headers = signer.sign("POST", "/stateless", body, 3, 1700000000);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);

    // The MAC must be exactly AES-CMAC(key, canonical head + body).
    const auto canonical = buildCanonicalRequest("POST", "/stateless", "001", 1700000000, body, 3);
    const auto expectedMac =
        CmacSigner::macHex(*provider.cmacKey(), canonical.data(), canonical.size());
    ASSERT_TRUE(expectedMac.has_value());
    EXPECT_EQ("Authorization: Wazuh 001:1700000000:" + *expectedMac, headers->authorization);
}

TEST(CmacSignerTest, DifferentTimestampChangesTheMac)
{
    const ConfigKeyProvider provider {"000102030405060708090a0b0c0d0e0f"};
    const CmacSigner signer {"001", provider};
    const uint8_t body[] = "abc";
    const auto first = signer.sign("POST", "/stateless", body, 3, 1700000000);
    const auto second = signer.sign("POST", "/stateless", body, 3, 1700000001);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->authorization, second->authorization);
}

TEST(CmacSignerTest, SignFileMatchesInMemorySignature)
{
    const ConfigKeyProvider provider {"000102030405060708090a0b0c0d0e0f"};
    const CmacSigner signer {"001", provider};

    // A body larger than the incremental chunk proves the chunked path.
    std::string body(100 * 1024 + 37, '\0');
    for (size_t index = 0; index < body.size(); index++)
    {
        body[index] = static_cast<char>('a' + (index % 23));
    }
    const std::string path = ::testing::TempDir() + "hc_signer_body.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << body;
    }

    const auto fromFile = signer.signFile("POST", "/stateful", path, 1700000000);
    const auto fromMemory = signer.sign(
        "POST", "/stateful", reinterpret_cast<const uint8_t*>(body.data()), body.size(), 1700000000);
    std::remove(path.c_str());

    ASSERT_TRUE(fromFile.has_value());
    ASSERT_TRUE(fromMemory.has_value());
    EXPECT_EQ(fromMemory->authorization, fromFile->authorization);
}

TEST(CmacSignerTest, SignFileFailsOnMissingFile)
{
    const ConfigKeyProvider provider {"000102030405060708090a0b0c0d0e0f"};
    const CmacSigner signer {"001", provider};
    EXPECT_FALSE(signer.signFile("POST", "/stateful", "/nonexistent/spool.bin", 1).has_value());
}

TEST(CmacSignerTest, UnusableKeyMaterialYieldsNoHeaders)
{
    const ConfigKeyProvider badProvider {"zz"};
    const CmacSigner signer {"001", badProvider};
    EXPECT_FALSE(signer.sign("POST", "/control", nullptr, 0, 1).has_value());
    EXPECT_FALSE(signer.signFile("POST", "/control", "/tmp/whatever", 1).has_value());
}

TEST(ConfigKeyProviderTest, ParsesValidHex)
{
    const ConfigKeyProvider provider {"000102030405060708090A0B0C0D0E0F"};
    const auto key = provider.cmacKey();
    ASSERT_TRUE(key.has_value());
    ASSERT_EQ(16u, key->size());
    EXPECT_EQ(0x00, (*key)[0]);
    EXPECT_EQ(0x0f, (*key)[15]);
}

TEST(ConfigKeyProviderTest, RejectsMalformedHex)
{
    EXPECT_FALSE(ConfigKeyProvider {""}.cmacKey().has_value());
    EXPECT_FALSE(ConfigKeyProvider {"0011"}.cmacKey().has_value());              // Too short.
    EXPECT_FALSE(ConfigKeyProvider {std::string(33, 'a')}.cmacKey().has_value()); // Odd length.
    EXPECT_FALSE(ConfigKeyProvider {"g0102030405060708090a0b0c0d0e0f0"}.cmacKey().has_value());
}
