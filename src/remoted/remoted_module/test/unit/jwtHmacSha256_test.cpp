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

// hmacSha256() (EVP_Q_mac) against RFC 4231 and the frozen profile vector, plus the ascii-key
// negative and the constant-time comparison helper.
#include <gtest/gtest.h>

#include "jwt/base64Url.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/testVectors.hpp"

#include <string>

using namespace jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors;

namespace
{
    std::string toHex(const HmacSha256Digest& d)
    {
        static const char* kHex = "0123456789abcdef";
        std::string out;
        for (const auto b : d)
        {
            out += kHex[b >> 4];
            out += kHex[b & 0x0f];
        }
        return out;
    }
} // namespace

TEST(JwtHmacSha256, Rfc4231TestCase2)
{
    const std::string keyText = "Jefe";
    const SecureBytes key {reinterpret_cast<const std::uint8_t*>(keyText.data()), keyText.size()};
    HmacSha256Digest mac {};
    ASSERT_TRUE(hmacSha256(key, "what do ya want for nothing?", mac));
    EXPECT_EQ(toHex(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(JwtHmacSha256, ReproducesTheVectorSignature)
{
    const auto key = JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key);
    HmacSha256Digest mac {};
    ASSERT_TRUE(hmacSha256(*key, tv::kSigningInput, mac));
    EXPECT_EQ(base64UrlEncode(mac.data(), mac.size()), tv::kSignatureB64Url);
}

TEST(JwtHmacSha256, AsciiKeyProducesTheNegativeVectorNotTheValidOne)
{
    const SecureBytes ascii {reinterpret_cast<const std::uint8_t*>(tv::kKeyHex.data()), tv::kKeyHex.size()};
    HmacSha256Digest mac {};
    ASSERT_TRUE(hmacSha256(ascii, tv::kSigningInput, mac));
    const auto sig = base64UrlEncode(mac.data(), mac.size());
    EXPECT_NE(sig, tv::kSignatureB64Url);
    EXPECT_EQ(std::string(tv::kSigningInput) + "." + sig, tv::kAsciiKeyToken);
}

TEST(JwtHmacSha256, EmptyKeyFails)
{
    const SecureBytes empty;
    HmacSha256Digest mac {};
    EXPECT_FALSE(hmacSha256(empty, "x", mac));
}

TEST(JwtHmacSha256, EqualIsExactLengthAndContent)
{
    HmacSha256Digest a {};
    a[0] = 1;
    HmacSha256Digest b = a;
    EXPECT_TRUE(hmacSha256Equal(a, b.data(), b.size()));
    EXPECT_FALSE(hmacSha256Equal(a, b.data(), b.size() - 1));
    b[31] ^= 0x80;
    EXPECT_FALSE(hmacSha256Equal(a, b.data(), b.size()));
}
