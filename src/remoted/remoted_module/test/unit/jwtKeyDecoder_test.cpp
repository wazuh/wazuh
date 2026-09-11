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

// 64 lowercase hex chars -> 32 bytes, and nothing else. Uses the frozen vector key (leading 0x00,
// trailing 0xff) so the binary-key path is exercised, not just printable bytes.
#include <gtest/gtest.h>

#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/testVectors.hpp"

#include <string>

using namespace jwt_profile::v1;
namespace tv = jwt_profile::v1::test_vectors;

TEST(JwtKeyDecoder, DecodesTheVectorKeyToThirtyTwoBytes)
{
    const auto key = JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key);
    ASSERT_EQ(key->size(), 32u);
    EXPECT_EQ(key->data()[0], 0x00);
    EXPECT_EQ(key->data()[1], 0x30);
    EXPECT_EQ(key->data()[2], 0x55);
    EXPECT_EQ(key->data()[31], 0xff);
}

TEST(JwtKeyDecoder, RejectsEveryOtherLength)
{
    const std::string hex {tv::kKeyHex};
    EXPECT_FALSE(JwtKeyDecoder::decode(""));
    EXPECT_FALSE(JwtKeyDecoder::decode(hex.substr(0, 63)));
    EXPECT_FALSE(JwtKeyDecoder::decode(hex + "0"));
    EXPECT_FALSE(JwtKeyDecoder::decode(hex + "00"));
    EXPECT_FALSE(JwtKeyDecoder::decode(hex.substr(0, 32))); // a 16-byte (legacy MD5-shaped) key
    EXPECT_FALSE(JwtKeyDecoder::decode(hex.substr(0, 48))); // 24 bytes
}

TEST(JwtKeyDecoder, RejectsUppercaseAndNonHex)
{
    std::string upper {tv::kKeyHex};
    upper[5] = 'A';
    EXPECT_FALSE(JwtKeyDecoder::decode(upper));

    std::string nonHex {tv::kKeyHex};
    nonHex[10] = 'g';
    EXPECT_FALSE(JwtKeyDecoder::decode(nonHex));

    std::string space {tv::kKeyHex};
    space[63] = ' ';
    EXPECT_FALSE(JwtKeyDecoder::decode(space));

    std::string nul {tv::kKeyHex};
    nul[0] = '\0';
    EXPECT_FALSE(JwtKeyDecoder::decode(nul));
}

TEST(JwtKeyDecoder, AsciiTextIsNotTheKey)
{
    // The 64 ASCII chars are 64 bytes; the key is the 32 decoded bytes. They can never compare equal
    // even in length -- the HMAC-level consequence is pinned in jwtHmacSha256_test.cpp.
    const auto key = JwtKeyDecoder::decode(tv::kKeyHex);
    ASSERT_TRUE(key);
    EXPECT_NE(key->size(), tv::kKeyHex.size());
}
