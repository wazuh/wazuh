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

// Profile constants, TimePolicy (fail-fast ranges), CanonicalAgentId (grammar pinned to what
// remoted's keystore/authMiddleware accept today), SecureBytes and the base64url helpers.
#include <gtest/gtest.h>

#include "jwt/base64Url.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/secureBytes.hpp"

#include <cstring>
#include <type_traits>

using namespace jwt_profile::v1;

TEST(JwtProfileTypes, ProfileConstantsArePinned)
{
    EXPECT_EQ(kTyp, "wazuh-agent+jwt");
    EXPECT_EQ(kAlg, "HS256");
    EXPECT_EQ(kIssuerPrefix, "wazuh-agent/");
    EXPECT_EQ(kKeyBytes, 32u);
    EXPECT_EQ(kKeyHexChars, 64u);
    EXPECT_EQ(kJtiBytes, 16u);
    EXPECT_EQ(kJtiChars, 22u);
    EXPECT_EQ(kMaxTokenBytes, 4096u);
    EXPECT_EQ(kLifetimeSec, 60);
    EXPECT_EQ(kMaxAgeSec, 43200);
    EXPECT_EQ(kMaxClockSkewSec, 43200);
    EXPECT_EQ(kDefaultAgeSec, 60);
    EXPECT_EQ(kDefaultClockSkewSec, 30);
}

TEST(JwtProfileTypes, TimePolicyDefaultsToProfileDefaults)
{
    constexpr TimePolicy policy;
    EXPECT_EQ(policy.maxAgeSec(), 60);
    EXPECT_EQ(policy.skewSec(), 30);
}

TEST(JwtProfileTypes, TimePolicyAcceptsTheWholeRangeAndNothingElse)
{
    EXPECT_NO_THROW(TimePolicy(1, 0));
    EXPECT_NO_THROW(TimePolicy(43200, 43200));
    const TimePolicy lowered {10, 5};
    EXPECT_EQ(lowered.maxAgeSec(), 10);
    EXPECT_EQ(lowered.skewSec(), 5);

    EXPECT_THROW(TimePolicy(0, 0), std::invalid_argument);
    EXPECT_THROW(TimePolicy(43201, 0), std::invalid_argument);
    EXPECT_THROW(TimePolicy(-1, 0), std::invalid_argument);
    EXPECT_THROW(TimePolicy(60, -1), std::invalid_argument);
    EXPECT_THROW(TimePolicy(60, 43201), std::invalid_argument);

    EXPECT_TRUE(TimePolicy::tryMake(43200, 43200).has_value());
    EXPECT_FALSE(TimePolicy::tryMake(0, 30).has_value());
    EXPECT_FALSE(TimePolicy::tryMake(60, 43201).has_value());
}

TEST(JwtProfileTypes, CanonicalAgentIdParsesDigitsAndPadsToThree)
{
    const auto one = CanonicalAgentId::parse("1");
    ASSERT_TRUE(one);
    EXPECT_EQ(one->text(), "001");
    EXPECT_EQ(one->numeric(), 1u);

    const auto padded = CanonicalAgentId::parse("0001");
    ASSERT_TRUE(padded);
    EXPECT_EQ(padded->text(), "001");
    EXPECT_EQ(*padded, *one);

    const auto wide = CanonicalAgentId::parse("12345");
    ASSERT_TRUE(wide);
    EXPECT_EQ(wide->text(), "12345");
    EXPECT_NE(*wide, *one);

    const auto max = CanonicalAgentId::parse("4294967295");
    ASSERT_TRUE(max);
    EXPECT_EQ(max->text(), "4294967295");

    EXPECT_EQ(CanonicalAgentId::fromNumeric(7).text(), "007");
    EXPECT_EQ(CanonicalAgentId::fromNumeric(0).text(), "000");
}

TEST(JwtProfileTypes, CanonicalAgentIdRejectsEverythingButDigits)
{
    for (const char* bad : {"",
                            " 1",
                            "1 ",
                            "+1",
                            "-1",
                            "00a",
                            "1.0",
                            "0x1",
                            "1/../2",
                            "١",            // non-ASCII digit
                            "4294967296",   // uint32 overflow
                            "99999999999"}) // > kMaxDigits
    {
        EXPECT_FALSE(CanonicalAgentId::parse(bad)) << '"' << bad << '"';
    }
}

TEST(JwtProfileTypes, ParseCanonicalRequiresTheExactCanonicalText)
{
    EXPECT_TRUE(CanonicalAgentId::parseCanonical("001"));
    EXPECT_TRUE(CanonicalAgentId::parseCanonical("12345"));
    EXPECT_FALSE(CanonicalAgentId::parseCanonical("1"));
    EXPECT_FALSE(CanonicalAgentId::parseCanonical("0001"));
    EXPECT_FALSE(CanonicalAgentId::parseCanonical("012345"));
    EXPECT_FALSE(CanonicalAgentId::parseCanonical(""));
}

TEST(JwtProfileTypes, SecureBytesIsMoveOnlyAndWipes)
{
    static_assert(!std::is_copy_constructible_v<SecureBytes>);
    static_assert(!std::is_copy_assignable_v<SecureBytes>);
    static_assert(std::is_nothrow_move_constructible_v<SecureBytes>);

    const std::uint8_t raw[] = {0x00, 0x01, 0xff};
    SecureBytes a {raw, sizeof(raw)};
    ASSERT_EQ(a.size(), 3u);
    EXPECT_EQ(std::memcmp(a.data(), raw, 3), 0);

    SecureBytes b {std::move(a)};
    EXPECT_TRUE(a.empty()); // NOLINT(bugprone-use-after-move): pinned post-move state
    ASSERT_EQ(b.size(), 3u);
    EXPECT_EQ(b.data()[2], 0xff);

    SecureBytes c {8};
    EXPECT_EQ(c.size(), 8u);
    c = std::move(b);
    EXPECT_TRUE(b.empty()); // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(c.size(), 3u);

    c.wipe();
    EXPECT_TRUE(c.empty());
    c.wipe(); // idempotent
    EXPECT_TRUE(c.empty());
}

TEST(JwtProfileTypes, Base64UrlEncodeIsUnpaddedUrlSafe)
{
    EXPECT_EQ(base64UrlEncode(""), "");
    EXPECT_EQ(base64UrlEncode("a"), "YQ");
    EXPECT_EQ(base64UrlEncode("ab"), "YWI");
    EXPECT_EQ(base64UrlEncode("abc"), "YWJj");
    const std::uint8_t urlSafe[] = {0xfb, 0xff, 0xbf};
    EXPECT_EQ(base64UrlEncode(urlSafe, sizeof(urlSafe)), "-_-_");
}

TEST(JwtProfileTypes, CanonicalBase64UrlCheckRejectsPaddingAlphabetLengthAndDirtyBits)
{
    EXPECT_TRUE(isCanonicalBase64UrlOf("YQ", 1));
    EXPECT_TRUE(isCanonicalBase64UrlOf("YWI", 2));
    EXPECT_TRUE(isCanonicalBase64UrlOf("YWJj", 3));
    EXPECT_TRUE(isCanonicalBase64UrlOf("", 0));
    EXPECT_TRUE(isCanonicalBase64UrlOf("AAECAwQFBgcICQoLDA0ODw", 16));

    EXPECT_FALSE(isCanonicalBase64UrlOf("YR", 1));   // trailing bits not zero
    EXPECT_FALSE(isCanonicalBase64UrlOf("YWJ", 2));  // trailing bits not zero
    EXPECT_FALSE(isCanonicalBase64UrlOf("YQ==", 1)); // padding
    EXPECT_FALSE(isCanonicalBase64UrlOf("YQ", 2));   // wrong length for the byte count
    EXPECT_FALSE(isCanonicalBase64UrlOf("+/8", 2));  // standard alphabet
    EXPECT_FALSE(isCanonicalBase64UrlOf("YQ%3d%3d", 1));
    EXPECT_FALSE(isBase64UrlAlphabet("abc="));
    EXPECT_FALSE(isBase64UrlAlphabet("a b"));
}

TEST(JwtProfileTypes, Base64UrlDecodeCanonicalRoundTripsAndRejectsNonCanonicalText)
{
    ASSERT_TRUE(base64UrlDecodeCanonical(""));
    EXPECT_EQ(*base64UrlDecodeCanonical(""), "");
    EXPECT_EQ(*base64UrlDecodeCanonical("YQ"), "a");
    EXPECT_EQ(*base64UrlDecodeCanonical("YWI"), "ab");
    EXPECT_EQ(*base64UrlDecodeCanonical("YWJj"), "abc");
    EXPECT_EQ(*base64UrlDecodeCanonical("YWJjZA"), "abcd");
    const auto urlSafe = base64UrlDecodeCanonical("-_-_");
    ASSERT_TRUE(urlSafe);
    EXPECT_EQ(*urlSafe, std::string("\xfb\xff\xbf", 3));

    EXPECT_FALSE(base64UrlDecodeCanonical("YR"));       // dirty trailing bits
    EXPECT_FALSE(base64UrlDecodeCanonical("YWJ"));      // dirty trailing bits
    EXPECT_FALSE(base64UrlDecodeCanonical("Y"));        // len % 4 == 1
    EXPECT_FALSE(base64UrlDecodeCanonical("YQ=="));     // padding
    EXPECT_FALSE(base64UrlDecodeCanonical("YQ%3d%3d")); // percent fill
    EXPECT_FALSE(base64UrlDecodeCanonical("+/8"));      // standard alphabet
    EXPECT_FALSE(base64UrlDecodeCanonical("YW Jj"));    // whitespace

    // Every byte string round-trips through encode -> decode, including the whole byte range.
    std::string all;
    for (int i = 0; i < 256; ++i)
    {
        all += static_cast<char>(i);
    }
    for (std::size_t len = 0; len <= all.size(); len += 37)
    {
        const std::string in = all.substr(0, len);
        const auto enc = base64UrlEncode(in);
        EXPECT_TRUE(isCanonicalBase64UrlOf(enc, in.size()));
        const auto dec = base64UrlDecodeCanonical(enc);
        ASSERT_TRUE(dec) << enc;
        EXPECT_EQ(*dec, in);
    }
    EXPECT_EQ(base64UrlDecodedSize(0), 0u);
    EXPECT_EQ(base64UrlDecodedSize(2), 1u);
    EXPECT_EQ(base64UrlDecodedSize(3), 2u);
    EXPECT_EQ(base64UrlDecodedSize(4), 3u);
    EXPECT_EQ(base64UrlDecodedSize(43), 32u);
    EXPECT_EQ(base64UrlDecodedSize(22), 16u);
}
