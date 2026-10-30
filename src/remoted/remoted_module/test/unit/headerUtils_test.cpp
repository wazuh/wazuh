/*
 * Wazuh remoted module - header lookup unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/contentEncoding.hpp"
#include "http_server/headerUtils.hpp"

#include <gtest/gtest.h>

using remoted::http::acceptsEncoding;
using remoted::http::equalsIgnoreCase;
using remoted::http::headerValue;

namespace
{
    // The offer every AcceptsZstdTest case is about; the parser itself is codec-neutral.
    bool acceptsZstd(std::string_view acceptEncoding)
    {
        return acceptsEncoding(acceptEncoding, remoted::common::kZstdContentEncoding);
    }
} // namespace

TEST(HeaderUtilsTest, FindsAnAlreadyLowercaseName)
{
    std::unordered_map<std::string, std::string> headers {{"authorization", "Bearer aaa.bbb.ccc"}};
    EXPECT_EQ(headerValue(headers, "authorization"), "Bearer aaa.bbb.ccc");
}

TEST(HeaderUtilsTest, FindsTheRfcCanonicalMixedCaseName)
{
    // The real-transport case (RestinioHttpServer.cpp's makeHttpRequest()): a well-known field
    // name comes back in its canonical spelling, not lowercased. This is the exact scenario an
    // exact-match find() misses -- see this header's own class comment for the bug it was written
    // to prevent.
    std::unordered_map<std::string, std::string> headers {{"Authorization", "Bearer aaa.bbb.ccc"}};
    EXPECT_EQ(headerValue(headers, "authorization"), "Bearer aaa.bbb.ccc");
}

TEST(HeaderUtilsTest, FindsAnUppercaseName)
{
    std::unordered_map<std::string, std::string> headers {{"AUTHORIZATION", "value"}};
    EXPECT_EQ(headerValue(headers, "authorization"), "value");
}

TEST(HeaderUtilsTest, MissingHeaderReturnsEmpty)
{
    std::unordered_map<std::string, std::string> headers {{"content-type", "application/json"}};
    EXPECT_EQ(headerValue(headers, "authorization"), "");
}

TEST(HeaderUtilsTest, EmptyMapReturnsEmpty)
{
    std::unordered_map<std::string, std::string> headers;
    EXPECT_EQ(headerValue(headers, "authorization"), "");
}

TEST(HeaderUtilsTest, DoesNotMatchADifferentLengthName)
{
    std::unordered_map<std::string, std::string> headers {{"authorization-extra", "value"}};
    EXPECT_EQ(headerValue(headers, "authorization"), "");
}

TEST(AcceptsZstdTest, OffersZstd)
{
    EXPECT_TRUE(acceptsZstd("zstd"));
}

TEST(AcceptsZstdTest, IsCaseInsensitive)
{
    EXPECT_TRUE(acceptsZstd("ZSTD"));
    EXPECT_TRUE(acceptsZstd("Zstd"));
}

TEST(AcceptsZstdTest, FindsZstdAmongOtherCodings)
{
    EXPECT_TRUE(acceptsZstd("gzip, zstd"));
    EXPECT_TRUE(acceptsZstd("zstd,gzip"));
    EXPECT_TRUE(acceptsZstd("  gzip ,\tzstd\t, br"));
}

TEST(AcceptsZstdTest, AbsentOrEmptyIsNotAnOffer)
{
    EXPECT_FALSE(acceptsZstd(""));
    EXPECT_FALSE(acceptsZstd(" "));
    EXPECT_FALSE(acceptsZstd(","));
}

TEST(AcceptsZstdTest, OtherCodingsAreNotAnOffer)
{
    EXPECT_FALSE(acceptsZstd("gzip"));
    EXPECT_FALSE(acceptsZstd("gzip, deflate, br"));
    EXPECT_FALSE(acceptsZstd("identity"));
}

TEST(AcceptsZstdTest, OnlyTheExactTokenCounts)
{
    EXPECT_FALSE(acceptsZstd("zstdx"));
    EXPECT_FALSE(acceptsZstd("xzstd"));
    EXPECT_FALSE(acceptsZstd("zst"));
    EXPECT_FALSE(acceptsZstd("zstd2"));
}

TEST(AcceptsZstdTest, WildcardIsNotInterpreted)
{
    EXPECT_FALSE(acceptsZstd("*"));
    EXPECT_FALSE(acceptsZstd("gzip, *;q=0.5"));
}

TEST(AcceptsZstdTest, HonoursAPositiveWeight)
{
    EXPECT_TRUE(acceptsZstd("zstd;q=1"));
    EXPECT_TRUE(acceptsZstd("zstd;q=1.0"));
    EXPECT_TRUE(acceptsZstd("zstd;q=0.5"));
    EXPECT_TRUE(acceptsZstd("zstd;q=0.001"));
    EXPECT_TRUE(acceptsZstd("gzip;q=0, zstd; q=0.8"));
    EXPECT_TRUE(acceptsZstd("zstd ; Q=0.5"));
}

TEST(AcceptsZstdTest, AZeroWeightRefusesIt)
{
    EXPECT_FALSE(acceptsZstd("zstd;q=0"));
    EXPECT_FALSE(acceptsZstd("zstd;q=0."));
    EXPECT_FALSE(acceptsZstd("zstd;q=0.000"));
    EXPECT_FALSE(acceptsZstd("gzip, zstd;q=0"));
}

TEST(AcceptsZstdTest, AMalformedWeightIsNotAnOffer)
{
    EXPECT_FALSE(acceptsZstd("zstd;q="));
    EXPECT_FALSE(acceptsZstd("zstd;q=abc"));
    EXPECT_FALSE(acceptsZstd("zstd;q=2"));
    EXPECT_FALSE(acceptsZstd("zstd;q=1.5"));
    EXPECT_FALSE(acceptsZstd("zstd;q=0.5555"));
    EXPECT_FALSE(acceptsZstd("zstd;q=-1"));
}

TEST(AcceptsZstdTest, IgnoresParametersThatAreNotAWeight)
{
    EXPECT_TRUE(acceptsZstd("zstd;level=3"));
    EXPECT_TRUE(acceptsZstd("zstd;level=3;q=0.5"));
    EXPECT_FALSE(acceptsZstd("zstd;level=3;q=0"));
}

TEST(AcceptsEncodingTest, WorksForAnyCodingToken)
{
    EXPECT_TRUE(acceptsEncoding("gzip, br", "br"));
    EXPECT_TRUE(acceptsEncoding("BR;q=0.5", "br"));
    EXPECT_FALSE(acceptsEncoding("gzip, br", "zstd"));
    EXPECT_FALSE(acceptsEncoding("br;q=0", "br"));
    EXPECT_FALSE(acceptsEncoding("zstd", ""));
}

TEST(EqualsIgnoreCaseTest, ComparesBothSidesWithoutRegardToCase)
{
    EXPECT_TRUE(equalsIgnoreCase("zstd", "zstd"));
    EXPECT_TRUE(equalsIgnoreCase("ZsTd", "zStD"));
    EXPECT_TRUE(equalsIgnoreCase("", ""));
    EXPECT_FALSE(equalsIgnoreCase("zstd", "zst"));
    EXPECT_FALSE(equalsIgnoreCase("zstd", "zstx"));
}
