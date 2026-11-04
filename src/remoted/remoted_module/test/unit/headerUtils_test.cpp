/*
 * Wazuh remoted module - header lookup unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/headerUtils.hpp"

#include <gtest/gtest.h>

using remoted::http::acceptsZstd;
using remoted::http::headerValue;

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

TEST(HeaderUtilsTest, AcceptsZstdWhenItIsOffered)
{
    for (const std::string value : {"zstd",
                                    "zstd;",
                                    "zstd;q=0.5;",
                                    "ZSTD",
                                    "Zstd",
                                    "gzip, zstd",
                                    "zstd, gzip",
                                    "gzip,zstd",
                                    "zstd;q=1",
                                    "zstd;q=1.000",
                                    "zstd;q=0.5",
                                    "zstd;Q=0.5",
                                    "zstd; q=0.5",
                                    "zstd ;q=0.5",
                                    "gzip,,zstd",
                                    "gzip;x=1, zstd",
                                    ", zstd",
                                    "\tzstd\t"})
    {
        SCOPED_TRACE(value);
        EXPECT_TRUE(acceptsZstd(value));
    }
}

TEST(HeaderUtilsTest, DoesNotAcceptZstdWhenItIsNotOffered)
{
    for (const std::string value : {"",
                                    "gzip",
                                    "identity",
                                    "*",
                                    "zstdx",
                                    "xzstd",
                                    "zstd;q=0",
                                    "zstd;q=0.000",
                                    "zstd;q=x",
                                    "zstd;q=.5",
                                    "zstd;q=1.5",
                                    "zstd;q=0.0001",
                                    "zstd;q=-1",
                                    "zstd;x=1",
                                    "zstd;q=0.5;q=0.5",
                                    "zstd;q= 0.5",
                                    "zstd;q=0, zstd",
                                    "zstd, zstd;x=1",
                                    "zstd;q=x, zstd",
                                    "zstd;q=2.5",
                                    "zstd;q=",
                                    "zstd, zstd;q=0",
                                    "gzip;q=0.5, identity"})
    {
        SCOPED_TRACE(value);
        EXPECT_FALSE(acceptsZstd(value));
    }
}

TEST(HeaderUtilsTest, AValueAtTheTransportLimitIsHandled)
{
    std::string offered;
    while (offered.size() + 5 + 4 <= 8192)
    {
        offered += "gzip,";
    }
    offered.append(8192 - 4 - offered.size(), ' ');
    offered += "zstd";
    ASSERT_EQ(offered.size(), 8192U);

    EXPECT_NO_THROW(EXPECT_TRUE(acceptsZstd(offered)));
    EXPECT_NO_THROW(EXPECT_FALSE(acceptsZstd(std::string(8192, 'a'))));
}

TEST(HeaderUtilsTest, TwoSpellingsOfTheHeaderGiveOneOfTheTwoAnswers)
{
    // Which spelling headerValue() returns depends on the map's iteration order.
    std::unordered_map<std::string, std::string> headers {{"Accept-Encoding", "gzip"}, {"accept-encoding", "zstd"}};

    const auto value = headerValue(headers, "accept-encoding");
    EXPECT_TRUE(value == "gzip" || value == "zstd");
    EXPECT_EQ(acceptsZstd(value), value == "zstd");
}
