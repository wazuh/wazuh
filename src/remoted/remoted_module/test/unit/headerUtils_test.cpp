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

using remoted::http::findHeader;
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

TEST(HeaderUtilsTest, FindHeaderTellsAnEmptyValueFromAnAbsentHeader)
{
    // `Content-Encoding:` sent with no value is still a header (answered 415), unlike no header at all.
    std::unordered_map<std::string, std::string> headers {{"Content-Encoding", ""}};
    const auto present = findHeader(headers, "content-encoding");
    ASSERT_TRUE(present.has_value());
    EXPECT_EQ(*present, "");
    EXPECT_FALSE(findHeader(headers, "authorization").has_value());
    EXPECT_EQ(headerValue(headers, "content-encoding"), "");
}
