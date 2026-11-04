/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "headerField.hpp"

#include <gtest/gtest.h>

#include <string>

TEST(HeaderFieldTest, ReadsTheValueOfTheNamedFieldInAnyCase)
{
    for (const auto* line :
            {"Retry-After: 30\r\n", "retry-after: 30\r\n", "RETRY-AFTER: 30\r\n"
            })
    {
        const auto value = headerValue(line, "Retry-After");
        ASSERT_TRUE(value.has_value()) << line;
        EXPECT_EQ(" 30\r\n", *value) << line;
    }
}

// The callers parse the value themselves (strtol, curl_getdate(), the coding list), so it comes
// back untouched.
TEST(HeaderFieldTest, KeepsTheValueAsItCame)
{
    EXPECT_EQ("\t zstd , gzip\r\n", headerValue("Content-Encoding:\t zstd , gzip\r\n", "Content-Encoding"));
    EXPECT_EQ("x", headerValue("Date:x", "Date"));
}

// Only the whole name followed by its colon is the field.
TEST(HeaderFieldTest, AnotherFieldIsNotIt)
{
    for (const auto* line :
            {"Dates: x\r\n", "Date-Header: x\r\n", "Date : x\r\n", "Date x\r\n", "XDate: x\r\n", "Da", ""
            })
    {
        EXPECT_FALSE(headerValue(line, "Date").has_value()) << line;
    }
}

TEST(HeaderFieldTest, ALineThatEndsAtTheColonHasNoValue)
{
    EXPECT_FALSE(headerValue("Date:", "Date").has_value());
    EXPECT_TRUE(headerValue("Date:\n", "Date").has_value());
}

TEST(HeaderFieldTest, TokensCompareIgnoringAsciiCaseOnly)
{
    EXPECT_TRUE(sameToken("zstd", "ZStd"));
    EXPECT_TRUE(sameToken("", ""));
    EXPECT_FALSE(sameToken("zstd", "zst"));
    EXPECT_FALSE(sameToken("zstd", "zstd "));
    EXPECT_FALSE(sameToken("\xc3\xa9", "\xc3\x89")); // "é" and "É" in UTF-8: not ASCII case.
}
