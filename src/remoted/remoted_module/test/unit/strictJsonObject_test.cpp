/*
 * Wazuh remoted module - strict JSON pre-parse tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Direct tests of the shared StrictJsonObject (jwt/strictJsonObject.hpp): the exact-set rules the
// profile verifiers rely on, and the input-bounds contract -- every byte the parser touches belongs
// to the text it was given. The truncated multi-byte cases are the regression for the ASAN
// heap-buffer-overflow CI caught in JwtVerify.NeverThrowsOnRandomOrMutatedInput: rapidjson's
// UTF-8 validation consumes continuation bytes without checking for the end of a NUL-terminated
// StringStream, so a decoded segment ending in a lead byte made it read past the std::string.

#include <gtest/gtest.h>

#include "jwt/strictJsonObject.hpp"

#include <array>
#include <string>
#include <string_view>

using jwt_profile::v1::JsonField;
using jwt_profile::v1::StrictJsonObject;

namespace
{
    constexpr std::array<JsonField, 3> kHeaderFields {{{"alg", false}, {"kid", false}, {"typ", false}}};
    constexpr std::array<JsonField, 2> kMixedFields {{{"exp", true}, {"sub", false}}};

    bool parses3(std::string_view json)
    {
        StrictJsonObject<3> out;
        return StrictJsonObject<3>::parse(kHeaderFields, json, out);
    }
    bool parses2(std::string_view json)
    {
        StrictJsonObject<2> out;
        return StrictJsonObject<2>::parse(kMixedFields, json, out);
    }

    // The exact text of a decoded header, as a heap std::string sized to it (beyond the SSO buffer),
    // with `tail` appended: the shape that exposed the over-read.
    std::string headerWithTail(std::string_view tail)
    {
        std::string json = R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt)";
        json.append(tail);
        return json;
    }
} // namespace

TEST(StrictJsonObject, AcceptsExactlyTheAllowlistedObjectAndExposesTheValues)
{
    StrictJsonObject<3> header;
    ASSERT_TRUE(
        StrictJsonObject<3>::parse(kHeaderFields, R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})", header));
    EXPECT_EQ(header.str(0), "HS256");
    EXPECT_EQ(header.str(1), "001");
    EXPECT_EQ(header.str(2), "wazuh-agent+jwt");

    StrictJsonObject<2> mixed;
    ASSERT_TRUE(StrictJsonObject<2>::parse(kMixedFields, R"({"sub":"001","exp":1700000060})", mixed)); // any order
    EXPECT_EQ(mixed.num(0), 1700000060);
    EXPECT_EQ(mixed.str(1), "001");
}

TEST(StrictJsonObject, RejectsMissingExtraDuplicateNestedAndMistypedMembers)
{
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001"})"));                       // missing typ
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001","typ":"t","cty":"JWT"})")); // extra member
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001","typ":"t","typ":"t"})"));   // duplicate
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":{"id":"001"},"typ":"t"})"));      // nested object
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":["001"],"typ":"t"})"));           // array value
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":1,"typ":"t"})"));                 // int where string
    EXPECT_FALSE(parses2(R"({"exp":"1700000060","sub":"001"})"));                  // string where int
    EXPECT_FALSE(parses2(R"({"exp":-1,"sub":"001"})"));                            // negative
    EXPECT_FALSE(parses2(R"({"exp":1.5,"sub":"001"})"));                           // double
    EXPECT_FALSE(parses2(R"({"exp":18446744073709551615,"sub":"001"})"));          // > INT64_MAX
    EXPECT_FALSE(parses2(R"({"exp":null,"sub":"001"})"));
    EXPECT_FALSE(parses3(R"(["HS256","001","t"])"));                     // root array
    EXPECT_FALSE(parses3(R"("HS256")"));                                 // root string
    EXPECT_FALSE(parses3(""));                                           // empty
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001","typ":"t"}{})")); // two roots
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001","typ":"t"} x)")); // trailing garbage
    // (Trailing JSON whitespace is tolerated by the parser, as before; the signature still has to
    // cover those exact bytes, so it buys an attacker nothing.)
}

TEST(StrictJsonObject, RejectsTruncatedMultiByteTailsWithoutReadingPastTheInput)
{
    // Under ASAN this is the regression: a 2-, 3- and 4-byte lead as the LAST byte of the text. Each
    // must be a plain rejection with no read beyond json.size().
    EXPECT_FALSE(parses3(headerWithTail("\xC3")));
    EXPECT_FALSE(parses3(headerWithTail("\xE2\x82")));
    EXPECT_FALSE(parses3(headerWithTail("\xF0")));
    EXPECT_FALSE(parses3(headerWithTail("\xF0\x9F\x98")));
    // ...and the same lead bytes right before the closing quote, where the text is otherwise complete.
    EXPECT_FALSE(parses3(headerWithTail("\xF0\"}")));
    EXPECT_FALSE(parses3(headerWithTail("\xE2\x82\"}")));
}

TEST(StrictJsonObject, RejectsAnyNonAsciiByteIncludingValidUtf8AndABom)
{
    // The profiles' text is ASCII by construction; a well-formed UTF-8 sequence is still not a
    // token of the profile.
    EXPECT_FALSE(parses3(headerWithTail("\xC3\xA9\"}"))); // 'é' inside typ
    EXPECT_FALSE(parses3("\xEF\xBB\xBF"
                         R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})")); // UTF-8 BOM
    EXPECT_FALSE(parses3(R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})"
                         "\xC2\xA0")); // NBSP after
    std::string embeddedNul = R"({"alg":"HS2)";
    embeddedNul.push_back('\0');
    embeddedNul += R"(56","kid":"001","typ":"t"})";
    EXPECT_FALSE(parses3(embeddedNul)); // embedded NUL inside a string value
}

TEST(StrictJsonObject, IsBoundedByTheViewNotByATerminator)
{
    // A view into a larger buffer: what follows the view must be invisible to the parser, whether
    // it is a valid continuation of the JSON or garbage.
    const std::string backing = R"({"alg":"HS256","kid":"001","typ":"t"}garbage that must not be read)";
    const std::string_view exact {backing.data(), backing.find('}') + 1};
    EXPECT_TRUE(parses3(exact));
    EXPECT_FALSE(parses3(std::string_view {backing.data(), exact.size() - 1})); // cut before '}'
}
