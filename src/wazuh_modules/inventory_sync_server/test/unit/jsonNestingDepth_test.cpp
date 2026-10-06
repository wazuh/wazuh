/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/jsonNestingDepth.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string>

using invsync::common::exceedsNestingDepth;
using invsync::common::MAX_JSON_NESTING_DEPTH;

namespace
{
    /// @p depth nested arrays, closed: `[[...]]`.
    std::string nestedArrays(std::size_t depth)
    {
        return std::string(depth, '[') + std::string(depth, ']');
    }
} // namespace

TEST(JsonNestingDepthTest, TheLimitMatchesTheEngine)
{
    // The engine's Json::MAX_DEPTH. Kept equal so the manager has one nesting limit for agent JSON.
    EXPECT_EQ(256U, MAX_JSON_NESTING_DEPTH);
}

TEST(JsonNestingDepthTest, ScalarsAndEmptyTextHaveNoDepth)
{
    for (const auto* text : {"", "42", "true", "null", R"("a string")"})
    {
        EXPECT_FALSE(exceedsNestingDepth(text, 0)) << "text: " << text;
    }
}

TEST(JsonNestingDepthTest, TheRootContainerIsDepthOne)
{
    EXPECT_FALSE(exceedsNestingDepth("{}", 1));
    EXPECT_FALSE(exceedsNestingDepth("[]", 1));
    EXPECT_TRUE(exceedsNestingDepth("{}", 0));
    EXPECT_TRUE(exceedsNestingDepth("[]", 0));
}

TEST(JsonNestingDepthTest, ExactlyTheLimitIsAcceptedAndOneMoreIsNot)
{
    EXPECT_FALSE(exceedsNestingDepth(nestedArrays(MAX_JSON_NESTING_DEPTH)));
    EXPECT_TRUE(exceedsNestingDepth(nestedArrays(MAX_JSON_NESTING_DEPTH + 1)));
}

TEST(JsonNestingDepthTest, ObjectsAndArraysCountAlike)
{
    EXPECT_FALSE(exceedsNestingDepth(R"({"a":[{"b":[]}]})", 4));
    EXPECT_TRUE(exceedsNestingDepth(R"({"a":[{"b":[]}]})", 3));
}

TEST(JsonNestingDepthTest, DepthIsTheMaximumNotTheTotal)
{
    // Many shallow siblings: a running total would reject this, the depth never passes 2.
    std::string text {"["};
    for (int i = 0; i < 1000; ++i)
    {
        text += i == 0 ? "[]" : ",[]";
    }
    text += "]";
    EXPECT_FALSE(exceedsNestingDepth(text, 2));
}

TEST(JsonNestingDepthTest, BracketsInsideStringsAreNotCounted)
{
    const std::string text = R"({"k":")" + std::string(1000, '[') + std::string(1000, '{') + R"("})";
    EXPECT_FALSE(exceedsNestingDepth(text, 1));
}

TEST(JsonNestingDepthTest, AnEscapedQuoteDoesNotEndTheString)
{
    // If \" closed the string, the brackets after it would be counted.
    EXPECT_FALSE(exceedsNestingDepth(R"(["a\"[[[[","b"])", 1));
    // An escaped backslash does end it: the bracket after the closing quote counts.
    EXPECT_TRUE(exceedsNestingDepth(R"(["a\\",[]])", 1));
}

TEST(JsonNestingDepthTest, StrayClosersDoNotBuyExtraDepth)
{
    // Without the floor at zero, leading closers would drive the count negative and hide the opens.
    EXPECT_TRUE(exceedsNestingDepth("]]]]" + nestedArrays(3), 2));
}

TEST(JsonNestingDepthTest, AnAttackSizedBodyIsRejectedAtTheFirstLevelOverTheCap)
{
    // The shape that overflowed nlohmann's recursive dump(): a million levels, under remoted's 5 MiB
    // cap. Unterminated on purpose -- the scan stops at level MAX + 1 and never needs the rest.
    EXPECT_TRUE(exceedsNestingDepth(std::string(1'000'000, '[')));
}
