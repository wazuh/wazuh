/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Agoust 11, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "globHelper_test.h"
#include "globHelper.h"
#include <sstream>

void GlobHelperTest::SetUp() {};

void GlobHelperTest::TearDown() {};

TEST_F(GlobHelperTest, patternMatchSimple)
{
    EXPECT_TRUE(Utils::patternMatch("test", "test"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcard)
{
    EXPECT_TRUE(Utils::patternMatch("test", "te*t"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtEnd)
{
    EXPECT_TRUE(Utils::patternMatch("test", "te*"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtStart)
{
    EXPECT_TRUE(Utils::patternMatch("test", "*st"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtStartAndEnd)
{
    EXPECT_TRUE(Utils::patternMatch("test", "*st*"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtStartAndEndAndMiddle)
{
    EXPECT_TRUE(Utils::patternMatch("test", "*s*t*"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtStartAndEndAndMiddleAndNoMatch)
{
    EXPECT_TRUE(Utils::patternMatch("test", "*s*t"));
}

TEST_F(GlobHelperTest, patternMatchSimpleWithWildcardAtStartAndEndAndMiddleAndNoMatch2)
{
    EXPECT_FALSE(Utils::patternMatch("test", "s*t*"));
}

TEST_F(GlobHelperTest, patternMatchWithWildcard2Characters)
{
    EXPECT_TRUE(Utils::patternMatch("test", "t*t"));
}

TEST_F(GlobHelperTest, patternMatchWithInvalidPostfix)
{
    EXPECT_FALSE(Utils::patternMatch("12", "*t"));
}

TEST_F(GlobHelperTest, patternMatchWithInvalidPostfix2)
{
    EXPECT_FALSE(Utils::patternMatch("12", "*t*"));
}

TEST_F(GlobHelperTest, patternMatchWithInvalidPrefix)
{
    EXPECT_FALSE(Utils::patternMatch("12", "t*"));
}

TEST_F(GlobHelperTest, patternMatchWithInvalidPrefix2)
{
    EXPECT_FALSE(Utils::patternMatch("13", "*t*"));
}

TEST_F(GlobHelperTest, patternMatchWithDimension)
{
    EXPECT_FALSE(Utils::patternMatch("13", "131111111111111111"));
}

TEST_F(GlobHelperTest, patternMatchWithDimension2)
{
    EXPECT_FALSE(Utils::patternMatch("111111111111111111", "11"));
}

TEST_F(GlobHelperTest, patternMatchWithDimension3)
{
    EXPECT_FALSE(Utils::patternMatch("11", "111111111111111111"));
}

TEST_F(GlobHelperTest, patternMatchAll)
{
    EXPECT_TRUE(Utils::patternMatch("abcdef", "*"));
}

TEST_F(GlobHelperTest, patternMatchSingleCharacter)
{
    EXPECT_TRUE(Utils::patternMatch("abcdef", "a?c*"));
}

TEST_F(GlobHelperTest, patternMatchSingleCharacter2)
{
    EXPECT_FALSE(Utils::patternMatch("abcdef", "a?c"));
}

TEST_F(GlobHelperTest, patternMatchSingleCharacter3)
{
    EXPECT_TRUE(Utils::patternMatch("abcd", "a?c?"));
}
