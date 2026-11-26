/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "directory_keys_darwin.hpp"

using ::testing::ElementsAre;

TEST(DirectoryKeysDarwinTest, AccountNamesFoldToLowerCase)
{
    EXPECT_EQ(DirectoryKeys::name("Bob.Smith_2"), "bob.smith_2");
}

TEST(DirectoryKeysDarwinTest, GuidsFoldToUpperCase)
{
    EXPECT_EQ(DirectoryKeys::guid("abcdefab-cdef-abcd-efab-cdef0000000c"), "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C");
}

TEST(DirectoryKeysDarwinTest, OnlyAsciiLettersAreFolded)
{
    // "É" in UTF-8 is two bytes above 0x7f, which tolower() leaves as they are.
    EXPECT_EQ(DirectoryKeys::name("\xC3\x89lise"), "\xC3\x89lise");
}

TEST(DirectoryKeysDarwinTest, SetsFoldEveryValueAndMergeTheOnesThatMeet)
{
    EXPECT_THAT(DirectoryKeys::names({"Bob", "bob", "ALICE"}), ElementsAre("alice", "bob"));
    EXPECT_THAT(DirectoryKeys::guids({"ab-1", "AB-1"}), ElementsAre("AB-1"));
}

TEST(DirectoryKeysDarwinTest, MapKeysFoldAndTheLastKeyInOrderWins)
{
    // "Bob" sorts before "bob", so the value of "bob" is the one kept.
    const auto folded = DirectoryKeys::byName({{"Bob", "first"}, {"bob", "second"}, {"Carol", "third"}});

    ASSERT_EQ(folded.size(), 2u);
    EXPECT_EQ(folded.at("bob"), "second");
    EXPECT_EQ(folded.at("carol"), "third");
}
