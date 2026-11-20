/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "uid_text_darwin.hpp"

namespace
{
    bool parses(const std::string& text, uid_t expected)
    {
        uid_t uid = 12345;
        return parseUidText(text, uid) && uid == expected;
    }

    bool rejected(const std::string& text)
    {
        uid_t uid = 12345;
        return !parseUidText(text, uid) && uid == 12345;
    }
}

TEST(UidTextDarwinTest, PlainUidsAreRead)
{
    EXPECT_TRUE(parses("0", 0));
    EXPECT_TRUE(parses("501", 501));
    EXPECT_TRUE(parses("4294967295", 4294967295u));
}

TEST(UidTextDarwinTest, TheSignedFormOfTheSystemAccountsIsRead)
{
    EXPECT_TRUE(parses("-2", 4294967294u));
    EXPECT_TRUE(parses("-2147483648", 2147483648u));
}

TEST(UidTextDarwinTest, ATextThatIsNotWhollyAUidIsRejected)
{
    EXPECT_TRUE(rejected(""));
    EXPECT_TRUE(rejected("abc"));
    EXPECT_TRUE(rejected("4911vr_bad"));
    EXPECT_TRUE(rejected("49 11"));
    EXPECT_TRUE(rejected(" 501"));
    EXPECT_TRUE(rejected("-"));
    EXPECT_TRUE(rejected("+"));
}

TEST(UidTextDarwinTest, ANumberThatDoesNotFitIn32BitsIsRejected)
{
    EXPECT_TRUE(rejected("4294967296"));
    EXPECT_TRUE(rejected("-2147483649"));
    EXPECT_TRUE(rejected("99999999999999999999"));
}
