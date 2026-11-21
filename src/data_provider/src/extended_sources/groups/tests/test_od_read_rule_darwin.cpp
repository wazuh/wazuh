/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "od_read_rule.hpp"

TEST(OdReadRuleDarwinTest, AQueryThatFoundNothingIsTrusted)
{
    EXPECT_TRUE(od::readIsTrusted(0, 0));
}

TEST(OdReadRuleDarwinTest, SomeReadableRecordsAreTrusted)
{
    EXPECT_TRUE(od::readIsTrusted(163, 1));
    EXPECT_TRUE(od::readIsTrusted(163, 163));
}

TEST(OdReadRuleDarwinTest, RecordsOfWhichNoneCouldBeReadAreNotTrusted)
{
    EXPECT_FALSE(od::readIsTrusted(163, 0));
}
