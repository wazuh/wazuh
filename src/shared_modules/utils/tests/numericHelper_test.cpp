/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "numericHelper_test.h"
#include "numericHelper.h"

void NumericUtilsTest::SetUp() {};

void NumericUtilsTest::TearDown() {};

TEST_F(NumericUtilsTest, floatToDoubleRound)
{
    EXPECT_DOUBLE_EQ(0.0, Utils::floatToDoubleRound(0.0f, 1));
    EXPECT_DOUBLE_EQ(0.0, Utils::floatToDoubleRound(0.0f, 2));
    EXPECT_DOUBLE_EQ(1.0, Utils::floatToDoubleRound(1.0f, 1));
    EXPECT_DOUBLE_EQ(1.0, Utils::floatToDoubleRound(1.0f, 2));
    EXPECT_DOUBLE_EQ(1.1, Utils::floatToDoubleRound(1.1f, 1));
    EXPECT_DOUBLE_EQ(1.1, Utils::floatToDoubleRound(1.1f, 2));
    EXPECT_DOUBLE_EQ(4.3, Utils::floatToDoubleRound(4.3f, 1));
    EXPECT_DOUBLE_EQ(4.3, Utils::floatToDoubleRound(4.3f, 2));
    EXPECT_DOUBLE_EQ(7.9, Utils::floatToDoubleRound(7.9f, 2));
    EXPECT_DOUBLE_EQ(7.99, Utils::floatToDoubleRound(7.99f, 2));
    EXPECT_DOUBLE_EQ(8.0, Utils::floatToDoubleRound(7.999f, 2));
    EXPECT_DOUBLE_EQ(7.0, Utils::floatToDoubleRound(7.001f, 2));
}
