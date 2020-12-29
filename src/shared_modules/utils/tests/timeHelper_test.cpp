/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "timeHelper_test.h"
#include "timeHelper.h"

void TimeUtilsTest::SetUp() {};

void TimeUtilsTest::TearDown() {};

TEST_F(TimeUtilsTest, CheckTimestamp) 
{
    const auto timestamp { Utils::getTimestamp(std::time(nullptr)) };
    EXPECT_FALSE(timestamp.empty());
}
