/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <regex>
#include "timeHelper_test.h"
#include "timeHelper.h"

void TimeUtilsTest::SetUp() {};

void TimeUtilsTest::TearDown() {};

TEST_F(TimeUtilsTest, CheckTimestamp)
{
    const auto currentTimestamp { Utils::getCurrentTimestamp() };
    const auto timestamp { Utils::getTimestamp(std::time(nullptr)) };
    EXPECT_FALSE(currentTimestamp.empty());
    EXPECT_FALSE(timestamp.empty());
}

TEST_F(TimeUtilsTest, CheckTimestampValidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR { "[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2}) (([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2})" };
    const auto currentTimestamp { Utils::getCurrentTimestamp() };
    const auto timestamp { Utils::getTimestamp(std::time(nullptr)) };
    EXPECT_TRUE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR)));
    EXPECT_TRUE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, CheckTimestampInvalidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR { "[0-9]{4}/([1-9]|1[0-2])/([1-9]|[1-2][0-9]|3[0-1])(2[0-3]|1[0-9]|[0-9]):([0-9]|[1-5][0-9]):([1-5][0-9]|[0-9])" };
    const auto currentTimestamp { Utils::getCurrentTimestamp() };
    const auto timestamp { Utils::getTimestamp(std::time(nullptr)) };
    EXPECT_FALSE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR)));
    EXPECT_FALSE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}
