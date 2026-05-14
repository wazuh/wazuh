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

#include "timeHelper_test.h"
#include "timeHelper.h"
#include <regex>

void TimeUtilsTest::SetUp() {};

void TimeUtilsTest::TearDown() {};

TEST_F(TimeUtilsTest, CheckTimestamp)
{
    const auto currentTimestamp {Utils::getCurrentTimestamp()};
    const auto timestamp {Utils::getTimestamp(std::time(nullptr))};
    EXPECT_FALSE(currentTimestamp.empty());
    EXPECT_FALSE(timestamp.empty());
}

TEST_F(TimeUtilsTest, CheckTimestampValidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR {
        "[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2}) (([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2})"};
    const auto currentTimestamp {Utils::getCurrentTimestamp()};
    const auto timestamp {Utils::getTimestamp(std::time(nullptr))};
    EXPECT_TRUE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR)));
    EXPECT_TRUE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, CheckTimestampInvalidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR {
        "[0-9]{4}/([1-9]|1[0-2])/([1-9]|[1-2][0-9]|3[0-1])(2[0-3]|1[0-9]|[0-9]):([0-9]|[1-5][0-9]):([1-5][0-9]|[0-9])"};
    const auto currentTimestamp {Utils::getCurrentTimestamp()};
    const auto timestamp {Utils::getTimestamp(std::time(nullptr))};
    EXPECT_FALSE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR)));
    EXPECT_FALSE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, CheckTimestampError)
{
    constexpr auto DATE_FORMAT_REGEX_STR {
        "[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2}) (([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2})"};
    const auto timestamp {Utils::getTimestamp(72057594037927936)};
    EXPECT_EQ("1970/01/01 00:00:00", timestamp);
    EXPECT_TRUE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, CheckCompactTimestampValidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR {
        "[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2}) (([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2}):(([0-9]|1[0-2]){2})"};
    constexpr auto COMPACT_FORMAT_REGEX_STR {
        "[0-9]{4}([0-9]|1[0-2]){2}(([0-9]|1[0-2]){2})(([0-9]|1[0-2]){2})(([0-9]|1[0-2]){2})(([0-9]|1[0-2]){2})"};
    const auto currentTimestamp {Utils::getCurrentTimestamp()};
    const auto timestamp {Utils::getCompactTimestamp(std::time(nullptr))};
    EXPECT_TRUE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR))) << timestamp;
    EXPECT_TRUE(std::regex_match(timestamp, std::regex(COMPACT_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, CheckCompactTimestampInvalidFormat)
{
    constexpr auto DATE_FORMAT_REGEX_STR {
        "[0-9]{4}/([1-9]|1[0-2])/([1-9]|[1-2][0-9]|3[0-1])(2[0-3]|1[0-9]|[0-9]):([0-9]|[1-5][0-9]):([1-5][0-9]|[0-9])"};
    const auto currentTimestamp {Utils::getCurrentTimestamp()};
    const auto timestamp {Utils::getCompactTimestamp(std::time(nullptr))};
    EXPECT_FALSE(std::regex_match(currentTimestamp, std::regex(DATE_FORMAT_REGEX_STR)));
    EXPECT_FALSE(std::regex_match(timestamp, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST_F(TimeUtilsTest, TimestampToISO8601)
{
    // Get timestamp in local time
    const auto timestamp {Utils::getTimestamp(std::time(nullptr), false)};
    // Get current ISO8601 timestamp in UTC
    const auto currentISO8601 {Utils::getCurrentISO8601()};
    // replace milliseconds to 000Z to align with timestamp format
    const auto currentISO8601ZeroMs {currentISO8601.substr(0, currentISO8601.size() - 4) + "000Z"};

    EXPECT_EQ(currentISO8601ZeroMs, Utils::timestampToISO8601(timestamp));
    EXPECT_EQ("", Utils::timestampToISO8601("21:00:00"));

    // Additional cases
    EXPECT_EQ("2025-12-01T18:25:40.000Z", Utils::timestampToISO8601("2025/12/01 18:25:40"));
    EXPECT_EQ("2025-06-30T18:29:50.000Z", Utils::timestampToISO8601("2025/06/30 18:29:50"));
}

TEST_F(TimeUtilsTest, RawTimestampToISO8601)
{
    EXPECT_EQ("2020-11-13T01:54:25.000Z", Utils::rawTimestampToISO8601(std::string("1605232465")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("abcdefg")));

    EXPECT_EQ("2020-11-13T01:54:25.000Z", Utils::rawTimestampToISO8601(std::string_view("1605232465")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("abcdefg")));

    EXPECT_EQ("2020-11-13T01:54:25.000Z", Utils::rawTimestampToISO8601(static_cast<uint32_t>(1605232465)));

    EXPECT_EQ("2020-11-13T01:54:25.665Z", Utils::rawTimestampToISO8601(1605232465.6655));
    EXPECT_EQ("2020-11-13T01:54:25.665Z", Utils::rawTimestampToISO8601(1605232465.665));
    EXPECT_EQ("2020-11-13T01:54:25.660Z", Utils::rawTimestampToISO8601(1605232465.66));
    EXPECT_EQ("2020-11-13T01:54:25.060Z", Utils::rawTimestampToISO8601(1605232465.06));
    EXPECT_EQ("2020-11-13T01:54:25.040Z", Utils::rawTimestampToISO8601(1605232465.04));
    EXPECT_EQ("2020-11-13T01:54:25.120Z", Utils::rawTimestampToISO8601(1605232465.120));

    // Test conversion from "YYYY/MM/DD hh:mm:ss" format - result depends on system timezone
    // Just verify it returns valid ISO8601 format
    auto result1 = Utils::rawTimestampToISO8601(std::string("2025/12/01 18:25:40"));
    EXPECT_FALSE(result1.empty());
    EXPECT_EQ(24u, result1.size());
    EXPECT_EQ('Z', result1.back());

    auto result2 = Utils::rawTimestampToISO8601(std::string("2025/06/30 18:29:50"));
    EXPECT_FALSE(result2.empty());
    EXPECT_EQ(24u, result2.size());
    EXPECT_EQ('Z', result2.back());

    // Test already-formatted ISO8601 strings pass through correctly
    EXPECT_EQ("2025-11-26T12:00:01.000Z", Utils::rawTimestampToISO8601(std::string("2025-11-26T12:00:01Z")));
    EXPECT_EQ("2024-11-14T18:32:28.000Z", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28Z")));
    EXPECT_EQ("2025-11-26T12:00:01.000Z", Utils::rawTimestampToISO8601(std::string("2025-11-26T12:00:01.000Z")));
    EXPECT_EQ("2024-11-14T18:32:28.005Z", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28.005Z")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28ZABC")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28.005ZABC")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28.0052Z")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string("2024-11-14T18:32:28.005A")));

    // Test conversion from "YYYY/MM/DD hh:mm:ss" format with string_view - result depends on system timezone
    auto result3 = Utils::rawTimestampToISO8601(std::string_view("2025/12/01 18:25:40"));
    EXPECT_FALSE(result3.empty());
    EXPECT_EQ(24u, result3.size());
    EXPECT_EQ('Z', result3.back());

    auto result4 = Utils::rawTimestampToISO8601(std::string_view("2025/06/30 18:29:50"));
    EXPECT_FALSE(result4.empty());
    EXPECT_EQ(24u, result4.size());
    EXPECT_EQ('Z', result4.back());
    // Test already-formatted ISO8601 strings pass through correctly with string_view
    EXPECT_EQ("2025-11-26T12:00:01.000Z", Utils::rawTimestampToISO8601(std::string_view("2025-11-26T12:00:01Z")));
    EXPECT_EQ("2024-11-14T18:32:28.000Z", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28Z")));
    EXPECT_EQ("2025-11-26T12:00:01.000Z", Utils::rawTimestampToISO8601(std::string_view("2025-11-26T12:00:01.000Z")));
    EXPECT_EQ("2024-11-14T18:32:28.005Z", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28.005Z")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28ZABC")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28.005ZABC")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28.0052Z")));
    EXPECT_EQ("", Utils::rawTimestampToISO8601(std::string_view("2024-11-14T18:32:28.005A")));
}
