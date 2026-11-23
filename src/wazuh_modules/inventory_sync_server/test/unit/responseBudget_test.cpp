/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/responseBudget.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <unordered_map>

using namespace std::chrono_literals;
using invsync::common::margin;
using invsync::common::overran;
using invsync::common::parseBudget;
using invsync::common::refuse;
using invsync::common::responseBudgetHeader;
using invsync::common::stampDeadline;

TEST(ResponseBudget, ParsesOnlyPositiveDigitRuns)
{
    EXPECT_EQ(20000ms, parseBudget("20000"));
    // Everything that is not a plain positive digit run is "no budget", never a guess: the session
    // must then behave exactly as it did before this header existed.
    EXPECT_EQ(std::nullopt, parseBudget("abc"));
    EXPECT_EQ(std::nullopt, parseBudget("-1"));
    EXPECT_EQ(std::nullopt, parseBudget("0"));
    EXPECT_EQ(std::nullopt, parseBudget("1e3"));
    EXPECT_EQ(std::nullopt, parseBudget(" 5"));
    EXPECT_EQ(std::nullopt, parseBudget(""));
    EXPECT_EQ(std::nullopt, parseBudget("999999999999"));         // 12 digits
    EXPECT_EQ(std::nullopt, parseBudget("99999999999999999999")); // 20 digits: would overflow a naive parse
}

TEST(ResponseBudget, NineDigitsIsTheLimit)
{
    // The ceiling is what makes overflow impossible without a wider type, so it is pinned exactly.
    EXPECT_EQ(999999999ms, parseBudget("999999999"));   // 9 digits
    EXPECT_EQ(std::nullopt, parseBudget("1000000000")); // 10
}

TEST(ResponseBudget, StampDeadlineAnchorsTheBudgetToNow)
{
    const auto now = std::chrono::steady_clock::now();
    const std::unordered_map<std::string, std::string> headers {{responseBudgetHeader(), "20000"}};

    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::chrono::milliseconds budget {0};
    EXPECT_TRUE(stampDeadline(headers, now, deadline, budget));

    ASSERT_TRUE(deadline.has_value());
    EXPECT_EQ(now + 20s, *deadline);
    EXPECT_EQ(20000ms, budget);
}

TEST(ResponseBudget, StampDeadlineLeavesNoDeadlineWithoutAReadableHeader)
{
    const auto now = std::chrono::steady_clock::now();
    const auto stamp = [&now](const std::unordered_map<std::string, std::string>& headers)
    {
        std::optional<std::chrono::steady_clock::time_point> deadline;
        std::chrono::milliseconds budget {0};
        const bool stamped = stampDeadline(headers, now, deadline, budget);
        EXPECT_FALSE(deadline.has_value());
        EXPECT_EQ(0ms, budget);
        return stamped;
    };

    EXPECT_FALSE(stamp({}));
    EXPECT_FALSE(stamp({{responseBudgetHeader(), "abc"}}));
    // A READABLE value under the name as remoted spells it on the wire: the transport lower-cases
    // header names, so looking it up with anything but the lower-case constant finds nothing. With
    // an unreadable value this case would pass either way and pin nothing.
    EXPECT_FALSE(stamp({{"X-Wazuh-Response-Budget-Ms", "20000"}}));
}

TEST(ResponseBudget, MarginIsOneSecondOrHalfTheBudget)
{
    EXPECT_EQ(1000ms, margin(20000ms)); // the default budget: the full second
    EXPECT_EQ(500ms, margin(1000ms));   // a 1 s response timeout is legal; a flat second would refuse everything
    EXPECT_EQ(0ms, margin(1ms));
}

TEST(ResponseBudget, RefuseIsFalseAtTheExactMarginAndTrueBelowIt)
{
    const auto now = std::chrono::steady_clock::now();

    // Budget 20 s => margin 1 s. The boundary is the only thing that tells '<' from '<='.
    EXPECT_FALSE(refuse(now + 1000ms, now, 20000ms));
    EXPECT_FALSE(refuse(now + 1001ms, now, 20000ms));
    EXPECT_TRUE(refuse(now + 999ms, now, 20000ms));

    // Budget 1 ms => margin 0: only a deadline already in the past refuses.
    EXPECT_FALSE(refuse(now, now, 1ms));
    EXPECT_FALSE(refuse(now + 1ms, now, 1ms));
    EXPECT_TRUE(refuse(now - 1ms, now, 1ms));
}

TEST(ResponseBudget, OverranIsFalseAtTheDeadlineAndTrueAfterIt)
{
    const auto deadline = std::chrono::steady_clock::now();
    EXPECT_FALSE(overran(deadline, deadline)); // answered exactly at the deadline: still awaited
    EXPECT_TRUE(overran(deadline, deadline + 1ms));
    EXPECT_FALSE(overran(deadline, deadline - 1ms));
}
