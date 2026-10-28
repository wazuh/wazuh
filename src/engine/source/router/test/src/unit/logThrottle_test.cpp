// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <chrono>

#include "logThrottle.hpp"

using router::LogThrottle;

TEST(LogThrottleTest, FirstOccurrenceIsLoggedWithNothingSuppressed)
{
    LogThrottle throttle {std::chrono::seconds(60)};
    const auto out = throttle.record(LogThrottle::Clock::time_point {} + std::chrono::seconds(1));
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, 0U);
}

TEST(LogThrottleTest, OccurrencesInsideTheWindowAreSuppressed)
{
    LogThrottle throttle {std::chrono::seconds(60)};
    const auto t0 = LogThrottle::Clock::time_point {} + std::chrono::seconds(1);
    ASSERT_TRUE(throttle.record(t0).has_value());
    EXPECT_FALSE(throttle.record(t0 + std::chrono::seconds(1)).has_value());
    EXPECT_FALSE(throttle.record(t0 + std::chrono::seconds(59)).has_value());
}

TEST(LogThrottleTest, FirstOccurrenceAfterTheWindowReportsSuppressedCount)
{
    LogThrottle throttle {std::chrono::seconds(60)};
    const auto t0 = LogThrottle::Clock::time_point {} + std::chrono::seconds(1);
    ASSERT_TRUE(throttle.record(t0).has_value());
    for (int i = 1; i <= 5; ++i)
    {
        EXPECT_FALSE(throttle.record(t0 + std::chrono::seconds(i)).has_value());
    }

    const auto out = throttle.record(t0 + std::chrono::seconds(60));
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, 5U);

    // The count restarts after each logged occurrence.
    EXPECT_FALSE(throttle.record(t0 + std::chrono::seconds(61)).has_value());
    const auto next = throttle.record(t0 + std::chrono::seconds(121));
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(*next, 1U);
}
