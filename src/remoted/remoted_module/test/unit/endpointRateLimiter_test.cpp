/*
 * Wazuh remoted module - Endpoint rate limiter unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the bucket arithmetic (burst, refill, saturation) plus the two properties that are
 * easy to break without noticing: the bucket starts FULL (an empty one would refuse the first
 * requests after every restart) and a diagnostics read never charges it (a metrics scrape must not
 * cost an agent its enrollment).
 *
 * Timing: every assertion is one-sided on purpose. "Allowed after waiting" only gets MORE true on a
 * slow machine (waiting adds tokens), and the "refused" cases are checked back to back with a rate
 * slow enough that a scheduling hiccup could not have refilled a whole token.
 */

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include "http_server/endpointRateLimiter.hpp"

using remoted::http::EndpointRateLimiter;
using namespace std::chrono_literals;

namespace
{
    EndpointRateLimiter::Settings settings(double rate, double burst)
    {
        EndpointRateLimiter::Settings s;
        s.ratePerSecond = rate;
        s.burst = burst;
        return s;
    }
} // namespace

TEST(EndpointRateLimiter, RateZeroDisablesTheLimiterEntirely)
{
    // 0 is a configured value ("no limit"), not a missing one: the limiter must then admit
    // everything, and say so, so the gate can drop its wrapper altogether.
    EndpointRateLimiter limiter {settings(0.0, 0.0)};

    EXPECT_FALSE(limiter.enabled());
    for (int i = 0; i < 1000; ++i)
    {
        EXPECT_TRUE(limiter.allow());
    }
    EXPECT_EQ(limiter.diagnostics().rejectedTotal, 0U);
    EXPECT_DOUBLE_EQ(limiter.diagnostics().limitPerSecond, 0.0);
}

TEST(EndpointRateLimiter, BurstIsSpentBeforeTheRatePaces)
{
    EndpointRateLimiter limiter {settings(1.0, 3.0)};

    ASSERT_TRUE(limiter.enabled());
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    // A fourth within the same second: one token takes a full second at this rate, so no plausible
    // scheduling delay between these statements could have refilled it.
    EXPECT_FALSE(limiter.allow());
    EXPECT_EQ(limiter.diagnostics().rejectedTotal, 1U);
}

TEST(EndpointRateLimiter, TheBucketIsSharedByEveryCaller)
{
    // The defining property of this limiter as opposed to a per-client one: allow() takes no
    // caller at all, so whoever spends the allowance spends it for everyone. This is what makes
    // the setting a fleet-wide ceiling.
    EndpointRateLimiter limiter {settings(1.0, 2.0)};

    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_FALSE(limiter.allow());
}

TEST(EndpointRateLimiter, TokensRefillOverTime)
{
    // Fast rate, single-token bucket: the wait only has to be long enough to earn one token back.
    EndpointRateLimiter limiter {settings(200.0, 1.0)};

    EXPECT_TRUE(limiter.allow());
    EXPECT_FALSE(limiter.allow());

    std::this_thread::sleep_for(50ms); // 10 tokens' worth; the bucket caps at 1
    EXPECT_TRUE(limiter.allow());
    // And the cap holds: the wait does not bank credit beyond the burst.
    EXPECT_FALSE(limiter.allow());
}

TEST(EndpointRateLimiter, TheBucketStartsFull)
{
    // Starting empty would refuse the first requests after every restart -- on /enroll, exactly
    // the moment a fleet coming back up needs it.
    EndpointRateLimiter limiter {settings(1.0, 5.0)};

    for (int i = 0; i < 5; ++i)
    {
        EXPECT_TRUE(limiter.allow()) << "request " << i;
    }
    EXPECT_EQ(limiter.diagnostics().rejectedTotal, 0U);
}

TEST(EndpointRateLimiter, BurstDefaultsToTheRateWhenUnset)
{
    // A burst of 0 means "same as the rate" -- the schema's documented meaning for the option.
    EndpointRateLimiter limiter {settings(3.0, 0.0)};

    EXPECT_DOUBLE_EQ(limiter.diagnostics().burst, 3.0);
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_FALSE(limiter.allow());
}

TEST(EndpointRateLimiter, DiagnosticsReportHeadroomWithoutSpendingIt)
{
    EndpointRateLimiter limiter {settings(1.0, 4.0)};

    EXPECT_DOUBLE_EQ(limiter.diagnostics().limitPerSecond, 1.0);
    EXPECT_DOUBLE_EQ(limiter.diagnostics().burst, 4.0);
    EXPECT_DOUBLE_EQ(limiter.diagnostics().available, 4.0);

    EXPECT_TRUE(limiter.allow());

    // Read repeatedly: a scrape observes the bucket, it must never move it -- otherwise a
    // frequently polled manager would refuse agents that a rarely polled one would admit.
    for (int i = 0; i < 20; ++i)
    {
        EXPECT_NEAR(limiter.diagnostics().available, 3.0, 0.5);
    }
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_TRUE(limiter.allow());
    EXPECT_FALSE(limiter.allow()) << "the 20 scrapes must not have refilled the bucket";
}

TEST(EndpointRateLimiter, RetryAfterIsTheRefillTimeRoundedUpAndNeverZero)
{
    EXPECT_EQ(EndpointRateLimiter {settings(100.0, 200.0)}.retryAfterSeconds(), 1U); // sub-second refill
    EXPECT_EQ(EndpointRateLimiter {settings(1.0, 1.0)}.retryAfterSeconds(), 1U);
    EXPECT_EQ(EndpointRateLimiter {settings(0.5, 1.0)}.retryAfterSeconds(), 2U); // one token every 2 s
}
