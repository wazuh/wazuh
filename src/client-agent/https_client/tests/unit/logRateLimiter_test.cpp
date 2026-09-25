/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "logRateLimiter.hpp"

#include "fakeSysSeams.hpp"

#include <gtest/gtest.h>

#include <chrono>

// A window long enough that nothing expires mid-test.
constexpr auto LONG_WINDOW
{
    std::chrono::seconds {60}
};

// The first occurrence must be reported immediately: an operator should not have to wait a whole
// window for the first sign of trouble.
TEST(LogRateLimiterTest, FirstOccurrenceEmitsImmediately)
{
    FakeClock clock;
    LogRateLimiter limiter {clock, LONG_WINDOW};

    const auto decision = limiter.record();

    EXPECT_TRUE(decision.emit);
    EXPECT_TRUE(static_cast<bool>(decision));
    EXPECT_EQ(decision.suppressed, 0U);
    EXPECT_EQ(decision.total, 1U);
}

// Everything after the first hit inside the same window stays quiet, but is still counted.
TEST(LogRateLimiterTest, SubsequentOccurrencesInsideTheWindowAreSuppressed)
{
    FakeClock clock;
    LogRateLimiter limiter {clock, LONG_WINDOW};

    ASSERT_TRUE(limiter.record().emit);

    for (int i = 0; i < 99; ++i)
    {
        clock.advance(std::chrono::milliseconds {100}); // Still well inside the 60s window.
        const auto decision = limiter.record();
        EXPECT_FALSE(decision.emit);
        EXPECT_EQ(decision.total, 0U); // A suppressed decision carries no count.
    }
}

// Once the window elapses, the next occurrence is emitted and reports everything it stands for.
TEST(LogRateLimiterTest, NextWindowReportsTheAggregatedCount)
{
    FakeClock clock;
    LogRateLimiter limiter {clock, std::chrono::milliseconds {50}};

    ASSERT_TRUE(limiter.record().emit);

    for (int i = 0; i < 99; ++i)
    {
        ASSERT_FALSE(limiter.record().emit);
    }

    clock.advance(std::chrono::milliseconds {80});

    const auto decision = limiter.record();
    EXPECT_TRUE(decision.emit);
    // 99 suppressed + the one that just triggered this emission.
    EXPECT_EQ(decision.total, 100U);
    EXPECT_EQ(decision.suppressed, 99U);
}

// suppressed is always total - 1, so a message rendering `total` reads correctly on the first hit
// ("1 occurrence(s)") as well as after a burst.
TEST(LogRateLimiterTest, TotalAlwaysExceedsSuppressedByExactlyOne)
{
    FakeClock clock;
    LogRateLimiter limiter {clock, std::chrono::milliseconds {20}};

    for (int round = 0; round < 5; ++round)
    {
        const auto decision = limiter.record();
        ASSERT_TRUE(decision.emit) << "round " << round;
        EXPECT_EQ(decision.total, decision.suppressed + 1);
        clock.advance(std::chrono::milliseconds {30});
    }
}

// A recovery clears the window state: the incident that follows is reported at once, even though
// the old window (measured from the LAST incident's last occurrence) has not elapsed yet. Without
// this, a fast-recovering-then-failing-again sequence could land the new incident's first line
// inside the old incident's tail window and suppress it -- exactly the case ControlStream's
// recovery handling (m_certVerificationReported/reset()) exists to avoid.
TEST(LogRateLimiterTest, ResetMakesTheNextOccurrenceEmitImmediately)
{
    FakeClock clock;
    LogRateLimiter limiter {clock, LONG_WINDOW};

    ASSERT_TRUE(limiter.record().emit);
    ASSERT_FALSE(limiter.record().emit); // Still inside the window.

    limiter.reset();

    const auto decision = limiter.record();
    EXPECT_TRUE(decision.emit);
    EXPECT_EQ(decision.suppressed, 0U);
    EXPECT_EQ(decision.total, 1U);
}
