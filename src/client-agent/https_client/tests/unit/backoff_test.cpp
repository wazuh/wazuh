/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "backoff.hpp"
#include "fakeSysSeams.hpp"

#include <gtest/gtest.h>

TEST(BackoffTest, FullJitterUpperBoundFollowsDoublingCeilings)
{
    ScriptedRandom random {{1.0}};
    Backoff backoff {1000, 60000, random};
    // uniform01() == 1.0 makes each delay equal to the current ceiling.
    EXPECT_EQ(1000, backoff.next().count());
    EXPECT_EQ(2000, backoff.next().count());
    EXPECT_EQ(4000, backoff.next().count());
    EXPECT_EQ(8000, backoff.next().count());
}

TEST(BackoffTest, CeilingIsCappedAndStaysCapped)
{
    ScriptedRandom random {{1.0}};
    Backoff backoff {1000, 60000, random};

    for (int attempt = 0; attempt < 12; attempt++)
    {
        backoff.next();
    }

    EXPECT_EQ(60000u, backoff.currentCeilingMs());
    backoff.next();
    EXPECT_EQ(60000u, backoff.currentCeilingMs());
}

TEST(BackoffTest, JitterLowerBoundIsZero)
{
    ScriptedRandom random {{0.0}};
    Backoff backoff {1000, 60000, random};
    EXPECT_EQ(0, backoff.next().count());
    EXPECT_EQ(0, backoff.next().count());
}

TEST(BackoffTest, JitterStaysWithinTheWindow)
{
    ScriptedRandom random {{0.25, 0.5}};
    Backoff backoff {1000, 60000, random};
    EXPECT_EQ(250, backoff.next().count());  // 0.25 * 1000
    EXPECT_EQ(1000, backoff.next().count()); // 0.50 * 2000
}

TEST(BackoffTest, ResetRestoresTheBaseWindow)
{
    ScriptedRandom random {{1.0}};
    Backoff backoff {1000, 60000, random};
    backoff.next();
    backoff.next();
    ASSERT_EQ(4000u, backoff.currentCeilingMs());
    backoff.reset();
    EXPECT_EQ(1000u, backoff.currentCeilingMs());
    EXPECT_EQ(1000, backoff.next().count());
}

TEST(BackoffTest, AttemptShiftIsBoundedAgainstOverflow)
{
    ScriptedRandom random {{1.0}};
    Backoff backoff {1000, 60000, random};

    for (int attempt = 0; attempt < 100; attempt++)
    {
        backoff.next(); // Must neither overflow nor exceed the cap.
    }

    EXPECT_EQ(60000u, backoff.currentCeilingMs());
}
