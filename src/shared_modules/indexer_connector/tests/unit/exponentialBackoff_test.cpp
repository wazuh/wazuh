/*
 * Wazuh - Indexer Connector exponential backoff unit tests.
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "exponentialBackoff.hpp"
#include <chrono>
#include <gtest/gtest.h>

class IndexerExponentialBackoffTest : public ::testing::Test
{
protected:
    static constexpr std::chrono::milliseconds BASE_DELAY {10};
    static constexpr std::chrono::milliseconds MAX_DELAY {40};

    static void expectDelayInRange(std::chrono::milliseconds delay,
                                   std::chrono::milliseconds minDelay,
                                   std::chrono::milliseconds maxDelay)
    {
        EXPECT_GE(delay, minDelay);
        EXPECT_LE(delay, maxDelay);
    }
};

TEST_F(IndexerExponentialBackoffTest, AppliesExponentialCapsAndReset)
{
    IndexerExponentialBackoff backoff(BASE_DELAY, MAX_DELAY);

    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, std::chrono::milliseconds {10});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {10}, std::chrono::milliseconds {20});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {20}, std::chrono::milliseconds {40});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {20}, std::chrono::milliseconds {40});

    backoff.reset();
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, BASE_DELAY);
}

// First failure must sleep exactly the base delay (no jitter), so a caller configuring e.g.
// RetryDelay=1s never waits less than that on its very first retry. Only the second consecutive
// failure onward introduces the randomized backoff step between the previous and current cap.
TEST_F(IndexerExponentialBackoffTest, FirstFailureSleepsExactlyBaseDelay)
{
    IndexerExponentialBackoff backoff(BASE_DELAY, MAX_DELAY);

    EXPECT_EQ(backoff.nextDelay(), BASE_DELAY);
    expectDelayInRange(backoff.nextDelay(), BASE_DELAY, BASE_DELAY * 2);

    backoff.reset();
    EXPECT_EQ(backoff.nextDelay(), BASE_DELAY);
}

TEST_F(IndexerExponentialBackoffTest, ConsecutiveFailuresDoNotExceedMaxDelay)
{
    IndexerExponentialBackoff backoff(BASE_DELAY, MAX_DELAY);

    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, BASE_DELAY);
    expectDelayInRange(backoff.nextDelay(), BASE_DELAY, BASE_DELAY * 2);

    for (size_t attempt = 0; attempt < 18; ++attempt)
    {
        expectDelayInRange(backoff.nextDelay(), MAX_DELAY / 2, MAX_DELAY);
    }
}

TEST_F(IndexerExponentialBackoffTest, MaxDelayUsesPreviousExponentialStepAsLowerBound)
{
    constexpr std::chrono::milliseconds baseDelay {1000};
    constexpr std::chrono::milliseconds maxDelay {15000};
    IndexerExponentialBackoff backoff(baseDelay, maxDelay);

    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, std::chrono::milliseconds {1000});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {1000}, std::chrono::milliseconds {2000});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {2000}, std::chrono::milliseconds {4000});
    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {4000}, std::chrono::milliseconds {8000});

    for (size_t attempt = 0; attempt < 7; ++attempt)
    {
        expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {8000}, maxDelay);
    }
}

TEST_F(IndexerExponentialBackoffTest, ZeroBaseDelayReturnsZero)
{
    IndexerExponentialBackoff backoff(std::chrono::milliseconds {0});

    EXPECT_EQ(backoff.nextDelay(), std::chrono::milliseconds {0});
    EXPECT_EQ(backoff.nextDelay(), std::chrono::milliseconds {0});
}

TEST_F(IndexerExponentialBackoffTest, NegativeBaseDelayIsClampedToZero)
{
    IndexerExponentialBackoff backoff(std::chrono::milliseconds {-10});

    EXPECT_EQ(backoff.nextDelay(), std::chrono::milliseconds {0});
    EXPECT_EQ(backoff.nextDelay(), std::chrono::milliseconds {0});
}

TEST_F(IndexerExponentialBackoffTest, MaxDelayBelowBaseDelayUsesBaseAsCap)
{
    constexpr std::chrono::milliseconds baseDelay {50};
    IndexerExponentialBackoff backoff(baseDelay, std::chrono::milliseconds {10});

    expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, baseDelay);

    for (size_t attempt = 0; attempt < 7; ++attempt)
    {
        expectDelayInRange(backoff.nextDelay(), std::chrono::milliseconds {0}, baseDelay);
    }
}
