/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "bufferLevel.hpp"

#include <gtest/gtest.h>

namespace
{
    // The legacy defaults: agent.warn_level, agent.normal_level, agent.tolerance.
    BufferLevelLadder defaultLadder()
    {
        return BufferLevelLadder {90, 70, 15};
    }
} // namespace

TEST(BufferLevelLadderTest, StartsNormalAndStaysQuietBelowTheWarnMark)
{
    auto ladder = defaultLadder();
    EXPECT_EQ(HC_BUFFER_NORMAL, ladder.level());

    const auto transition = ladder.observe(89, false, 0);
    EXPECT_FALSE(transition.announce);
    EXPECT_EQ(HC_BUFFER_NORMAL, ladder.level());
}

TEST(BufferLevelLadderTest, AnnouncesWarningAtTheWarnMark)
{
    auto ladder = defaultLadder();
    const auto transition = ladder.observe(90, false, 0);
    EXPECT_TRUE(transition.announce);
    EXPECT_EQ(HC_BUFFER_WARNING, transition.level);

    // Already there: no repeat announcement while it stays above the mark.
    EXPECT_FALSE(ladder.observe(95, false, 0).announce);
}

TEST(BufferLevelLadderTest, HysteresisHoldsWarningBetweenNormalAndWarnLevels)
{
    auto ladder = defaultLadder();
    ladder.observe(90, false, 0);

    // Back under the warn mark but above normal_level: the legacy ladder stays
    // in WARNING, which is exactly what stops a buffer hovering around the mark
    // from flapping an event per crossing.
    EXPECT_FALSE(ladder.observe(80, false, 0).announce);
    EXPECT_EQ(HC_BUFFER_WARNING, ladder.level());

    const auto backToNormal = ladder.observe(70, false, 0);
    EXPECT_TRUE(backToNormal.announce);
    EXPECT_EQ(HC_BUFFER_NORMAL, backToNormal.level);
}

TEST(BufferLevelLadderTest, ADroppedEventGoesStraightToFull)
{
    auto ladder = defaultLadder();

    // buffer.c enters FULL on full(), not on a percentage: the byte analogue is
    // the drop-newest rejection, whatever the occupancy reads.
    const auto transition = ladder.observe(99, true, 100);
    EXPECT_TRUE(transition.announce);
    EXPECT_EQ(HC_BUFFER_FULL, transition.level);
}

TEST(BufferLevelLadderTest, FloodOnlyAfterFullHoldsForTolerance)
{
    auto ladder = defaultLadder();
    ladder.observe(99, true, 1000); // Enters FULL, starts the dwell.

    EXPECT_FALSE(ladder.observe(99, true, 1010).announce); // 10 s: too soon.
    EXPECT_EQ(HC_BUFFER_FULL, ladder.level());

    const auto flooded = ladder.observe(99, true, 1015); // 15 s: tolerance met.
    EXPECT_TRUE(flooded.announce);
    EXPECT_EQ(HC_BUFFER_FLOOD, flooded.level);

    // FLOOD is terminal until the buffer actually drains.
    EXPECT_FALSE(ladder.observe(99, true, 2000).announce);
}

TEST(BufferLevelLadderTest, ZeroToleranceFloodsOnTheNextObservation)
{
    BufferLevelLadder ladder {90, 70, 0};
    ladder.observe(99, true, 500);
    EXPECT_EQ(HC_BUFFER_FLOOD, ladder.observe(99, true, 500).level);
}

TEST(BufferLevelLadderTest, StepDownFromFullToWarningIsSilent)
{
    auto ladder = defaultLadder();
    ladder.observe(99, true, 0);

    // buffer.c drops FULL/FLOOD back to WARNING without emitting anything --
    // only the return to NORMAL is reported. Announcing here would invent an
    // event the manager never used to see.
    const auto stepDown = ladder.observe(85, false, 0);
    EXPECT_FALSE(stepDown.announce);
    EXPECT_EQ(HC_BUFFER_WARNING, ladder.level());
}

TEST(BufferLevelLadderTest, DrainingFromFloodAnnouncesNormal)
{
    auto ladder = defaultLadder();
    ladder.observe(99, true, 0);
    ladder.observe(99, true, 60); // FLOOD.

    const auto recovered = ladder.observe(10, false, 61);
    EXPECT_TRUE(recovered.announce);
    EXPECT_EQ(HC_BUFFER_NORMAL, recovered.level);
}

TEST(BufferLevelLadderTest, RefillAfterRecoveryRestartsTheDwell)
{
    auto ladder = defaultLadder();
    ladder.observe(99, true, 0);
    ladder.observe(10, false, 5); // Back to NORMAL.

    ladder.observe(99, true, 100);                          // FULL again, dwell restarts at 100.
    EXPECT_FALSE(ladder.observe(99, true, 110).announce);   // Not 15 s yet.
    EXPECT_EQ(HC_BUFFER_FLOOD, ladder.observe(99, true, 115).level);
}

TEST(BufferLevelLadderTest, InvertedThresholdsAreClampedLikeInternalOptions)
{
    // internal_options caps normal_level at warn_level - 1; a config that
    // inverts them would otherwise make every observation both warn and normal.
    BufferLevelLadder ladder {50, 80, 15}; // normal_level clamps to 49.
    EXPECT_TRUE(ladder.observe(50, false, 0).announce);
    EXPECT_EQ(HC_BUFFER_WARNING, ladder.level());

    // Still above the clamped normal mark: WARNING holds rather than resolving
    // on the same observation that raised it.
    EXPECT_FALSE(ladder.observe(50, false, 0).announce);
    EXPECT_EQ(HC_BUFFER_WARNING, ladder.level());

    EXPECT_TRUE(ladder.observe(49, false, 0).announce);
    EXPECT_EQ(HC_BUFFER_NORMAL, ladder.level());
}
