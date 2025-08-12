/**
 * Wazuh Inventory Sync - GapSet Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "../../src/gapSet.hpp"

// Test fixture for GapSet tests
class GapSetTest : public ::testing::Test
{
protected:
    GapSetTest() = default;
    ~GapSetTest() override = default;
};

TEST_F(GapSetTest, Constructor)
{
    GapSet gs(10);
    ASSERT_FALSE(gs.empty());
    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 1);
    EXPECT_EQ(ranges[0].first, 0);
    EXPECT_EQ(ranges[0].second, 9);
}

TEST_F(GapSetTest, Observe)
{
    GapSet gs(10);
    gs.observe(5);
    ASSERT_TRUE(gs.contains(5));
    ASSERT_FALSE(gs.contains(4));

    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 2);
    EXPECT_EQ(ranges[0].first, 0);
    EXPECT_EQ(ranges[0].second, 4);
    EXPECT_EQ(ranges[1].first, 6);
    EXPECT_EQ(ranges[1].second, 9);

    // Observe an already observed value. It should not change anything.
    gs.observe(5);
    ASSERT_TRUE(gs.contains(5));
    ASSERT_EQ(gs.ranges().size(), 2);

    // Observe an out-of-bounds value. It should not change anything.
    gs.observe(10);
    ASSERT_FALSE(gs.contains(10));
    gs.observe(999);
    ASSERT_FALSE(gs.contains(999));
}

TEST_F(GapSetTest, Empty)
{
    GapSet gs(3);
    ASSERT_FALSE(gs.empty());
    gs.observe(0);
    ASSERT_FALSE(gs.empty());
    gs.observe(1);
    ASSERT_FALSE(gs.empty());
    gs.observe(2);
    ASSERT_TRUE(gs.empty());
}

TEST_F(GapSetTest, Contains)
{
    GapSet gs(5);
    gs.observe(2);
    ASSERT_TRUE(gs.contains(2));
    ASSERT_FALSE(gs.contains(0));
    ASSERT_FALSE(gs.contains(1));
    ASSERT_FALSE(gs.contains(3));
    ASSERT_FALSE(gs.contains(4));
    // Check for out-of-bounds value
    ASSERT_FALSE(gs.contains(5));
}

TEST_F(GapSetTest, RangesNoObservations)
{
    GapSet gs(5);
    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 1);
    EXPECT_EQ(ranges[0].first, 0);
    EXPECT_EQ(ranges[0].second, 4);
}

TEST_F(GapSetTest, RangesSomeObservations)
{
    GapSet gs(10);
    gs.observe(0);
    gs.observe(9);
    gs.observe(4);
    gs.observe(5);
    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 2);
    EXPECT_EQ(ranges[0].first, 1);
    EXPECT_EQ(ranges[0].second, 3);
    EXPECT_EQ(ranges[1].first, 6);
    EXPECT_EQ(ranges[1].second, 8);
}

TEST_F(GapSetTest, RangesAllObservations)
{
    GapSet gs(4);
    gs.observe(0);
    gs.observe(1);
    gs.observe(2);
    gs.observe(3);
    ASSERT_TRUE(gs.empty());
    ASSERT_TRUE(gs.ranges().empty());
}

TEST_F(GapSetTest, RangesGapsAtBoundaries)
{
    GapSet gs(10);
    gs.observe(3);
    gs.observe(4);
    gs.observe(7);
    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 3);
    EXPECT_EQ(ranges[0].first, 0);
    EXPECT_EQ(ranges[0].second, 2);
    EXPECT_EQ(ranges[1].first, 5);
    EXPECT_EQ(ranges[1].second, 6);
    EXPECT_EQ(ranges[2].first, 8);
    EXPECT_EQ(ranges[2].second, 9);
}

TEST_F(GapSetTest, EdgeCaseSizeZero)
{
    GapSet gs(0);
    ASSERT_TRUE(gs.empty());
    ASSERT_TRUE(gs.ranges().empty());
}

TEST_F(GapSetTest, EdgeCaseSizeOne)
{
    GapSet gs(1);
    ASSERT_FALSE(gs.empty());
    auto ranges = gs.ranges();
    ASSERT_EQ(ranges.size(), 1);
    EXPECT_EQ(ranges[0].first, 0);
    EXPECT_EQ(ranges[0].second, 0);
    gs.observe(0);
    ASSERT_TRUE(gs.empty());
    ASSERT_TRUE(gs.ranges().empty());
}
