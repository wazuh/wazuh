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
#include <random>
#include <thread>

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

    // Observe an out-of-bounds value. It should throw an exception.
    try
    {
        gs.observe(10);
        FAIL() << "Expected std::out_of_range exception for observe(10)";
    }
    catch (const std::out_of_range& e)
    {
        // Expected
    }
    catch (...)
    {
        FAIL() << "Expected std::out_of_range exception for observe(10)";
    }

    ASSERT_FALSE(gs.contains(10));

    try
    {
        gs.observe(999);
        FAIL() << "Expected std::out_of_range exception for observe(999)";
    }
    catch (const std::out_of_range& e)
    {
        // Expected
    }
    catch (...)
    {
        FAIL() << "Expected std::out_of_range exception for observe(999)";
    }

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

TEST_F(GapSetTest, LastUpdateChangesOnlyOnValidObserve)
{
    GapSet gs(5);
    auto before = gs.lastUpdate();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    gs.observe(2);
    auto after = gs.lastUpdate();
    EXPECT_GT(after, before);

    // Should NOT update lastUpdate
    auto checkpoint = gs.lastUpdate();
    gs.observe(2); // duplicate
    EXPECT_EQ(gs.lastUpdate(), checkpoint);
}

TEST_F(GapSetTest, IntervalMerging_Adjacent)
{
    GapSet gs(10);

    // Observe adjacent sequences - should merge into single interval
    gs.observe(3);
    EXPECT_EQ(gs.intervalCount(), 1);

    gs.observe(4);
    EXPECT_EQ(gs.intervalCount(), 1); // Should merge

    gs.observe(2);
    EXPECT_EQ(gs.intervalCount(), 1); // Should merge with existing [3,4]

    gs.observe(5);
    EXPECT_EQ(gs.intervalCount(), 1); // Should merge to create [2,5]

    // Verify the merged interval
    EXPECT_TRUE(gs.contains(2));
    EXPECT_TRUE(gs.contains(3));
    EXPECT_TRUE(gs.contains(4));
    EXPECT_TRUE(gs.contains(5));
    EXPECT_FALSE(gs.contains(1));
    EXPECT_FALSE(gs.contains(6));
}

TEST_F(GapSetTest, IntervalMerging_Multiple)
{
    GapSet gs(20);

    // Create separate intervals
    gs.observe(2);  // [2,2]
    gs.observe(5);  // [5,5]
    gs.observe(8);  // [8,8]
    gs.observe(12); // [12,12]
    EXPECT_EQ(gs.intervalCount(), 4);

    // Fill gaps to merge intervals: 2-5 and 8-12
    gs.observe(3); // [2,3], [5,5], [8,8], [12,12]
    gs.observe(4); // [2,5], [8,8], [12,12]
    EXPECT_EQ(gs.intervalCount(), 3);

    gs.observe(9);  // [2,5], [8,9], [12,12]
    gs.observe(10); // [2,5], [8,10], [12,12]
    gs.observe(11); // [2,5], [8,12]
    EXPECT_EQ(gs.intervalCount(), 2);

    // Bridge the final gap
    gs.observe(6); // [2,6], [8,12]
    gs.observe(7); // [2,12]
    EXPECT_EQ(gs.intervalCount(), 1);
}

TEST_F(GapSetTest, IntervalMerging_SequentialFill)
{
    GapSet gs(10);

    // Fill sequentially from 0
    for (uint64_t i = 0; i < 5; ++i)
    {
        gs.observe(i);
        EXPECT_EQ(gs.intervalCount(), 1); // Should always be single interval
    }

    // Fill sequentially from end
    for (uint64_t i = 9; i > 4; --i)
    {
        gs.observe(i);
        if (i == 5)
        {
            EXPECT_EQ(gs.intervalCount(), 1); // Should merge into complete range
            EXPECT_TRUE(gs.empty());
        }
        else
        {
            EXPECT_EQ(gs.intervalCount(), 2); // Two intervals until merge
        }
    }
}

TEST_F(GapSetTest, SparseData_LargeSequenceSpace)
{
    // Test sparse data in large sequence space (original use case)
    GapSet gs(1000000);

    // Observe sparse sequences
    std::vector<uint64_t> sparse = {17, 234, 50000, 999999, 0, 123456};
    for (auto seq : sparse)
    {
        gs.observe(seq);
    }

    EXPECT_EQ(gs.intervalCount(), sparse.size()); // All separate intervals
    EXPECT_EQ(gs.observedCount(), sparse.size());

    for (auto seq : sparse)
    {
        EXPECT_TRUE(gs.contains(seq));
    }

    // Should have many gap ranges
    auto ranges = gs.ranges();
    EXPECT_GT(ranges.size(), 3);

    // First gap should be [1, 16] (after observing 0)
    EXPECT_EQ(ranges[0].first, 1);
    EXPECT_EQ(ranges[0].second, 16);
}

TEST_F(GapSetTest, RandomizedObservationsMatchReference)
{
    constexpr uint64_t N = 200;
    GapSet gs(N);

    // Reference bitmap to validate correctness
    std::vector<bool> ref(N, false);

    std::mt19937_64 rng(123456);
    std::uniform_int_distribution<uint64_t> dist(0, N - 1);

    for (int i = 0; i < 2000; ++i)
    {
        auto v = dist(rng);
        gs.observe(v);
        ref[v] = true;
    }

    // Validate contains()
    for (uint64_t i = 0; i < N; ++i)
    {
        EXPECT_EQ(gs.contains(i), ref[i]) << "Mismatch at i=" << i;
    }

    // Validate ranges() versus reference gaps
    std::vector<std::pair<uint64_t, uint64_t>> expected;
    bool inGap = false;
    uint64_t start = 0;
    for (uint64_t i = 0; i < N; ++i)
    {
        if (!ref[i])
        {
            if (!inGap)
            {
                inGap = true;
                start = i;
            }
        }
        else if (inGap)
        {
            expected.emplace_back(start, i - 1);
            inGap = false;
        }
    }
    if (inGap)
        expected.emplace_back(start, N - 1);

    auto gaps = gs.ranges();
    ASSERT_EQ(gaps.size(), expected.size());
    for (size_t j = 0; j < gaps.size(); ++j)
    {
        EXPECT_EQ(gaps[j].first, expected[j].first);
        EXPECT_EQ(gaps[j].second, expected[j].second);
    }
}
