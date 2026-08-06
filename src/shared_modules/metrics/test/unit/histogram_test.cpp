/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <thread>
#include <vector>

#include <wazuh_metrics/atomicHistogram.hpp>

using namespace wazuh::metrics;

// ============================================================
// Bucket mapping at the edges: the first three octaves (values
// 0..7) map exactly -- one value per bucket, no averaging -- so a
// single observation of v in that range must report p50 == v.
// ============================================================

TEST(HistogramTest, ExactSmallValuesRoundTripThroughPercentiles)
{
    for (uint64_t v = 0; v <= 7; ++v)
    {
        AtomicHistogram histogram("test.histogram");
        histogram.observe(v);

        const auto snapshot = histogram.snapshot();
        EXPECT_EQ(snapshot.count, 1U);
        EXPECT_EQ(snapshot.sum, v);
        EXPECT_EQ(snapshot.min, v);
        EXPECT_EQ(snapshot.max, v);
        EXPECT_EQ(snapshot.p50, v) << "v=" << v;
        EXPECT_EQ(snapshot.p90, v) << "v=" << v;
        EXPECT_EQ(snapshot.p99, v) << "v=" << v;
    }
}

// ============================================================
// Known distribution: a dominant cluster plus one outlier.
// 100 observations of 1000 and 1 of 1'000'000. Sorted, positions
// 1..100 are all 1000 and position 101 is 1'000'000, so even p99
// (rank = ceil(0.99*101) = 100) lands on the last "1000" sample --
// its bucket estimate, not the raw value, so allow the ~12.5%
// bucket-width error, but max/min/sum/count are exact.
// ============================================================

TEST(HistogramTest, KnownDistributionClusterPlusOutlier)
{
    AtomicHistogram histogram("test.histogram");

    for (int i = 0; i < 100; ++i)
    {
        histogram.observe(1000);
    }
    histogram.observe(1000000);

    const auto snapshot = histogram.snapshot();

    EXPECT_EQ(snapshot.count, 101U);
    EXPECT_EQ(snapshot.sum, 100ULL * 1000 + 1000000);
    EXPECT_EQ(snapshot.min, 1000U);
    EXPECT_EQ(snapshot.max, 1000000U);

    // Bucket-resolution estimate: relative error bounded by ~12.5%.
    EXPECT_NEAR(static_cast<double>(snapshot.p50), 1000.0, 0.125 * 1000.0);
    EXPECT_NEAR(static_cast<double>(snapshot.p90), 1000.0, 0.125 * 1000.0);
    EXPECT_NEAR(static_cast<double>(snapshot.p99), 1000.0, 0.125 * 1000.0);
}

// ============================================================
// Percentiles over 1..100, each observed once. The rank formula is
// rank = (quantile*count truncated) + 1 (ceil for non-exact ranks),
// so:
//   p50: rank = int(0.50*100) + 1 = 51 -> value 51  -> bucket mid 52
//   p90: rank = int(0.90*100) + 1 = 91 -> value 91  -> bucket mid 88
//   p99: rank = int(0.99*100) + 1 = 100 -> value 100 -> bucket mid 104
// Bucket widths at these magnitudes: value 51 falls in octave 5
// (values 32..63, width 8); values 91 and 100 fall in octave 6
// (values 64..127, width 16). These are exact consequences of
// AtomicHistogram's bucket layout, not approximations.
// ============================================================

TEST(HistogramTest, PercentilesOverUniformSequence)
{
    AtomicHistogram histogram("test.histogram");

    for (uint64_t v = 1; v <= 100; ++v)
    {
        histogram.observe(v);
    }

    const auto snapshot = histogram.snapshot();

    EXPECT_EQ(snapshot.count, 100U);
    EXPECT_EQ(snapshot.sum, 5050U); // sum(1..100)
    EXPECT_EQ(snapshot.min, 1U);
    EXPECT_EQ(snapshot.max, 100U);

    EXPECT_EQ(snapshot.p50, 52U);
    EXPECT_EQ(snapshot.p90, 88U);
    EXPECT_EQ(snapshot.p99, 104U);
}

// ============================================================
// Upper clamp: the largest possible value must not crash the
// bucket mapping and must still be tracked exactly as max/count.
// ============================================================

TEST(HistogramTest, ClampsAtUpperBoundWithoutCrashing)
{
    AtomicHistogram histogram("test.histogram");

    histogram.observe(std::numeric_limits<uint64_t>::max());
    histogram.observe(1);

    const auto snapshot = histogram.snapshot();
    EXPECT_EQ(snapshot.count, 2U);
    EXPECT_EQ(snapshot.max, std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(snapshot.min, 1U);
}

// ============================================================
// Exact min/max over an arbitrary sequence (bucket estimation only
// affects percentiles, not min/max, which are tracked verbatim).
// ============================================================

TEST(HistogramTest, MinMaxAreExactOverArbitrarySequence)
{
    AtomicHistogram histogram("test.histogram");

    for (uint64_t v : {50ULL, 10ULL, 999ULL, 3ULL, 777ULL, 1ULL})
    {
        histogram.observe(v);
    }

    const auto snapshot = histogram.snapshot();
    EXPECT_EQ(snapshot.min, 1U);
    EXPECT_EQ(snapshot.max, 999U);
    EXPECT_EQ(snapshot.count, 6U);
    EXPECT_EQ(snapshot.sum, 50U + 10U + 999U + 3U + 777U + 1U);
}

// ============================================================
// reset(): zeroes everything, and min does NOT leak its internal
// sentinel (numeric_limits<uint64_t>::max()) once the count is
// back to zero.
// ============================================================

TEST(HistogramTest, ResetZeroesSnapshotAndDoesNotLeakMinSentinel)
{
    AtomicHistogram histogram("test.histogram");

    histogram.observe(10);
    histogram.observe(20);
    histogram.observe(30);

    histogram.reset();

    const auto snapshot = histogram.snapshot();
    EXPECT_EQ(snapshot.count, 0U);
    EXPECT_EQ(snapshot.sum, 0U);
    EXPECT_EQ(snapshot.min, 0U); // NOT numeric_limits<uint64_t>::max()
    EXPECT_EQ(snapshot.max, 0U);
    EXPECT_EQ(snapshot.p50, 0U);
    EXPECT_EQ(snapshot.p90, 0U);
    EXPECT_EQ(snapshot.p99, 0U);

    // Histogram remains usable after reset.
    histogram.observe(5);
    EXPECT_EQ(histogram.snapshot().count, 1U);
}

TEST(HistogramTest, FreshHistogramSnapshotIsAllZero)
{
    AtomicHistogram histogram("test.histogram");

    const auto snapshot = histogram.snapshot();
    EXPECT_EQ(snapshot.count, 0U);
    EXPECT_EQ(snapshot.sum, 0U);
    EXPECT_EQ(snapshot.min, 0U);
    EXPECT_EQ(snapshot.max, 0U);
}

// ============================================================
// Disabled: observe() becomes a no-op, value() reports 0.
// ============================================================

TEST(HistogramTest, DisabledObserveIsNoOp)
{
    AtomicHistogram histogram("test.histogram");

    histogram.observe(42);
    EXPECT_EQ(histogram.snapshot().count, 1U);

    histogram.disable();
    EXPECT_FALSE(histogram.isEnabled());

    histogram.observe(100);
    histogram.observe(200);
    EXPECT_EQ(histogram.snapshot().count, 1U); // unchanged

    EXPECT_DOUBLE_EQ(histogram.value(), 0.0); // value() reports 0 while disabled

    histogram.enable();
    EXPECT_TRUE(histogram.isEnabled());
    histogram.observe(100);
    EXPECT_EQ(histogram.snapshot().count, 2U);
}

// ============================================================
// Basic metadata: name(), type(), isEnabled() default state.
// ============================================================

TEST(HistogramTest, BasicMetadata)
{
    AtomicHistogram histogram("test.histogram");

    EXPECT_EQ(histogram.name(), "test.histogram");
    EXPECT_EQ(histogram.type(), MetricType::HISTOGRAM);
    EXPECT_TRUE(histogram.isEnabled());
}

// ============================================================
// value() mirrors the observation count (IMetric::value() contract
// for histograms), not the sum or any percentile.
// ============================================================

TEST(HistogramTest, ValueEqualsObservationCount)
{
    AtomicHistogram histogram("test.histogram");

    EXPECT_DOUBLE_EQ(histogram.value(), 0.0);

    for (int i = 0; i < 7; ++i)
    {
        histogram.observe(static_cast<uint64_t>(i * 10));
    }

    EXPECT_DOUBLE_EQ(histogram.value(), 7.0);
    EXPECT_EQ(histogram.value(), static_cast<double>(histogram.snapshot().count));
}

// ============================================================
// Concurrency: 8 threads x 100k observations each of a distinct
// fixed value per thread. count and sum are exact regardless of
// interleaving (both are plain atomic accumulators); snapshot()
// must not crash while observes are still landing concurrently.
// ============================================================

TEST(HistogramTest, ConcurrentObserveIsExactForCountAndSum)
{
    AtomicHistogram histogram("test.histogram");

    constexpr int NUM_THREADS = 8;
    constexpr int OBSERVATIONS_PER_THREAD = 100000;

    std::vector<std::thread> threads;
    std::atomic<bool> stopSnapshotting {false};

    // A snapshotting thread races the observers: this must never crash
    // or hang, even though its own numbers are best-effort.
    std::thread snapshotter(
        [&histogram, &stopSnapshotting]()
        {
            while (!stopSnapshotting.load(std::memory_order_relaxed))
            {
                volatile auto snap = histogram.snapshot();
                (void)snap;
            }
        });

    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&histogram, threadId = t]()
            {
                const uint64_t value = static_cast<uint64_t>(threadId + 1); // 1..8
                for (int i = 0; i < OBSERVATIONS_PER_THREAD; ++i)
                {
                    histogram.observe(value);
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }
    stopSnapshotting.store(true, std::memory_order_relaxed);
    snapshotter.join();

    const auto snapshot = histogram.snapshot();

    constexpr uint64_t expectedCount = static_cast<uint64_t>(NUM_THREADS) * OBSERVATIONS_PER_THREAD;
    // sum(1..8) * OBSERVATIONS_PER_THREAD
    constexpr uint64_t expectedSum = 36ULL * OBSERVATIONS_PER_THREAD;

    EXPECT_EQ(snapshot.count, expectedCount);
    EXPECT_EQ(snapshot.sum, expectedSum);
    EXPECT_EQ(snapshot.min, 1U);
    EXPECT_EQ(snapshot.max, 8U);
}
