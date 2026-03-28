#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include <fastmetrics/atomicHistogram.hpp>

using namespace fastmetrics;

TEST(HistogramTest, BasicOperations)
{
    AtomicHistogram<> histogram("test.latency");

    EXPECT_EQ(histogram.name(), "test.latency");
    EXPECT_EQ(histogram.type(), MetricType::HISTOGRAM);
    EXPECT_TRUE(histogram.isEnabled());

    // Initial state
    EXPECT_EQ(histogram.count(), 0);
    EXPECT_EQ(histogram.sum(), 0);
    EXPECT_EQ(histogram.mean(), 0);
}

TEST(HistogramTest, RecordValues)
{
    AtomicHistogram<> histogram("test.latency");

    // Record some values
    histogram.record(5);
    histogram.record(25);
    histogram.record(75);
    histogram.record(200);

    EXPECT_EQ(histogram.count(), 4);
    EXPECT_EQ(histogram.sum(), 5 + 25 + 75 + 200);
    EXPECT_EQ(histogram.min(), 5);
    EXPECT_EQ(histogram.max(), 200);
    EXPECT_EQ(histogram.mean(), (5 + 25 + 75 + 200) / 4);
}

TEST(HistogramTest, BucketDistribution)
{
    AtomicHistogram<> histogram("test.latency");

    // Default buckets: [1, 10, 100, 1k, 10k, 100k, 1M, 10M, +inf]

    // Record values in different buckets
    histogram.record(5);     // bucket 1: [1, 10)
    histogram.record(50);    // bucket 2: [10, 100)
    histogram.record(500);   // bucket 3: [100, 1k)
    histogram.record(5000);  // bucket 4: [1k, 10k)
    histogram.record(50000); // bucket 5: [10k, 100k)

    EXPECT_EQ(histogram.count(), 5);

    // Check bucket counts
    EXPECT_EQ(histogram.bucketCount(0), 0); // <1
    EXPECT_EQ(histogram.bucketCount(1), 1); // [1, 10)
    EXPECT_EQ(histogram.bucketCount(2), 1); // [10, 100)
    EXPECT_EQ(histogram.bucketCount(3), 1); // [100, 1k)
    EXPECT_EQ(histogram.bucketCount(4), 1); // [1k, 10k)
    EXPECT_EQ(histogram.bucketCount(5), 1); // [10k, 100k)
}

TEST(HistogramTest, Reset)
{
    AtomicHistogram<> histogram("test.latency");

    histogram.record(100);
    histogram.record(200);
    histogram.record(300);

    EXPECT_EQ(histogram.count(), 3);
    EXPECT_GT(histogram.sum(), 0);

    histogram.reset();

    EXPECT_EQ(histogram.count(), 0);
    EXPECT_EQ(histogram.sum(), 0);
    EXPECT_EQ(histogram.min(), 0);
    EXPECT_EQ(histogram.max(), 0);
    EXPECT_EQ(histogram.mean(), 0);
}

TEST(HistogramTest, EnableDisable)
{
    AtomicHistogram<> histogram("test.latency");

    histogram.record(100);
    EXPECT_EQ(histogram.count(), 1);

    histogram.disable();
    EXPECT_FALSE(histogram.isEnabled());

    // Records should be ignored
    histogram.record(200);
    histogram.record(300);
    EXPECT_EQ(histogram.count(), 1); // Still 1

    histogram.enable();
    histogram.record(400);
    EXPECT_EQ(histogram.count(), 2);
}

TEST(HistogramTest, ThreadSafety)
{
    AtomicHistogram<> histogram("test.latency");

    constexpr int NUM_THREADS = 8;
    constexpr int RECORDS_PER_THREAD = 1000;

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [&histogram, i]()
            {
                for (int j = 0; j < RECORDS_PER_THREAD; ++j)
                {
                    // Record different values per thread
                    histogram.record((i + 1) * 100 + j);
                }
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(histogram.count(), NUM_THREADS * RECORDS_PER_THREAD);
    EXPECT_GT(histogram.sum(), 0);
    EXPECT_GT(histogram.min(), 0);
    EXPECT_GT(histogram.max(), 0);
}

TEST(HistogramTest, EdgeCases)
{
    AtomicHistogram<> histogram("test.latency");

    // Zero value
    histogram.record(0);
    EXPECT_EQ(histogram.count(), 1);
    EXPECT_EQ(histogram.min(), 0);
    EXPECT_EQ(histogram.max(), 0);

    histogram.reset();

    // Very large value (goes to infinity bucket)
    histogram.record(999999999);
    EXPECT_EQ(histogram.count(), 1);
    EXPECT_EQ(histogram.max(), 999999999);
}
