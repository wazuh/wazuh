#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

#include <fastmetrics/slidingWindowRate.hpp>

using namespace fastmetrics;

TEST(SlidingWindowRateTest, InitialRateIsZero)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(60)), 0.0);
}

TEST(SlidingWindowRateTest, CalculatesRateAfterSamples)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    // First sample
    rate.sample();

    // Wait a bit and produce events
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    counter.store(100);

    // Get rate - should be ~166 events/sec (100 events / 0.6 sec)
    double eps = rate.getRate(std::chrono::seconds(60));
    EXPECT_GT(eps, 100.0); // At least 100 eps (conservative bound given timing)
    EXPECT_LT(eps, 250.0); // Not more than 250 eps
}

TEST(SlidingWindowRateTest, MultipleWindows)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    // Sample, add events, sample again
    rate.sample();
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    counter.store(600);

    // All windows should see the same rate with only 2 data points
    double eps1m = rate.getRate(std::chrono::seconds(60));
    double eps5m = rate.getRate(std::chrono::seconds(300));
    double eps30m = rate.getRate(std::chrono::seconds(1800));

    // All should be approximately the same since we only have ~0.6s of data
    EXPECT_GT(eps1m, 500.0);
    EXPECT_GT(eps5m, 500.0);
    EXPECT_GT(eps30m, 500.0);
}

TEST(SlidingWindowRateTest, SampleCount)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    EXPECT_EQ(rate.sampleCount(), 0);

    rate.sample();
    EXPECT_EQ(rate.sampleCount(), 1);

    rate.sample();
    EXPECT_EQ(rate.sampleCount(), 2);
}

TEST(SlidingWindowRateTest, HandlesCallbackException)
{
    SlidingWindowRate rate([]() -> uint64_t { throw std::runtime_error("boom"); });

    // Should not crash, sample count stays 0 because exception prevents recording
    rate.sample();
    EXPECT_EQ(rate.sampleCount(), 0);
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(60)), 0.0);
}

TEST(SlidingWindowRateTest, RateWithBurstyTraffic)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    // Initial sample
    rate.sample();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Burst of events
    counter.store(1000);
    rate.sample();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // No new events
    rate.sample();

    // Rate over 1 second window should reflect the burst but average over the window
    double eps = rate.getRate(std::chrono::seconds(60));
    EXPECT_GT(eps, 0.0);
}

TEST(SlidingWindowRateTest, SteadyRate)
{
    std::atomic<uint64_t> counter {0};
    SlidingWindowRate rate([&counter]() { return counter.load(); });

    // Generate steady traffic: ~1000 events/sec
    const int iterations = 5;
    for (int i = 0; i < iterations; ++i)
    {
        counter.store((i + 1) * 200);
        rate.sample();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    double eps = rate.getRate(std::chrono::seconds(60));
    // Should be approximately 1000 eps
    EXPECT_GT(eps, 700.0);
    EXPECT_LT(eps, 1500.0);
}
