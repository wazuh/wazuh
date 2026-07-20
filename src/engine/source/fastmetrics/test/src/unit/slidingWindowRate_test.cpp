#include <gtest/gtest.h>

#include <chrono>
#include <thread>
#include <vector>

#include <fastmetrics/slidingWindowRate.hpp>

using namespace fastmetrics;

TEST(SlidingWindowRateTest, InitialRateIsZero)
{
    SlidingWindowRate rate;
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(60)), 0.0);
}

TEST(SlidingWindowRateTest, SingleIncrementProducesPositiveRate)
{
    SlidingWindowRate rate;

    rate.increment();

    EXPECT_GT(rate.getRate(std::chrono::seconds(1)), 0.0);
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(1)), 1.0);
}

TEST(SlidingWindowRateTest, MultipleIncrementsSameSecond)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 100; ++i)
    {
        rate.increment();
    }

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(1)), 100.0);
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(10)), 10.0);
}

TEST(SlidingWindowRateTest, MultipleWindowsAverageCorrectly)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 600; ++i)
    {
        rate.increment();
    }

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(1)), 600.0);
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(60)), 10.0);
    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(300)), 2.0);
}

TEST(SlidingWindowRateTest, ZeroWindowReturnsZero)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 50; ++i)
    {
        rate.increment();
    }

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(0)), 0.0);
}

TEST(SlidingWindowRateTest, OldEventsFallOutOfWindow)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 10; ++i)
    {
        rate.increment();
    }

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(1)), 10.0);

    std::this_thread::sleep_for(std::chrono::seconds(2));

    EXPECT_DOUBLE_EQ(rate.getRate(std::chrono::seconds(1)), 0.0);
}

TEST(SlidingWindowRateTest, BurstyTrafficProducesPositiveAverage)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 1000; ++i)
    {
        rate.increment();
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    double eps = rate.getRate(std::chrono::seconds(2));

    EXPECT_GT(eps, 0.0);
    EXPECT_LE(eps, 500.0);
}

TEST(SlidingWindowRateTest, ConcurrentIncrementsProduceReasonableRate)
{
    SlidingWindowRate rate;

    constexpr int threadsCount = 4;
    constexpr int incrementsPerThread = 10000;

    std::vector<std::thread> threads;
    threads.reserve(threadsCount);

    for (int t = 0; t < threadsCount; ++t)
    {
        threads.emplace_back(
            [&rate]()
            {
                for (int i = 0; i < incrementsPerThread; ++i)
                {
                    rate.increment();
                }
            });
    }

    for (auto& th : threads)
    {
        th.join();
    }

    const double eps = rate.getRate(std::chrono::seconds(1));

    EXPECT_GT(eps, 0.0);
    EXPECT_LE(eps, static_cast<double>(threadsCount * incrementsPerThread));
}

TEST(SlidingWindowRateTest, WindowLargerThanMaxIsClamped)
{
    SlidingWindowRate rate;

    for (int i = 0; i < 60; ++i)
    {
        rate.increment();
    }

    const double epsMax = rate.getRate(std::chrono::seconds(31 * 60));
    const double epsTooLarge = rate.getRate(std::chrono::seconds(60 * 60));

    EXPECT_DOUBLE_EQ(epsMax, epsTooLarge);
}
