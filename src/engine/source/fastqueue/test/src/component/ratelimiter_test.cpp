#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <thread>
#include <vector>

#include <fastqueue/ratelimiter.hpp>

using namespace fastqueue;

class RateLimiterTest : public ::testing::Test
{
};

/**
 * @brief Reproduces the race condition bug where multiple consumers cause
 * refillTokens() to add tokens multiple times for the same time interval.
 *
 * With the buggy implementation:
 * - 1 consumer at 1000 EPS → ~1000 actual EPS (correct)
 * - 8 consumers at 1000 EPS → ~1500-2000 actual EPS (tokens duplicated)
 *
 * The fix ensures only one thread wins the refill per interval via CAS.
 */
TEST_F(RateLimiterTest, MultiConsumerDoesNotExceedRate)
{
    constexpr size_t TARGET_EPS = 1000;
    constexpr size_t NUM_CONSUMERS = 8;
    constexpr int TEST_DURATION_MS = 2000;
    // Allow 15% tolerance for timing jitter
    constexpr double TOLERANCE = 0.15;

    // Start with 0 burst so we measure only the steady-state refill rate
    RateLimiter limiter(TARGET_EPS, 1); // burstSize=1 to minimize initial burst impact

    std::atomic<int64_t> totalAcquired {0};
    std::atomic<bool> running {true};

    auto consumer = [&]()
    {
        int64_t localCount = 0;
        while (running.load(std::memory_order_relaxed))
        {
            if (limiter.tryAcquire(1))
            {
                localCount++;
            }
            else
            {
                std::this_thread::yield();
            }
        }
        totalAcquired.fetch_add(localCount, std::memory_order_relaxed);
    };

    // Launch consumers
    std::vector<std::thread> threads;
    threads.reserve(NUM_CONSUMERS);
    for (size_t i = 0; i < NUM_CONSUMERS; ++i)
    {
        threads.emplace_back(consumer);
    }

    // Let them run for the test duration
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    running.store(false, std::memory_order_relaxed);

    for (auto& t : threads)
    {
        t.join();
    }

    double elapsed_seconds = TEST_DURATION_MS / 1000.0;
    double expected = TARGET_EPS * elapsed_seconds;
    double actual = static_cast<double>(totalAcquired.load());
    double actualEPS = actual / elapsed_seconds;

    // The actual count should NOT exceed the expected by more than tolerance
    // Before fix: 8 consumers would reach ~1500-2000 EPS instead of 1000
    EXPECT_LE(actual, expected * (1.0 + TOLERANCE))
        << "Rate limiter exceeded configured rate! "
        << "Expected ~" << expected << " tokens in " << elapsed_seconds << "s, "
        << "got " << actual << " (" << actualEPS << " EPS with " << NUM_CONSUMERS << " consumers)";

    // Sanity: should have gotten a reasonable amount (at least 70% of target)
    EXPECT_GE(actual, expected * (1.0 - TOLERANCE * 2))
        << "Rate limiter too restrictive! "
        << "Expected ~" << expected << " but got " << actual;
}

/**
 * @brief Verify single consumer still works correctly after the fix.
 */
TEST_F(RateLimiterTest, SingleConsumerAccuracy)
{
    constexpr size_t TARGET_EPS = 1000;
    constexpr int TEST_DURATION_MS = 2000;
    constexpr double TOLERANCE = 0.15;

    RateLimiter limiter(TARGET_EPS, 1);

    std::atomic<int64_t> totalAcquired {0};
    std::atomic<bool> running {true};

    std::thread consumer([&]()
    {
        int64_t localCount = 0;
        while (running.load(std::memory_order_relaxed))
        {
            if (limiter.tryAcquire(1))
            {
                localCount++;
            }
            else
            {
                std::this_thread::yield();
            }
        }
        totalAcquired.fetch_add(localCount, std::memory_order_relaxed);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    running.store(false, std::memory_order_relaxed);
    consumer.join();

    double elapsed_seconds = TEST_DURATION_MS / 1000.0;
    double expected = TARGET_EPS * elapsed_seconds;
    double actual = static_cast<double>(totalAcquired.load());

    EXPECT_LE(actual, expected * (1.0 + TOLERANCE));
    EXPECT_GE(actual, expected * (1.0 - TOLERANCE * 2));
}

/**
 * @brief Stress test: high EPS with many consumers — the exact scenario
 * that triggers the bug most severely.
 */
TEST_F(RateLimiterTest, HighEPSManyConsumersStressTest)
{
    constexpr size_t TARGET_EPS = 5000;
    constexpr size_t NUM_CONSUMERS = 16;
    constexpr int TEST_DURATION_MS = 3000;
    constexpr double TOLERANCE = 0.15;

    RateLimiter limiter(TARGET_EPS, 1);

    std::atomic<int64_t> totalAcquired {0};
    std::atomic<bool> running {true};

    auto consumer = [&]()
    {
        int64_t localCount = 0;
        while (running.load(std::memory_order_relaxed))
        {
            if (limiter.tryAcquire(1))
            {
                localCount++;
            }
            else
            {
                std::this_thread::yield();
            }
        }
        totalAcquired.fetch_add(localCount, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    threads.reserve(NUM_CONSUMERS);
    for (size_t i = 0; i < NUM_CONSUMERS; ++i)
    {
        threads.emplace_back(consumer);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    running.store(false, std::memory_order_relaxed);

    for (auto& t : threads)
    {
        t.join();
    }

    double elapsed_seconds = TEST_DURATION_MS / 1000.0;
    double expected = TARGET_EPS * elapsed_seconds;
    double actual = static_cast<double>(totalAcquired.load());
    double actualEPS = actual / elapsed_seconds;

    EXPECT_LE(actual, expected * (1.0 + TOLERANCE))
        << "Stress test: rate limiter exceeded configured rate! "
        << "Expected ~" << expected << " tokens, got " << actual
        << " (" << actualEPS << " EPS with " << NUM_CONSUMERS << " consumers)";

    EXPECT_GE(actual, expected * (1.0 - TOLERANCE * 2));
}

/**
 * @brief Verify waitAcquire works correctly with multiple consumers.
 */
TEST_F(RateLimiterTest, WaitAcquireMultiConsumer)
{
    constexpr size_t TARGET_EPS = 500;
    constexpr size_t NUM_CONSUMERS = 8;
    constexpr int TEST_DURATION_MS = 2000;
    constexpr double TOLERANCE = 0.15;

    RateLimiter limiter(TARGET_EPS, 1);

    std::atomic<int64_t> totalAcquired {0};
    std::atomic<bool> running {true};

    auto consumer = [&]()
    {
        int64_t localCount = 0;
        while (running.load(std::memory_order_relaxed))
        {
            if (limiter.waitAcquire(1, 50000)) // 50ms timeout
            {
                localCount++;
            }
        }
        totalAcquired.fetch_add(localCount, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    threads.reserve(NUM_CONSUMERS);
    for (size_t i = 0; i < NUM_CONSUMERS; ++i)
    {
        threads.emplace_back(consumer);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    running.store(false, std::memory_order_relaxed);

    for (auto& t : threads)
    {
        t.join();
    }

    double elapsed_seconds = TEST_DURATION_MS / 1000.0;
    double expected = TARGET_EPS * elapsed_seconds;
    double actual = static_cast<double>(totalAcquired.load());

    EXPECT_LE(actual, expected * (1.0 + TOLERANCE))
        << "waitAcquire: rate limiter exceeded! Expected ~" << expected
        << ", got " << actual;
}

/**
 * @brief Verify that multi-consumer throughput does not exceed the configured
 * rate, just as a single consumer does not.
 *
 */
TEST_F(RateLimiterTest, MultiConsumerRateMatchesSingleConsumer)
{
    constexpr size_t TARGET_EPS = 2000;
    constexpr int TEST_DURATION_MS = 2000;
    constexpr double UPPER_TOLERANCE = 0.15; // Neither mode should exceed TARGET_EPS by >15%
    constexpr double MULTI_LOWER_TOLERANCE = 0.70; // 8 consumers should reach at least 70%
    constexpr double SINGLE_LOWER_TOLERANCE = 0.50; // 1 consumer may be slower due to yield() jitter

    auto measureEPS = [&](size_t numConsumers) -> double
    {
        RateLimiter limiter(TARGET_EPS, 1);

        std::atomic<int64_t> totalAcquired {0};
        std::atomic<bool> running {true};

        auto consumer = [&]()
        {
            int64_t localCount = 0;
            while (running.load(std::memory_order_relaxed))
            {
                if (limiter.tryAcquire(1))
                {
                    localCount++;
                }
                else
                {
                    std::this_thread::yield();
                }
            }
            totalAcquired.fetch_add(localCount, std::memory_order_relaxed);
        };

        std::vector<std::thread> threads;
        threads.reserve(numConsumers);
        for (size_t i = 0; i < numConsumers; ++i)
        {
            threads.emplace_back(consumer);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
        running.store(false, std::memory_order_relaxed);

        for (auto& t : threads)
        {
            t.join();
        }

        double elapsed_seconds = TEST_DURATION_MS / 1000.0;
        return static_cast<double>(totalAcquired.load()) / elapsed_seconds;
    };

    double singleEPS = measureEPS(1);
    double multiEPS = measureEPS(8);

    // Multi-consumer must not exceed the configured rate (the CAS fix invariant)
    EXPECT_LE(multiEPS, TARGET_EPS * (1.0 + UPPER_TOLERANCE))
        << "Multi-consumer exceeds configured rate: " << multiEPS << " EPS (target: " << TARGET_EPS << ")";

    // Single-consumer must not exceed the configured rate either
    EXPECT_LE(singleEPS, TARGET_EPS * (1.0 + UPPER_TOLERANCE))
        << "Single-consumer exceeds configured rate: " << singleEPS << " EPS (target: " << TARGET_EPS << ")";

    // Sanity: multi-consumer should reach a reasonable fraction of TARGET_EPS
    EXPECT_GE(multiEPS, TARGET_EPS * MULTI_LOWER_TOLERANCE)
        << "Multi-consumer too restrictive: " << multiEPS << " EPS (target: " << TARGET_EPS << ")";

    // Sanity: single-consumer has a wider lower margin because yield() duration
    // is non-deterministic on slow or CPU-constrained machines
    EXPECT_GE(singleEPS, TARGET_EPS * SINGLE_LOWER_TOLERANCE)
        << "Single-consumer too restrictive: " << singleEPS << " EPS (target: " << TARGET_EPS << ")";
}
