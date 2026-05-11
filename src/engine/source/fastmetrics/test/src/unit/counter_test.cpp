#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include <fastmetrics/atomicCounter.hpp>

using namespace fastmetrics;

TEST(CounterTest, BasicOperations)
{
    AtomicCounter counter("test.counter");

    EXPECT_EQ(counter.name(), "test.counter");
    EXPECT_EQ(counter.type(), MetricType::COUNTER);
    EXPECT_TRUE(counter.isEnabled());

    // Initial value
    EXPECT_EQ(counter.get(), 0);

    // Increment by 1
    counter.increment();
    EXPECT_EQ(counter.get(), 1);

    // Add 10
    counter.add(10);
    EXPECT_EQ(counter.get(), 11);

    // Add 0 (should still work)
    counter.add(0);
    EXPECT_EQ(counter.get(), 11);
}

TEST(CounterTest, Reset)
{
    AtomicCounter counter("test.counter");

    counter.add(100);
    EXPECT_EQ(counter.get(), 100);

    counter.reset();
    EXPECT_EQ(counter.get(), 0);
}

TEST(CounterTest, EnableDisable)
{
    AtomicCounter counter("test.counter");

    // Enabled by default
    counter.add(5);
    EXPECT_EQ(counter.get(), 5);

    // Disable
    counter.disable();
    EXPECT_FALSE(counter.isEnabled());

    // Updates should be ignored
    counter.add(10);
    EXPECT_EQ(counter.get(), 5); // Still 5

    // Re-enable
    counter.enable();
    EXPECT_TRUE(counter.isEnabled());

    counter.add(10);
    EXPECT_EQ(counter.get(), 15);
}

TEST(CounterTest, ThreadSafety)
{
    AtomicCounter counter("test.counter");

    constexpr int NUM_THREADS = 10;
    constexpr int INCREMENTS_PER_THREAD = 10000;

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [&counter]()
            {
                for (int j = 0; j < INCREMENTS_PER_THREAD; ++j)
                {
                    counter.increment();
                }
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(counter.get(), NUM_THREADS * INCREMENTS_PER_THREAD);
}

TEST(CounterTest, MultiThreadedMixedOperations)
{
    AtomicCounter counter("test.counter");

    std::thread t1([&counter]()
                   {
                       for (int i = 0; i < 1000; ++i)
                           counter.add(1);
                   });

    std::thread t2([&counter]()
                   {
                       for (int i = 0; i < 1000; ++i)
                           counter.add(2);
                   });

    std::thread t3([&counter]()
                   {
                       for (int i = 0; i < 1000; ++i)
                           counter.add(3);
                   });

    t1.join();
    t2.join();
    t3.join();

    // Expected: 1000*1 + 1000*2 + 1000*3 = 6000
    EXPECT_EQ(counter.get(), 6000);
}
