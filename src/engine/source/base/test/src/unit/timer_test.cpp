#include <gtest/gtest.h>
#include <base/timer.hpp>
#include <thread> // for std::this_thread::sleep_for

TEST(TimerTest, TimerInitialization)
{
    base::chrono::Timer timer;
    // Ensure that the timer starts with a small elapsed time
    ASSERT_GE(timer.elapsed<std::chrono::milliseconds>(), 0);
}

TEST(TimerTest, TimerElapsedTime)
{
    base::chrono::Timer timer;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto elapsed_time = timer.elapsed<std::chrono::milliseconds>();
    // Check if the elapsed time is approximately 100 milliseconds
    ASSERT_GE(elapsed_time, 100);
    ASSERT_LT(elapsed_time, 200); // allow some margin for the test execution time
}

TEST(TimerTest, TimerElapsedTimeDifferentUnit)
{
    base::chrono::Timer timer;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto elapsed_time_micro = timer.elapsed<std::chrono::microseconds>();
    // Check if the elapsed time in microseconds is approximately 100000 microseconds
    ASSERT_GE(elapsed_time_micro, 100000);
    ASSERT_LT(elapsed_time_micro, 200000); // allow some margin for the test execution time
}

TEST(TimerTest, TimerMultipleCalls)
{
    base::chrono::Timer timer;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto elapsed_time_1 = timer.elapsed<std::chrono::milliseconds>();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto elapsed_time_2 = timer.elapsed<std::chrono::milliseconds>();

    // Check if the elapsed times are sequentially increasing
    ASSERT_GE(elapsed_time_1, 50);
    ASSERT_LT(elapsed_time_1, 150); // allow some margin for the test execution time
    ASSERT_GE(elapsed_time_2, 100);
    ASSERT_LT(elapsed_time_2, 200); // allow some margin for the test execution time
}
