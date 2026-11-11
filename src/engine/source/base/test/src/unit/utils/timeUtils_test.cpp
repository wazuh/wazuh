// SPDX-License-Identifier: AGPL-3.0-or-later
#include "gtest/gtest.h"
#include <base/utils/timeUtils.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <regex>
#include <thread>
#include <vector>

class TimeUtilsTest : public ::testing::Test
{
protected:
    TimeUtilsTest() = default;
    virtual ~TimeUtilsTest() = default;
};

TEST(TimeUtilsTest, CheckCurrentDateDefaultSeparator)
{
    constexpr auto DATE_FORMAT_REGEX_STR {"[0-9]{4}/([0-9]|1[0-2]){2}/(([0-9]|1[0-2]){2})"};
    const auto currentData {base::utils::time::getCurrentDate()};
    EXPECT_TRUE(std::regex_match(currentData, std::regex(DATE_FORMAT_REGEX_STR)));
}

TEST(TimeUtilsTest, CheckCurrentDateCustomSeparator)
{
    constexpr auto DATE_FORMAT_REGEX_STR {"[0-9]{4}.([0-9]|1[0-2]){2}.(([0-9]|1[0-2]){2})"};
    const auto currentData {base::utils::time::getCurrentDate(".")};
    EXPECT_TRUE(std::regex_match(currentData, std::regex(DATE_FORMAT_REGEX_STR)));
}

using base::utils::time::StrictlyIncreasingClock;

TEST(TimeUtilsTest, StrictClockFollowsRisingClock)
{
    StrictlyIncreasingClock clock;
    EXPECT_EQ(clock.next(10), 10);
    EXPECT_EQ(clock.next(20), 20);
    EXPECT_EQ(clock.next(30), 30);
}

TEST(TimeUtilsTest, StrictClockBumpsOnTie)
{
    StrictlyIncreasingClock clock;
    EXPECT_EQ(clock.next(100), 100);
    EXPECT_EQ(clock.next(100), 101);
    EXPECT_EQ(clock.next(100), 102);
}

TEST(TimeUtilsTest, StrictClockBumpsOnBackwardsClock)
{
    StrictlyIncreasingClock clock;
    EXPECT_EQ(clock.next(100), 100);
    EXPECT_EQ(clock.next(50), 101);
    EXPECT_EQ(clock.next(40), 102);
}

TEST(TimeUtilsTest, StrictClockUniqueUnderContention)
{
    constexpr int THREADS = 8;
    constexpr int CALLS = 100'000;
    constexpr int64_t K = 1'000'000;

    StrictlyIncreasingClock clock;
    std::atomic<bool> start {false};
    std::vector<std::vector<int64_t>> values(THREADS);
    std::vector<std::thread> workers;
    workers.reserve(THREADS);

    for (int t = 0; t < THREADS; ++t)
    {
        values[t].reserve(CALLS);
        workers.emplace_back(
            [&clock, &start, &out = values[t]]()
            {
                // Spin until every thread is ready so the calls really contend
                while (!start.load(std::memory_order_acquire))
                {
                    std::this_thread::yield();
                }
                for (int i = 0; i < CALLS; ++i)
                {
                    out.push_back(clock.next(K));
                }
            });
    }
    start.store(true, std::memory_order_release);
    for (auto& w : workers)
    {
        w.join();
    }

    std::vector<int64_t> all;
    all.reserve(static_cast<size_t>(THREADS) * CALLS);
    for (const auto& v : values)
    {
        ASSERT_EQ(v.size(), static_cast<size_t>(CALLS));
        // Each thread sees its own values strictly increasing
        for (size_t i = 1; i < v.size(); ++i)
        {
            ASSERT_LT(v[i - 1], v[i]);
        }
        all.insert(all.end(), v.begin(), v.end());
    }

    // m_last starts at 0, so the first call returns max(K, 1) = K: the union is exactly {K, ..., K + 799 999}
    std::sort(all.begin(), all.end());
    ASSERT_EQ(all.size(), static_cast<size_t>(THREADS) * CALLS);
    for (size_t i = 0; i < all.size(); ++i)
    {
        ASSERT_EQ(all[i], K + static_cast<int64_t>(i));
    }
}

TEST(TimeUtilsTest, EpochNanosToISO8601Values)
{
    using base::utils::time::epochNanosToISO8601;
    EXPECT_EQ(epochNanosToISO8601(0), "1970-01-01T00:00:00.000000000Z");
    EXPECT_EQ(epochNanosToISO8601(1), "1970-01-01T00:00:00.000000001Z");
    EXPECT_EQ(epochNanosToISO8601(999'999'999), "1970-01-01T00:00:00.999999999Z");
    EXPECT_EQ(epochNanosToISO8601(1'000'000'001), "1970-01-01T00:00:01.000000001Z");
    EXPECT_EQ(epochNanosToISO8601(-1), "1969-12-31T23:59:59.999999999Z");
}

TEST(TimeUtilsTest, EpochNanosToISO8601Format)
{
    const auto formatted = base::utils::time::epochNanosToISO8601(base::utils::time::systemEpochNanos());
    EXPECT_EQ(formatted.size(), 30U);
    EXPECT_TRUE(std::regex_match(formatted, std::regex(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$)")))
        << formatted;
}

TEST(TimeUtilsTest, ReceptionClockIsSharedAndIncreasing)
{
    auto& clock = base::utils::time::receptionClock();
    const auto first = clock.next();
    const auto second = clock.next();

    int64_t fromOther = 0;
    std::thread other([&fromOther]() { fromOther = base::utils::time::receptionClock().next(); });
    other.join();

    EXPECT_NE(first, second);
    EXPECT_NE(first, fromOther);
    EXPECT_NE(second, fromOther);
    EXPECT_GT(second, first);
    EXPECT_GT(fromOther, second);
}
