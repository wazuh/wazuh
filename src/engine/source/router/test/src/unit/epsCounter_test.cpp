#include <gtest/gtest.h>

#include <router/orchestrator.hpp>

#include "epsCounter.hpp"

class T : public router::Orchestrator
{
public:
    using EpsCounter = Orchestrator::EpsCounter;
};

TEST(EpsCounter, BuildsDefault)
{
    auto counter = T::EpsCounter();
    EXPECT_EQ(counter.getEps(), router::DEFAULT_EPS);
    EXPECT_EQ(counter.getRefreshInterval(), router::DEFAULT_INTERVAL);
    EXPECT_EQ(counter.isActive(), router::DEFAULT_STATE);
}

TEST(EpsCounter, BuildsParams)
{
    auto counter = T::EpsCounter(2, 2, true);
    EXPECT_EQ(counter.getEps(), 2);
    EXPECT_EQ(counter.getRefreshInterval(), 2);
    EXPECT_EQ(counter.isActive(), true);
}

TEST(EpsCounter, BuildsError)
{
    EXPECT_THROW(T::EpsCounter(0, 2, true), std::runtime_error);
    EXPECT_THROW(T::EpsCounter(2, 0, true), std::runtime_error);
    EXPECT_THROW(T::EpsCounter(0, 0, true), std::runtime_error);
}

TEST(EpsCounter, Start)
{
    auto counter = T::EpsCounter(2, 2, true);
    counter.start();
    EXPECT_EQ(counter.isActive(), true);

    auto counter1 = T::EpsCounter(2, 2, false);
    counter1.start();
    EXPECT_EQ(counter1.isActive(), true);
}

TEST(EpsCounter, Stop)
{
    auto counter = T::EpsCounter(2, 2, true);
    counter.stop();
    EXPECT_EQ(counter.isActive(), false);

    auto counter1 = T::EpsCounter(2, 2, false);
    counter1.stop();
    EXPECT_EQ(counter1.isActive(), false);
}

TEST(EpsCounter, ChangeSettings)
{
    auto counter = T::EpsCounter(2, 2, true);
    counter.changeSettings(3, 3);
    EXPECT_EQ(counter.getEps(), 3);
    EXPECT_EQ(counter.getRefreshInterval(), 3);

    EXPECT_THROW(counter.changeSettings(0, 3), std::runtime_error);
    EXPECT_THROW(counter.changeSettings(3, 0), std::runtime_error);
    EXPECT_THROW(counter.changeSettings(0, 0), std::runtime_error);
}

TEST(EpsCounter, LimitReachedSingleThread)
{
    auto counter = T::EpsCounter(1, 1, true);
    EXPECT_EQ(counter.limitReached(), false);
    EXPECT_EQ(counter.limitReached(), true);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), false);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), false);
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), true);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), false);
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), true);
    EXPECT_EQ(counter.limitReached(), true);
}

TEST(EpsCounter, LimitReachedMultipleThreads)
{
    auto nThreads = 5;
    auto counter = std::make_shared<T::EpsCounter>(nThreads, 1, true);
    auto results = std::make_shared<std::vector<std::vector<bool>>>();

    for (auto i = 0; i < nThreads; i++)
    {
        results->emplace_back(std::vector<bool>());
    }
    std::vector<std::thread> threads;
    auto testFn = [](decltype(counter) counter, decltype(results) results, int i)
    {
        return [counter, results, i]()
        {
            results->at(i).emplace_back(counter->limitReached());
        };
    };

    for (auto i = 0; i < nThreads; i++)
    {
        threads.emplace_back(std::thread(testFn(counter, results, i)));
    }

    for (auto i = 0; i < nThreads; i++)
    {
        threads.at(i).join();
    }

    for (auto i = 0; i < nThreads; i++)
    {
        for (auto res : results->at(i))
        {
            EXPECT_EQ(res, false);
        }
    }

    counter = std::make_shared<T::EpsCounter>(nThreads - 1, 1, true);
    results = std::make_shared<std::vector<std::vector<bool>>>();
    for (auto i = 0; i < nThreads; i++)
    {
        results->emplace_back(std::vector<bool>());
    }
    for (auto i = 0; i < nThreads; i++)
    {
        threads.at(i) = std::thread(testFn(counter, results, i));
    }

    for (auto i = 0; i < nThreads; i++)
    {
        threads.at(i).join();
    }

    auto trueCount = 0;
    for (auto i = 0; i < nThreads; i++)
    {
        for (auto res : results->at(i))
        {
            if (res)
            {
                trueCount++;
            }
        }
    }

    EXPECT_EQ(trueCount, 1);
}
