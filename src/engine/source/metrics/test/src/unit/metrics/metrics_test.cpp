#include <gtest/gtest.h>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <base/functionExecutor.hpp>
#include <base/threadSynchronizer.hpp>

#include "metric/metric.hpp"

using namespace base::test;

namespace metrics::test
{
class TestMetric : public metrics::BaseOtMetric<uint64_t>
{
protected:
    void otUpdate(uint64_t value) override { updateCalls.fetch_add(1, std::memory_order_relaxed); }
    void otCreate() override { createCalls.fetch_add(1, std::memory_order_relaxed); }
    void otDestroy() override { destroyCalls.fetch_add(1, std::memory_order_relaxed); }

public:
    std::atomic_uint updateCalls = 0;
    std::atomic_uint createCalls = 0;
    std::atomic_uint destroyCalls = 0;

    TestMetric(std::string&& name, std::string&& description, std::string&& unit)
        : BaseOtMetric<uint64_t>(std::move(name), std::move(description), std::move(unit))
    {
    }
};

TEST(BaseMetricMultiThreadedTest, Enable)
{
    auto metric = std::make_shared<TestMetric>("name", "description", "unit");
    auto nThreads = 100;
    auto iterations = 100;
    ThreadSynchronizer sync(nThreads);

    for (auto iteration = 0; iteration < iterations; ++iteration)
    {
        metric->disable();
        std::vector<std::thread> threads;

        for (auto i = 0; i < nThreads; ++i)
        {
            threads.emplace_back(std::thread(
                [&sync, metric]
                {
                    sync.waitForAll();

                    metric->enable();
                }));
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_TRUE(metric->isEnabled());
    }
}

TEST(BaseMetricMultiThreadedTest, Disable)
{
    auto metric = std::make_shared<TestMetric>("name", "description", "unit");
    auto nThreads = 100;
    auto iterations = 100;
    ThreadSynchronizer sync(nThreads);

    for (auto iteration = 0; iteration < iterations; ++iteration)
    {
        metric->enable();
        std::vector<std::thread> threads;

        sync.reset();

        for (auto i = 0; i < nThreads; ++i)
        {
            threads.push_back(std::thread(
                [&, metric]
                {
                    sync.waitForAll();

                    metric->disable();
                }));
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_FALSE(metric->isEnabled());
    }
}

TEST(BaseMetricMultiThreadedTest, Update)
{
    auto nThreads = 100;
    auto iterations = 100;
    ThreadSynchronizer syncFirstPhase(nThreads);
    ThreadSynchronizer syncSecondPhase(nThreads);

    for (auto iteration = 0; iteration < iterations; ++iteration)
    {
        auto metric = std::make_shared<TestMetric>("name", "description", "unit");
        metric->enable();
        std::vector<std::thread> threads;

        syncFirstPhase.reset();
        syncSecondPhase.reset();

        for (auto i = 0; i < nThreads; ++i)
        {
            threads.push_back(std::thread(
                [&, metric]()
                {
                    syncFirstPhase.waitForAll();

                    metric->update(1);

                    syncSecondPhase.waitForAll();

                    metric->update(1);
                }));
        }

        syncFirstPhase.waitNotifyAll();
        syncSecondPhase.waitNotifyAll(
            [&, metric]()
            {
                ASSERT_EQ(metric->updateCalls, nThreads);
                metric->disable();
            });

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure that all threads have performed the first update only, the second update should not have been
        // performed due to the metric being disabled
        ASSERT_EQ(metric->updateCalls, nThreads);
    }
}

TEST(BaseMetricMultiThreadedTest, CreateDestroyUpdate)
{
    auto nThreads = 100;
    auto iterations = 100;
    ThreadSynchronizer sync(nThreads);

    for (auto iteration = 0; iteration < iterations; ++iteration)
    {
        auto metric = std::make_shared<TestMetric>("name", "description", "unit");
        if (iteration % 2 == 0)
        {
            metric->enable();
        }
        else
        {
            metric->disable();
        }

        std::vector<std::thread> threads;

        sync.reset();

        FunctionExecutor funcExec(
            [metric]() { metric->create(); }, [metric]() { metric->destroy(); }, [metric]() { metric->update(1); });
        for (auto i = 0; i < nThreads; ++i)
        {
            threads.push_back(std::thread(
                [&, metric]()
                {
                    sync.waitForAll();
                    funcExec.executeRoundRobinFunction();
                }));
        }

        sync.waitNotifyAll();

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure at least one thread has called create, destroy and update
        ASSERT_GT(metric->createCalls, 0);
        ASSERT_GT(metric->destroyCalls, 0);

        // If the metric was enabled, ensure that at least one thread has called update
        if (metric->isEnabled())
        {
            ASSERT_GT(metric->updateCalls, 0);
        }
        else
        {
            ASSERT_EQ(metric->updateCalls, 0);
        }
    }
}

} // namespace metrics::test
