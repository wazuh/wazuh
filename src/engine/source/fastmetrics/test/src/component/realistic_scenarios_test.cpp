#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <queue>
#include <random>
#include <thread>
#include <vector>

#include <base/utils/singletonLocator.hpp>
#include <fastmetrics/registry.hpp>

/**
 * @file realistic_scenarios_test.cpp
 * @brief Component tests showing realistic production usage with cached metrics
 *
 * These tests demonstrate the OPTIMAL pattern:
 * - Lookup metrics ONCE (constructor, setup)
 * - Cache shared_ptr locally
 * - Use cached pointer in hot paths (zero overhead)
 */

class RealisticScenariosTest : public ::testing::Test
{
protected:
    void SetUp() override { fastmetrics::registerManager(); }

    void TearDown() override
    {
        // Unregister singleton for next test
        SingletonLocator::unregisterManager<fastmetrics::IManager>();
    }
};

/**
 * @test EventProcessingPipeline
 * @brief Simulates event processing with cached metrics (OPTIMAL pattern)
 */
TEST_F(RealisticScenariosTest, EventProcessingPipeline)
{
    const int NUM_WORKERS = 8;
    const int EVENTS_PER_WORKER = 1000;

    // Cache metrics ONCE before hot path
    auto& registry = fastmetrics::manager();
    auto eventsReceived = registry.getOrCreateCounter("events.received");
    auto eventsProcessed = registry.getOrCreateCounter("events.processed");
    auto eventsDropped = registry.getOrCreateCounter("events.dropped");
    auto bytesReceived = registry.getOrCreateCounter("bytes.received");

    std::atomic<int64_t> totalEvents {0};

    std::vector<std::thread> workers;
    for (int w = 0; w < NUM_WORKERS; ++w)
    {
        workers.emplace_back(
            [&, workerId = w]()
            {
                std::mt19937 rng(workerId);
                std::uniform_int_distribution<int> latencyDist(50, 200);
                std::uniform_int_distribution<int> sizeDist(100, 1000);

                for (int i = 0; i < EVENTS_PER_WORKER; ++i)
                {
                    // HOT PATH: Direct access via cached pointers (~3ns each)
                    eventsReceived->add();
                    bytesReceived->add(sizeDist(rng));

                    auto start = std::chrono::steady_clock::now();

                    // Simulate processing
                    std::this_thread::sleep_for(std::chrono::microseconds(latencyDist(rng) / 100));

                    auto end = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

                    // Simulate occasional drops (5%)
                    if (i % 20 == 0)
                    {
                        eventsDropped->add();
                    }
                    else
                    {
                        eventsProcessed->add();
                    }

                    totalEvents.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }

    for (auto& worker : workers)
    {
        worker.join();
    }

    // Verify results
    EXPECT_EQ(eventsReceived->get(), NUM_WORKERS * EVENTS_PER_WORKER);
    EXPECT_EQ(eventsProcessed->get() + eventsDropped->get(), NUM_WORKERS * EVENTS_PER_WORKER);
    EXPECT_GT(bytesReceived->get(), 0);
}

/**
 * @test WorkerPoolPattern
 * @brief Shows how workers cache metrics for optimal performance
 */
TEST_F(RealisticScenariosTest, WorkerPoolPattern)
{
    class Worker
    {
    private:
        int m_id;
        // Cached metrics (lookup ONCE in constructor)
        std::shared_ptr<fastmetrics::ICounter> m_tasksProcessed;
        std::shared_ptr<fastmetrics::ICounter> m_tasksFailed;

    public:
        explicit Worker(int id)
            : m_id(id)
        {
            auto& registry = fastmetrics::manager();
            std::string prefix = "worker." + std::to_string(id);

            // Lookup metrics ONCE
            m_tasksProcessed = registry.getOrCreateCounter(prefix + ".processed");
            m_tasksFailed = registry.getOrCreateCounter(prefix + ".failed");
        }

        void processTask(bool shouldFail = false)
        {
            // HOT PATH: Zero overhead, just atomics
            auto start = std::chrono::steady_clock::now();

            // Simulate work
            std::this_thread::sleep_for(std::chrono::microseconds(10));

            auto end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            if (shouldFail)
            {
                m_tasksFailed->add();
            }
            else
            {
                m_tasksProcessed->add();
            }
        }
    };

    const int NUM_WORKERS = 4;
    const int TASKS_PER_WORKER = 500;

    std::vector<Worker> workers;
    for (int i = 0; i < NUM_WORKERS; ++i)
    {
        workers.emplace_back(i);
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_WORKERS; ++i)
    {
        threads.emplace_back(
            [&workers, i, TASKS_PER_WORKER]()
            {
                for (int j = 0; j < TASKS_PER_WORKER; ++j)
                {
                    workers[i].processTask(j % 50 == 0); // 2% failure
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify each worker's metrics
    auto& registry = fastmetrics::manager();
    for (int i = 0; i < NUM_WORKERS; ++i)
    {
        std::string prefix = "worker." + std::to_string(i);
        auto processed = std::dynamic_pointer_cast<fastmetrics::ICounter>(registry.get(prefix + ".processed"));
        auto failed = std::dynamic_pointer_cast<fastmetrics::ICounter>(registry.get(prefix + ".failed"));

        ASSERT_NE(processed, nullptr);
        ASSERT_NE(failed, nullptr);
        EXPECT_EQ(processed->get() + failed->get(), TASKS_PER_WORKER);
    }
}

/**
 * @test DynamicMetricCreation
 * @brief Test creating metrics dynamically based on runtime data
 */
TEST_F(RealisticScenariosTest, DynamicMetricCreation)
{
    std::vector<std::string> modules = {"syscheck", "sca", "vulnerability", "syscollector"};
    const int EVENTS_PER_MODULE = 100;

    std::vector<std::thread> threads;

    for (const auto& module : modules)
    {
        threads.emplace_back(
            [&module, EVENTS_PER_MODULE]()
            {
                // Create module-specific metrics dynamically
                std::string metricName = "events.by_module." + module;
                auto counter = fastmetrics::manager().getOrCreateCounter(metricName);

                // Cache and use
                for (int i = 0; i < EVENTS_PER_MODULE; ++i)
                {
                    counter->add();
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify all module metrics were created
    auto& registry = fastmetrics::manager();
    for (const auto& module : modules)
    {
        std::string metricName = "events.by_module." + module;
        auto metric = registry.get(metricName);
        ASSERT_NE(metric, nullptr);

        auto counter = std::dynamic_pointer_cast<fastmetrics::ICounter>(metric);
        EXPECT_EQ(counter->get(), EVENTS_PER_MODULE);
    }
}

/**
 * @test HighFrequencyUpdates
 * @brief Stress test with very high update frequency
 */
TEST_F(RealisticScenariosTest, HighFrequencyUpdates)
{
    const int NUM_THREADS = 16;
    const int UPDATES_PER_THREAD = 100000;

    // Cache metric ONCE before hot path
    auto counter = fastmetrics::manager().getOrCreateCounter("stress.counter");

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&counter, UPDATES_PER_THREAD]()
            {
                // HOT PATH: Maximum performance
                for (int i = 0; i < UPDATES_PER_THREAD; ++i)
                {
                    counter->add();
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify no updates were lost
    EXPECT_EQ(counter->get(), NUM_THREADS * UPDATES_PER_THREAD);
}
