/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <wazuh_metrics/manager.hpp>

/**
 * @file realisticScenarios_test.cpp
 * @brief Concurrency tests showing realistic production usage with cached metrics.
 *
 * wazuh_metrics has no process-wide singleton: each daemon owns a Manager and
 * injects it. These tests instantiate a local Manager per test (no
 * SingletonLocator) and demonstrate the OPTIMAL pattern:
 * - Lookup metrics ONCE (constructor, setup)
 * - Cache shared_ptr locally
 * - Use cached pointer in hot paths (zero overhead)
 */

using namespace wazuh::metrics;

class RealisticScenariosTest : public ::testing::Test
{
protected:
    Manager manager;
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
    auto eventsReceived = manager.getOrCreateCounter("events.received");
    auto eventsProcessed = manager.getOrCreateCounter("events.processed");
    auto eventsDropped = manager.getOrCreateCounter("events.dropped");
    auto bytesReceived = manager.getOrCreateCounter("bytes.received");

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
    EXPECT_EQ(eventsReceived->get(), static_cast<uint64_t>(NUM_WORKERS) * EVENTS_PER_WORKER);
    EXPECT_EQ(eventsProcessed->get() + eventsDropped->get(), static_cast<uint64_t>(NUM_WORKERS) * EVENTS_PER_WORKER);
    EXPECT_GT(bytesReceived->get(), 0U);
}

/**
 * @test WorkerPoolPattern
 * @brief Shows how workers cache metrics for optimal performance, backed by a
 * shared local Manager injected at construction time.
 */
TEST_F(RealisticScenariosTest, WorkerPoolPattern)
{
    class Worker
    {
    private:
        // Cached metrics (lookup ONCE in constructor)
        std::shared_ptr<ICounter> m_tasksProcessed;
        std::shared_ptr<ICounter> m_tasksFailed;

    public:
        Worker(Manager& registry, int id)
        {
            std::string prefix = "worker." + std::to_string(id);

            // Lookup metrics ONCE
            m_tasksProcessed = registry.getOrCreateCounter(prefix + ".processed");
            m_tasksFailed = registry.getOrCreateCounter(prefix + ".failed");
        }

        void processTask(bool shouldFail = false)
        {
            // HOT PATH: Zero overhead, just atomics
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
        workers.emplace_back(manager, i);
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
    for (int i = 0; i < NUM_WORKERS; ++i)
    {
        std::string prefix = "worker." + std::to_string(i);
        auto processed = std::dynamic_pointer_cast<ICounter>(manager.get(prefix + ".processed"));
        auto failed = std::dynamic_pointer_cast<ICounter>(manager.get(prefix + ".failed"));

        ASSERT_NE(processed, nullptr);
        ASSERT_NE(failed, nullptr);
        EXPECT_EQ(processed->get() + failed->get(), static_cast<uint64_t>(TASKS_PER_WORKER));
    }
}

/**
 * @test DynamicMetricCreation
 * @brief Test creating metrics dynamically based on runtime data, from
 * multiple threads racing getOrCreate on distinct names.
 */
TEST_F(RealisticScenariosTest, DynamicMetricCreation)
{
    std::vector<std::string> modules = {"syscheck", "sca", "vulnerability", "syscollector"};
    const int EVENTS_PER_MODULE = 100;

    std::vector<std::thread> threads;

    for (const auto& module : modules)
    {
        threads.emplace_back(
            [this, &module, EVENTS_PER_MODULE]()
            {
                // Create module-specific metrics dynamically
                std::string metricName = "events.by_module." + module;
                auto counter = manager.getOrCreateCounter(metricName);

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
    for (const auto& module : modules)
    {
        std::string metricName = "events.by_module." + module;
        auto metric = manager.get(metricName);
        ASSERT_NE(metric, nullptr);

        auto counter = std::dynamic_pointer_cast<ICounter>(metric);
        EXPECT_EQ(counter->get(), static_cast<uint64_t>(EVENTS_PER_MODULE));
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
    auto counter = manager.getOrCreateCounter("stress.counter");

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
    EXPECT_EQ(counter->get(), static_cast<uint64_t>(NUM_THREADS) * UPDATES_PER_THREAD);
}

/**
 * @test MixedMetricTypesUnderConcurrency
 * @brief Exercises counter, gauge and histogram concurrently through the same
 * Manager to catch cross-type registration races.
 */
TEST_F(RealisticScenariosTest, MixedMetricTypesUnderConcurrency)
{
    const int NUM_THREADS = 8;
    const int OBSERVATIONS_PER_THREAD = 2000;

    auto counter = manager.getOrCreateCounter("mixed.events");
    auto gauge = manager.getOrCreateGaugeInt("mixed.inflight");
    auto histogram = manager.getOrCreateHistogram("mixed.latency");

    std::vector<std::thread> threads;
    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&, threadId = t]()
            {
                std::mt19937 rng(threadId);
                std::uniform_int_distribution<int> latencyDist(1, 1000);

                for (int i = 0; i < OBSERVATIONS_PER_THREAD; ++i)
                {
                    counter->add();
                    gauge->add(1);
                    histogram->observe(static_cast<uint64_t>(latencyDist(rng)));
                    gauge->sub(1);
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(counter->get(), static_cast<uint64_t>(NUM_THREADS) * OBSERVATIONS_PER_THREAD);
    EXPECT_EQ(gauge->get(), 0); // as many adds as subs
    EXPECT_EQ(histogram->snapshot().count, static_cast<uint64_t>(NUM_THREADS) * OBSERVATIONS_PER_THREAD);
}
