#include "rocksDBQueue.hpp"
#include "rocksDBQueueCF.hpp"
#include <benchmark/benchmark.h>
#include <filesystem>
#include <system_error>

constexpr auto TEST_DB = "test.db";
constexpr auto TEST_CF_DB = "test_cf.db";

constexpr auto TEST_AGENT_NUMBER {1000};
constexpr auto TEST_EVENTS_PER_AGENT {10000};
constexpr auto TEST_THREADS {4};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

static void pushBenchmark(benchmark::State& state)
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_DB, ec);

    RocksDBQueue<std::string> queue(TEST_DB);
    for (auto _ : state)
    {
        queue.push("test");
    }
}

BENCHMARK(pushBenchmark);

static void popBenchmark(benchmark::State& state)
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_DB, ec);

    RocksDBQueue<std::string> queue(TEST_DB);

    for (auto _ : state)
    {
        state.PauseTiming();
        queue.push("test");
        state.ResumeTiming();
        queue.pop();
    }
}

BENCHMARK(popBenchmark);

static void frontBenchmark(benchmark::State& state)
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_DB, ec);

    RocksDBQueue<std::string> queue(TEST_DB);
    queue.push("test");

    for (auto _ : state)
    {
        queue.front();
    }
}

BENCHMARK(frontBenchmark);

class ThreadPoolBenchmarkFixture : public benchmark::Fixture
{
protected:
    std::shared_ptr<RocksDBQueue<std::string>> queue;                   ///< RocksDB queue.
    std::vector<std::shared_ptr<RocksDBQueueCF<std::string>>> queueCFs; ///< RocksDB queue with column family.

public:
    /**
     * @brief Benchmark setup routine.
     *
     * @param state Benchmark state.
     */
    void SetUp(const ::benchmark::State& state) override
    {
        std::error_code ec;
        std::filesystem::remove_all(TEST_DB, ec);
        queue = std::make_shared<RocksDBQueue<std::string>>(TEST_DB);

        for (int i = 0; i < TEST_THREADS; ++i)
        {
            std::filesystem::remove_all(TEST_CF_DB + std::to_string(i), ec);
            queueCFs.emplace_back(std::make_shared<RocksDBQueueCF<std::string>>(TEST_CF_DB + std::to_string(i)));
        }
    }

    /**
     * @brief Benchmark teardown routine.
     *
     * @param state Benchmark state.
     */
    void TearDown(const ::benchmark::State& state) override
    {
        queue.reset();

        for (auto& queueCF : queueCFs)
        {
            queueCF.reset();
        }
    }
};

BENCHMARK_DEFINE_F(ThreadPoolBenchmarkFixture, ThreadPoolPerformance)(benchmark::State& state)
{
    std::atomic<bool> stop {false};
    std::vector<std::thread> threads;

    auto cfLambda = [&](int threadIndex)
    {
        while (!stop)
        {
            for (int i = 0; i < TEST_AGENT_NUMBER; ++i)
            {
                if (stop)
                {
                    break;
                }
                for (int j = 0; j < TEST_EVENTS_PER_AGENT; ++j)
                {
                    if (stop)
                    {
                        break;
                    }
                    queueCFs.at(threadIndex)->push(std::to_string(i), "test");
                }
            }

            for (int i = 0; i < TEST_AGENT_NUMBER; ++i)
            {
                if (stop)
                {
                    break;
                }
                queueCFs.at(threadIndex)->clear(std::to_string(i));
            }
        }
    };

    for (int i = 0; i < TEST_THREADS; ++i)
    {
        threads.emplace_back(cfLambda, i);
    }

    for (auto _ : state)
    {
        for (int i = 0; i < TEST_AGENT_NUMBER; ++i)
        {
            for (int j = 0; j < TEST_EVENTS_PER_AGENT; ++j)
            {
                queue->push("test");
            }
        }

        for (int i = 0; i < TEST_AGENT_NUMBER; ++i)
        {
            for (int j = 0; j < TEST_EVENTS_PER_AGENT; ++j)
            {
                queue->pop();
            }
        }
    }

    stop.store(true);
    for (auto& thread : threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }
}

BENCHMARK_REGISTER_F(ThreadPoolBenchmarkFixture, ThreadPoolPerformance)->Iterations(1)->Threads(1);
