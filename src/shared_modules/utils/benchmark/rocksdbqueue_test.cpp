#include "rocksDBQueue.hpp"
#include <benchmark/benchmark.h>
#include <filesystem>
#include <system_error>

constexpr auto TEST_DB = "test.db";

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
