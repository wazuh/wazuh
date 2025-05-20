#include <random>
#include <thread>

#include <benchmark/benchmark.h>
#include <fmt/format.h>

#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

#include <metrics/metricsManager.hpp>
using namespace metricsManager;

static constexpr char kBenchDbName[] = "bench";
static auto metricsManagerPtr = std::make_shared<MetricsManager>();
static auto kvdbManager = std::make_shared<kvdb_manager::KVDBManager>("/tmp/", metricsManagerPtr);

static void dbSetup(const benchmark::State& s)
{
    auto res = kvdbManager->getHandler(kBenchDbName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto db = std::get<kvdb_manager::KVDBHandle>(res);

    for (int i = 0; i < s.range(0); ++i)
    {
        db->write(fmt::format("user-{}", i), "action");
    }
}

static void dbTeardown(const benchmark::State& s)
{
    kvdbManager->unloadDB(kBenchDbName);
}

static void kvdbRead(benchmark::State& state)
{
    auto res = kvdbManager->getHandler(kBenchDbName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto db = std::get<kvdb_manager::KVDBHandle>(res);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, state.range(0));
    auto user = fmt::format("user-{}", distrib(gen));

    for (auto _ : state)
    {
        auto val = db->read(user);
        benchmark::DoNotOptimize(std::get<std::string>(val));
    }
}

BENCHMARK(kvdbRead)
    ->Setup(dbSetup)
    ->Teardown(dbTeardown)
    ->Range(8, 16 << 10)
    ->ThreadRange(1, std::thread::hardware_concurrency());

static void kvdbHasKey(benchmark::State& state)
{
    auto res = kvdbManager->getHandler(kBenchDbName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto db = std::get<kvdb_manager::KVDBHandle>(res);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, state.range(0));
    auto user = fmt::format("user-{}", distrib(gen));

    for (auto _ : state)
    {
        auto val = db->hasKey(user);
        benchmark::DoNotOptimize(val);
    }
}

BENCHMARK(kvdbHasKey)
    ->Setup(dbSetup)
    ->Teardown(dbTeardown)
    ->Range(8, 16 << 10)
    ->ThreadRange(1, std::thread::hardware_concurrency());

static void kvdbWrite(benchmark::State& state)
{
    auto res = kvdbManager->getHandler(kBenchDbName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto db = std::get<kvdb_manager::KVDBHandle>(res);

    std::vector<std::string> keys;
    for (int i = 0; i < state.range(0); ++i)
    {
        keys.push_back(fmt::format("user-{}", i));
    }

    for (auto _ : state)
    {
        for (auto const& key : keys)
        {
            db->write(key, "action");
        }

        state.PauseTiming();
        db->cleanColumn();
        state.ResumeTiming();
    }
}

BENCHMARK(kvdbWrite)->Setup(dbSetup)->Teardown(dbTeardown)->Range(8, 16 << 10);

static void kvdbWriteTx(benchmark::State& state)
{
    auto res = kvdbManager->getHandler(kBenchDbName);
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto db = std::get<kvdb_manager::KVDBHandle>(res);

    std::vector<std::pair<std::string, std::string>> keysList;
    for (int i = 0; i < state.range(0); ++i)
    {
        keysList.push_back({fmt::format("user-{}", i), "action"});
    }

    for (auto _ : state)
    {
        db->writeToTransaction(keysList);

        state.PauseTiming();
        db->cleanColumn();
        state.ResumeTiming();
    }
}

BENCHMARK(kvdbWriteTx)->Setup(dbSetup)->Teardown(dbTeardown)->Range(8, 16 << 10);
