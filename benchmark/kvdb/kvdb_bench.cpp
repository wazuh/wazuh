#include <random>
#include <thread>

#include <benchmark/benchmark.h>
#include <fmt/format.h>

#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>

static constexpr char kBenchDbName[] = "bench";
static auto kvdbManager = std::make_shared<KVDBManager>("/tmp/");

static void dbSetup(const benchmark::State& s)
{
    auto db = kvdbManager->addDb(kBenchDbName);

    for (int i = 0; i < s.range(0); ++i)
    {
        db->write(fmt::format("user-{}", i), "action");
    }
}

static void dbTeardown(const benchmark::State& s)
{
    kvdbManager->deleteDB(kBenchDbName);
}

static void kvdbRead(benchmark::State& state)
{
    auto db = kvdbManager->getDB(kBenchDbName);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, state.range(0));
    auto user = fmt::format("user-{}", distrib(gen));

    for (auto _ : state)
    {
        auto val = db->read(user);
        benchmark::DoNotOptimize(val.data());
    }
}

BENCHMARK(kvdbRead)
    ->Setup(dbSetup)
    ->Teardown(dbTeardown)
    ->Range(8, 16 << 10)
    ->ThreadRange(1, std::thread::hardware_concurrency());

static void kvdbHasKey(benchmark::State& state)
{
    auto db = kvdbManager->getDB(kBenchDbName);

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
    auto db = kvdbManager->getDB(kBenchDbName);

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
    auto db = kvdbManager->getDB(kBenchDbName);

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

BENCHMARK(kvdbWriteTx)
    ->Setup(dbSetup)
    ->Teardown(dbTeardown)
    ->Range(8, 16 << 10);
