#include <benchmark/benchmark.h>

#include <memory>
#include <string>
#include <vector>

#include <agentcache/agentMetadataCache.hpp>
#include <fastmetrics/registry.hpp>

using namespace agentcache;
using namespace std::chrono_literals;

// =============================================================================
// Test data
// =============================================================================

namespace
{
// Register the fastmetrics manager before main() runs: the cache resolves its counters from it.
struct FastMetricsInit
{
    FastMetricsInit() { fastmetrics::registerManager(); }
};
static FastMetricsInit fastMetricsInit_;
} // namespace

static std::string makeHeader(int agentNum)
{
    std::string id = std::to_string(agentNum);
    while (id.size() < 3)
    {
        id = "0" + id;
    }
    return R"({"wazuh":{"agent":{"id":")" + id + R"(","name":"agent-)" + id
           + R"(","version":"5.0.0","host":{"hostname":"host-)" + id
           + R"(","os":{"name":"Ubuntu","platform":"linux","version":"24.04"}}}}})";
}

static const std::string HEADER_001 = makeHeader(1);

// =============================================================================
// Benchmarks
// =============================================================================

/**
 * Baseline: parse a header JSON without any cache (raw json::Json construction).
 * This measures the cost we are trying to avoid.
 */
static void BM_Baseline_ParseOnly(benchmark::State& state)
{
    for (auto _ : state)
    {
        auto parsed = std::make_shared<const json::Json>(std::string_view(HEADER_001));
        benchmark::DoNotOptimize(parsed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Baseline_ParseOnly);

/**
 * Cache hit path: repeated lookups for the same header.
 * Measures the best-case read performance.
 */
static void BM_GetOrParse_CacheHit(benchmark::State& state)
{
    AgentMetadataCache cache(60s);
    cache.getOrParse(HEADER_001); // Warm up

    for (auto _ : state)
    {
        auto result = cache.getOrParse(HEADER_001);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GetOrParse_CacheHit);

/**
 * Cache miss path: each iteration uses a unique header that has never been seen.
 * Measures the parse + insert cost.
 *
 * Headers are pre-generated outside the timed loop (indexed by iteration) so the
 * measurement reflects only getOrParse's cost — PauseTiming/ResumeTiming per iteration
 * would add far more overhead than the string construction it hides.
 */
static void BM_GetOrParse_CacheMiss(benchmark::State& state)
{
    AgentMetadataCache cache(60s);

    // Distinct agent id per element -> every lookup is a genuine miss (one entry per agent).
    std::vector<std::string> headers;
    for (int64_t i = 0; i < state.max_iterations; ++i)
    {
        headers.push_back(makeHeader(static_cast<int>(i) + 1));
    }

    int64_t idx = 0;
    for (auto _ : state)
    {
        auto result = cache.getOrParse(headers[idx++]);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GetOrParse_CacheMiss);

/**
 * Multi-agent round-robin: simulate realistic traffic from N agents
 * where headers repeat cyclically.
 */
static void BM_GetOrParse_MultiAgent(benchmark::State& state)
{
    const int numAgents = state.range(0);
    AgentMetadataCache cache(60s);

    std::vector<std::string> headers;
    headers.reserve(numAgents);
    for (int i = 1; i <= numAgents; ++i)
    {
        headers.push_back(makeHeader(i));
    }

    // Warm up all entries
    for (auto& h : headers)
    {
        cache.getOrParse(h);
    }

    int idx = 0;
    for (auto _ : state)
    {
        auto result = cache.getOrParse(headers[idx % numAgents]);
        benchmark::DoNotOptimize(result);
        ++idx;
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GetOrParse_MultiAgent)->Arg(10)->Arg(50)->Arg(100)->Arg(500);

/**
 * Multi-threaded benchmark: concurrent getOrParse from multiple threads.
 * Measures contention and scalability.
 */
static void BM_GetOrParse_Concurrent(benchmark::State& state)
{
    static AgentMetadataCache cache(60s);
    static std::vector<std::string> headers = []()
    {
        std::vector<std::string> h;
        for (int i = 1; i <= 20; ++i)
        {
            h.push_back(makeHeader(i));
        }
        return h;
    }();

    // Warm up on thread 0 only.  Google Benchmark rendezvouses all threads at the start of
    // the timed loop (state.begin() -> StartKeepRunning barrier), so this warmup is
    // guaranteed to complete and be visible before any thread runs its first timed lookup.
    if (state.thread_index() == 0)
    {
        cache.clear();
        for (auto& h : headers)
        {
            cache.getOrParse(h);
        }
    }

    int idx = state.thread_index();
    for (auto _ : state)
    {
        auto result = cache.getOrParse(headers[idx % headers.size()]);
        benchmark::DoNotOptimize(result);
        ++idx;
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GetOrParse_Concurrent)->ThreadRange(1, 8);
