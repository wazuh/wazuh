#include <benchmark/benchmark.h>

// Dummy benchmark to verify the benchmark framework is set up correctly.
static void BM_Dummy(benchmark::State& state)
{
    for (auto _ : state)
    {
        // Simulate some work.
        benchmark::DoNotOptimize(42);
    }
}
BENCHMARK(BM_Dummy);

BENCHMARK_MAIN();
