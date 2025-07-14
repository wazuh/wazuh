#include <benchmark/benchmark.h>
#include <streamlog/logger.hpp>

#include <thread>

// Dummy benchmark to ensure the logger compiles and links correctly
static void BM_LoggerInitialization(benchmark::State& state)
{
    for (auto _ : state)
    {
        // Sleep for a short duration to simulate work
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    state.SetItemsProcessed(state.iterations());
}


BENCHMARK(BM_LoggerInitialization);
BENCHMARK_MAIN();
