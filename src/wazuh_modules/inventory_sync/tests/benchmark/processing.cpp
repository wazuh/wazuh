#include "external/benchmark/benchmark.h"

static void BM_ReturnStringByValue(benchmark::State& state)
{
    for (auto _ : state)
    {
        // std::string result = secureComm.getParameter(AuthenticationParameter::SSL_CERTIFICATE);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ReturnStringByValue);

BENCHMARK_MAIN();
