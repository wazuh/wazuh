#include <benchmark/benchmark.h>
#include <logicExpression/logicExpression.hpp>

using namespace std;

static void BM_DijkstraEvaluator(benchmark::State& state)
{
    auto fakeTermBuilder = [](string s) -> function<bool(int)>
    {
        if (s == "PAIR")
        {
            return [](int i)
            {
                return i % 2 == 0;
            };
        }
        else if (s == "ODD")
        {
            return [](int i)
            {
                return i % 2 != 0;
            };
        }
        else if (s == "GREAT5")
        {
            return [](int i)
            {
                return i > 5;
            };
        }
        else if (s == "GREAT1")
        {
            return [](int i)
            {
                return i > 1;
            };
        }
        else
        {
            throw runtime_error(
                "Error test fakeBuilder, got unexpected term: " + s);
        }
    };

    // Build function
    auto evaluator = logicExpression::buildDijstraEvaluator<int>(
        "(PAIR OR ODD AND NOT GREAT5) AND GREAT1", fakeTermBuilder);

    // Benchamark
    for (auto _ : state)
    {
        bool result = true;
        for (auto i = 0; i < state.range(0); ++i)
        {
            benchmark::DoNotOptimize(result = result && evaluator(i));
        }
    }
}

// Benchmarks

BENCHMARK(BM_DijkstraEvaluator)
    ->RangeMultiplier(10)->Range(1, 10000000)
    ->Unit(benchmark::kMicrosecond);
