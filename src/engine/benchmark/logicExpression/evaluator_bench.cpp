#include <benchmark/benchmark.h>

#include <logicexpr/logicexpr.hpp>

static void BM_DijkstraEvaluator(benchmark::State& state)
{
     auto fakeTermBuilder = [](std::string s) -> std::function<bool(int)>
    {
        if (s == "even")
        {
            return [](int i)
            {
                return i % 2 == 0;
            };
        }
        else if (s == "odd")
        {
            return [](int i)
            {
                return i % 2 != 0;
            };
        }
        else if (s == "great5")
        {
            return [](int i)
            {
                return i > 5;
            };
        }
        else if (s == "great1")
        {
            return [](int i)
            {
                return i > 1;
            };
        }
        else
        {
            throw std::runtime_error(
                "Error test fakeBuilder, got unexpected term: " + s);
        }
    };

    parsec::Parser<std::string> termP = [](std::string_view text, size_t pos) -> parsec::Result<std::string>
    {
        // Until space, ( or ) without including it
        auto end = text.find_first_of(" ()", pos);
        if (end == std::string_view::npos)
        {
            end = text.size();
        }
        // the keyword cannot be a operator, so we check it here
        if (std::isupper(text[pos]) || text[pos] == '(' || text[pos] == ')')
        {
            return parsec::makeError<std::string>("Unexpected token", pos);
        }
        return parsec::makeSuccess<std::string>(std::string {text.substr(pos, end - pos)}, end);
    };

    auto expression = "(even OR odd AND NOT great5) AND great1";
    std::function<bool(int)> evaluator = logicexpr::buildDijstraEvaluator<int, std::string>(expression, fakeTermBuilder, termP);

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
