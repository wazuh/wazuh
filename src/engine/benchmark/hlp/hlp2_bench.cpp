#include <benchmark/benchmark.h>

#include <random>
#include <string>

#include "poc_parsec.hpp"
#include <hlp/hlp.hpp>

std::string randomString(int size)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(97, 122); // ASCII values for lowercase letters

    std::string randomString;
    randomString.reserve(size);

    for (int i = 0; i < size; ++i)
    {
        randomString.push_back(static_cast<char>(dis(gen)));
    }

    return randomString;
}

static void BM_literalSuccess(benchmark::State& state)
{
    std::string input = randomString(state.range(0));
    std::string_view inputView(input);
    auto literalP = hlp::getLiteralParser("literal", {}, {input});

    for (auto _ : state)
    {
        auto result = literalP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
    }
}
BENCHMARK(BM_literalSuccess)->RangeMultiplier(2)->Range(1, 100);

static void BM_literalFailure(benchmark::State& state)
{
    std::string input = randomString(state.range(0));
    std::string_view inputView(input);
    auto literalP = hlp::getLiteralParser("literal", {}, {input + "a"});

    for (auto _ : state)
    {
        auto result = literalP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_literalFailure)->RangeMultiplier(2)->Range(1, 100);

static void BM_literalAndSuccess(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = hlp::getLiteralParser("literal", {}, {literal});
    auto literalAndP = literalP & literalP;

    for (auto _ : state)
    {
        auto result = literalAndP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
    }
}
BENCHMARK(BM_literalAndSuccess)->RangeMultiplier(2)->Range(1, 100);

static void BM_literalAndFailureFirst(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = hlp::getLiteralParser("literal", {}, {literal + "a"});
    auto literalAndP = literalP & literalP;

    for (auto _ : state)
    {
        auto result = literalAndP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_literalAndFailureFirst)->RangeMultiplier(2)->Range(1, 100);

static void BM_literalAndFailureSecond(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = hlp::getLiteralParser("literal", {}, {literal});
    auto literalPF = hlp::getLiteralParser("literal", {}, {literal + "a"});
    auto literalAndP = literalP & literalPF;

    for (auto _ : state)
    {
        auto result = literalAndP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_literalAndFailureSecond)->RangeMultiplier(2)->Range(1, 100);

static void BM_literalList16Success(benchmark::State& state)
{
    std::string literal = randomString(16);
    auto size = state.range(0);

    std::string input;
    for (int i = 0; i < size; ++i)
    {
        input += literal;
    }
    std::string_view inputView(input);

    auto literalP = hlp::getLiteralParser("literal", {}, {literal});
    auto literalManyP = parsec::many1(literalP);

    for (auto _ : state)
    {
        auto result = literalManyP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
    }
}
BENCHMARK(BM_literalList16Success)->RangeMultiplier(2)->Range(1, 32);

static void BM_literalList16Failure(benchmark::State& state)
{
    std::string literal = randomString(16);
    auto size = state.range(0);

    std::string input;
    for (int i = 0; i < size; ++i)
    {
        input += literal;
    }
    std::string_view inputView(input);

    auto literalP = hlp::getLiteralParser("literal", {}, {randomString(16)});
    auto literalManyP = parsec::many1(literalP);

    for (auto _ : state)
    {
        auto result = literalManyP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_literalList16Failure)->RangeMultiplier(2)->Range(1, 32);

static void BM_pocLiteralSuccess(benchmark::State& state)
{
    std::string input = randomString(state.range(0));
    std::string_view inputView(input);
    auto literalP = pocParsers::synLiteral(input, input, "");

    for (auto _ : state)
    {
        auto result = literalP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }

        auto semResult = result.value().semParser(result.value().parsed);
        benchmark::DoNotOptimize(semResult);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_pocLiteralSuccess)->RangeMultiplier(2)->Range(1, 100);

static void BM_pocLiteralFailure(benchmark::State& state)
{
    std::string input = randomString(state.range(0));
    std::string_view inputView(input);
    auto literalP = pocParsers::synLiteral(input + "a", input + "a", "");

    for (auto _ : state)
    {
        auto result = literalP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocLiteralFailure)->RangeMultiplier(2)->Range(1, 100);

static void BM_pocLiteralAndSuccess(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = pocParsers::synLiteral(literal, literal, "");
    auto literalAndP = literalP & literalP;

    for (auto _ : state)
    {
        auto result = literalAndP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }

        auto semResultL = result.nested()[0].value().semParser(result.nested()[0].value().parsed);
        benchmark::DoNotOptimize(semResultL);
        benchmark::ClobberMemory();

        auto semResultR = result.nested()[1].value().semParser(result.nested()[1].value().parsed);
        benchmark::DoNotOptimize(semResultR);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_pocLiteralAndSuccess)->RangeMultiplier(2)->Range(1, 100);

static void BM_pocLiteralAndFailureFirst(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = pocParsers::synLiteral(literal, literal, "");
    auto literalAndP = pocParsers::synLiteral(literal + "a", literal + "a", "") & literalP;

    for (auto _ : state)
    {
        auto result = literalAndP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocLiteralAndFailureFirst)->RangeMultiplier(2)->Range(1, 100);

static void BM_pocLiteralAndFailureSecond(benchmark::State& state)
{
    std::string literal = randomString(state.range(0));
    std::string input = literal + literal;
    std::string_view inputView(input);
    auto literalP = pocParsers::synLiteral(literal, literal, "");
    auto literalAndP = literalP & pocParsers::synLiteral(literal + "a", literal + "a", "");

    for (auto _ : state)
    {
        auto result = literalAndP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocLiteralAndFailureSecond)->RangeMultiplier(2)->Range(1, 100);

static void BM_pocLiteralList16Success(benchmark::State& state)
{
    std::string literal = randomString(16);
    auto size = state.range(0);

    std::string input;
    for (int i = 0; i < size; ++i)
    {
        input += literal;
    }
    std::string_view inputView(input);

    auto literalP = pocParsers::synLiteral(literal, literal, "");
    auto literalManyP = hlpc::repeat(literalP, size);

    for (auto _ : state)
    {
        auto result = literalManyP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }

        for (auto& nested : result.nested())
        {
            auto semResult = nested.value().semParser(nested.value().parsed);
            benchmark::DoNotOptimize(semResult);
            benchmark::ClobberMemory();
        }
    }
}
BENCHMARK(BM_pocLiteralList16Success)->RangeMultiplier(2)->Range(1, 32);

static void BM_pocLiteralList16Failure(benchmark::State& state)
{
    std::string literal = randomString(16);
    auto size = state.range(0);

    std::string input;
    for (int i = 0; i < size; ++i)
    {
        input += literal;
    }
    std::string_view inputView(input);

    auto literalFail = randomString(16);

    auto literalP = pocParsers::synLiteral(literalFail, literalFail, "");
    auto literalManyP = hlpc::repeat(literalP, size);

    for (auto _ : state)
    {
        auto result = literalManyP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocLiteralList16Failure)->RangeMultiplier(2)->Range(1, 32);

static void BM_ipSuccess(benchmark::State& state)
{
    std::string input = "192.168.0.23";
    std::string_view inputView(input);

    auto ipP = hlp::getIPParser("ip", {""}, {});

    for (auto _ : state)
    {
        auto result = ipP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
    }
}
BENCHMARK(BM_ipSuccess);

static void BM_ipFailure(benchmark::State& state)
{
    std::string input = "198.168.0.";
    std::string_view inputView(input);

    auto ipP = hlp::getIPParser("ip", {""}, {});

    for (auto _ : state)
    {
        auto result = ipP(inputView, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_ipFailure);

static void BM_pocIpSuccess(benchmark::State& state)
{
    std::string input = "192.168.0.23";
    std::string_view inputView(input);

    auto ipP = pocParsers::ipParser("ip", "");

    for (auto _ : state)
    {
        auto result = ipP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }

        auto semResult = result.value().semParser(result.value().parsed);
        if (std::holds_alternative<base::Error>(semResult))
        {
            state.SkipWithError("Semantic parsing failed");
        }
    }
}
BENCHMARK(BM_pocIpSuccess);

static void BM_pocIpFailure(benchmark::State& state)
{
    std::string input = "192.168.0.";
    std::string_view inputView(input);

    auto ipP = pocParsers::ipParser("ip", "");

    for (auto _ : state)
    {
        auto result = ipP(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocIpFailure);

static void BM_litIpLitSuccess(benchmark::State& state)
{
    std::string lit = randomString(8);
    std::string ip = "192.168.0.24";
    std::string input = lit + ip + lit;

    auto litP = hlp::getLiteralParser(lit, {}, {lit});
    std::string endTip {};
    endTip = lit[0];
    auto ipP = hlp::getIPParser("ip", {endTip}, {});
    auto p = litP & ipP & litP;

    for (auto _ : state)
    {
        auto result = p(input, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
    }
}
BENCHMARK(BM_litIpLitSuccess);

static void BM_litIpLitFailureLastLit(benchmark::State& state)
{
    std::string lit = randomString(8);
    std::string ip = "192.168.0.24";
    std::string input = lit + ip + lit;

    auto litP = hlp::getLiteralParser(lit, {}, {lit});
    auto litPF = hlp::getLiteralParser(lit + "a", {}, {lit + "a"});
    std::string endTip {};
    endTip = lit[0];
    auto ipP = hlp::getIPParser("ip", {endTip}, {});
    auto p = litP & ipP & litPF;

    for (auto _ : state)
    {
        auto result = p(input, 0);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_litIpLitFailureLastLit);

static void BM_pocLitIpLitSuccess(benchmark::State& state)
{
    std::string lit = randomString(8);
    std::string ip = "192.168.0.24";
    std::string input = lit + ip + lit;
    std::string_view inputView(input);

    auto litP = pocParsers::synLiteral(lit, lit, "");
    auto ipP = pocParsers::ipParser("ip", "");
    auto p = litP & ipP & litP;

    for (auto _ : state)
    {
        auto result = p(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }

        std::vector<hlpc::SemToken> semTokens;
        auto semVisitor = [&semTokens](const hlpc::Result& result, auto& recurRef) -> std::optional<base::Error>
        {
            if (result.hasValue())
            {
                auto res = result.value().semParser(result.value().parsed);
                if (std::holds_alternative<base::Error>(res))
                {
                    return std::get<base::Error>(res);
                }

                semTokens.emplace_back(std::get<hlpc::SemToken>(std::move(res)));
            }

            for (const auto& child : result.nested())
            {
                auto error = recurRef(child, recurRef);
                if (error)
                {
                    return std::move(error);
                }
            }

            return std::nullopt;
        };

        auto error = semVisitor(result, semVisitor);
        if (error)
        {
            state.SkipWithError(std::string(std::string("Semantic parsing failed: ") + error.value().message).c_str());
        }
    }
}
BENCHMARK(BM_pocLitIpLitSuccess);

static void BM_pocLitIpLitFailureLastLit(benchmark::State& state)
{
    std::string lit = randomString(8);
    std::string ip = "192.168.0.24";
    std::string input = lit + ip + lit;
    std::string_view inputView(input);

    auto litP = pocParsers::synLiteral(lit, lit, "");
    auto litPF = pocParsers::synLiteral(lit + "a", lit + "a", "");
    auto ipP = pocParsers::ipParser("ip", "");
    auto p = litP & ipP & litPF;

    for (auto _ : state)
    {
        auto result = p(inputView);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();

        if (result.success())
        {
            state.SkipWithError("Parsing succeeded");
        }
    }
}
BENCHMARK(BM_pocLitIpLitFailureLastLit);
