#include <benchmark/benchmark.h>
#include <vector>

#include "operation_a.hpp"

using namespace std;
using namespace rxcpp;

template<class... Args>
void BM_IntAndOperationA(benchmark::State& state, Args&&... args)
{
    // Config
    auto args_tuple = make_tuple(move(args)...);
    const auto EVENTS = get<0>(args_tuple);
    const auto OPERATIONS = get<1>(args_tuple);

    // Tear Up
    vector<operation_a::Operation<int>> ops;
    for (auto i = 0; i < OPERATIONS; ++i)
    {
        ops.push_back(operation_a::Operation<int>(to_string(i),
                                                  [=](operation_a::OperationResult<int> r)
                                                  { return operation_a::OperationResult(true, r.event() + 1); }));
    }
    operation_a::CombinatorAnd<int> and_a("and", ops);

    // Input
    auto input = observable<>::create<operation_a::OperationResult<int>>(
                     [EVENTS](auto s)
                     {
                         for (auto i = 0; i < EVENTS; ++i)
                         {
                             s.on_next(operation_a::OperationResult<int>(false, i));
                         }
                         s.on_completed();
                     })
                     .publish();

    // Check
    auto total = 0;
    auto check_sub = make_subscriber<operation_a::OperationResult<int>>([&](auto r) { ++total; });
    and_a.connect(input).second.subscribe(check_sub);

    // Start
    for (auto _ : state)
    {
        input.connect();
        // Check that expected events are processed
        if (total != EVENTS)
        {
            string message =
                "Total events processed in iteration must be " + to_string(EVENTS) + ", but got " + to_string(total);
            state.SkipWithError(message.c_str());
            break;
        }
    }
    state.counters["operations"] = OPERATIONS;
    state.counters["events"] = EVENTS;
    state.counters["eventRate"] = benchmark::Counter(EVENTS, benchmark::Counter::kIsRate);
    state.counters["eventInvRate"] =
        benchmark::Counter(EVENTS, benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
}

// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10->10", 10, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "100->10", 100, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000->10", 1000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000->10", 10000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "100000->10", 100000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000000->10", 1000000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000000->10", 10000000, 10)->Unit(benchmark::kSecond);

// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10->100", 10, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "100->100", 100, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000->100", 1000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000->100", 10000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "100000->100", 100000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000000->100", 1000000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000000->100", 10000000, 100)->Unit(benchmark::kSecond);

BENCHMARK_CAPTURE(BM_IntAndOperationA, "10->1000", 10, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationA, "100->1000", 100, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000->1000", 1000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000->1000", 10000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationA, "100000->1000", 100000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationA, "1000000->1000", 1000000, 1000)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationA, "10000000->1000", 10000000, 1000)->Unit(benchmark::kSecond);

template<class... Args>
void BM_IntAndOperationRaw(benchmark::State& state, Args&&... args)
{
    // Config
    auto args_tuple = make_tuple(move(args)...);
    const auto EVENTS = get<0>(args_tuple);
    const auto OPERATIONS = get<1>(args_tuple);

    // Tear Up
    // Input
    auto input = observable<>::create<operation_a::OperationResult<int>>(
                     [EVENTS](auto s)
                     {
                         for (auto i = 0; i < EVENTS; ++i)
                         {
                             s.on_next(operation_a::OperationResult<int>(false, i));
                         }
                         s.on_completed();
                     })
                     .publish();
    observable<operation_a::OperationResult<int>> step = input;
    for (auto i = 0; i < OPERATIONS; ++i)
    {
        step = step.map([](auto r) { return operation_a::OperationResult(true, r.event() + 1); })
                   .filter([](auto r) { return r.success(); });
    }

    // Check
    auto total = 0;
    auto check_sub = make_subscriber<operation_a::OperationResult<int>>([&](auto r) { ++total; });
    step.subscribe(check_sub);

    // Start
    for (auto _ : state)
    {
        input.connect();
        // Check that expected events are processed
        if (total != EVENTS)
        {
            string message =
                "Total events processed in iteration must be " + to_string(EVENTS) + ", but got " + to_string(total);
            state.SkipWithError(message.c_str());
            break;
        }
    }
    state.counters["operations"] = OPERATIONS;
    state.counters["events"] = EVENTS;
    state.counters["eventRate"] = benchmark::Counter(EVENTS, benchmark::Counter::kIsRate);
    state.counters["eventInvRate"] =
        benchmark::Counter(EVENTS, benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
}

// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10->10", 10, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100->10", 100, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000->10", 1000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000->10", 10000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100000->10", 100000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000000->10", 1000000, 10)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000000->10", 10000000, 10)->Unit(benchmark::kSecond);

// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10->100", 10, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100->100", 100, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000->100", 1000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000->100", 10000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100000->100", 100000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000000->100", 1000000, 100)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000000->100", 10000000, 100)->Unit(benchmark::kSecond);

BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10->1000", 10, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100->1000", 100, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000->1000", 1000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000->1000", 10000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "100000->1000", 100000, 1000)->Unit(benchmark::kSecond);
BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "1000000->1000", 1000000, 1000)->Unit(benchmark::kSecond);
// BENCHMARK_CAPTURE(BM_IntAndOperationRaw, "10000000->1000", 10000000, 1000)->Unit(benchmark::kSecond);
