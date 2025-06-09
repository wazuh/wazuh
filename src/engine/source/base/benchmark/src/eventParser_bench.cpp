#include <benchmark/benchmark.h>
#include <string>
#include <memory>

#include <base/eventParser.hpp>

using namespace base::eventParsers;

// A helper wrapper that invokes parseLegacyEvent on a given std::string input.
static void BM_ParseLegacyEvent_Simple(benchmark::State& state) {
    // Simple “queue:location:message” without escapes or legacy prefix
    const std::string input = "1:location:message";
    for (auto _ : state) {
        auto ev = parseLegacyEvent(std::string(input));
        benchmark::DoNotOptimize(ev);
    }
}
BENCHMARK(BM_ParseLegacyEvent_Simple);

static void BM_ParseLegacyEvent_WithEscapes(benchmark::State& state) {
    // Location contains escaped colons (“|:”), message is short
    const std::string input = 
        "2:part1|:part2|:part3:payload";
    for (auto _ : state) {
        auto ev = parseLegacyEvent(std::string(input));
        benchmark::DoNotOptimize(ev);
    }
}
BENCHMARK(BM_ParseLegacyEvent_WithEscapes);

static void BM_ParseLegacyEvent_LongIPv6(benchmark::State& state) {
    // A longer example: IPv6‐style escaped location
    const std::string input = 
        "3:001|:0db8|:85a3|:0000|:0000|:8a2e|:0370|:7334:msg";
    for (auto _ : state) {
        auto ev = parseLegacyEvent(std::string(input));
        benchmark::DoNotOptimize(ev);
    }
}
BENCHMARK(BM_ParseLegacyEvent_LongIPv6);

static void BM_ParseLegacyEvent_LegacyLocation(benchmark::State& state) {
    // Legacy “[ID] Name->Module:message” format
    const std::string input = "4:[agent007] Alice Wonderland->dashboard:UserLogin";
    for (auto _ : state) {
        auto ev = parseLegacyEvent(std::string(input));
        benchmark::DoNotOptimize(ev);
    }
}
BENCHMARK(BM_ParseLegacyEvent_LegacyLocation);

static void BM_ParseLegacyEvent_LegacyWithEscapes(benchmark::State& state) {
    // Legacy prefix plus escaped colons in location and message
    const std::string input =
        "5:[xyz123] Agent|:007->server|:8080:payload|:data";
    for (auto _ : state) {
        auto ev = parseLegacyEvent(std::string(input));
        benchmark::DoNotOptimize(ev);
    }
}
BENCHMARK(BM_ParseLegacyEvent_LegacyWithEscapes);

BENCHMARK_MAIN();
