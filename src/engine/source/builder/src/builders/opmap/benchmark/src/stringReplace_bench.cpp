// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <base/baseTypes.hpp>
#include <base/json.hpp>
#include <builder/allowedFields.hpp>
#include <fmt/format.h>

#include "builders/argument.hpp"
#include "builders/buildCtx.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

namespace
{

using namespace builder::builders;

/**
 * @brief Measure the op returned by opBuilderHelperStringReplace over a field of the given size.
 *
 * The op mutates the event, so the original event is restored outside the timed region.
 * @param state Benchmark state (range(0) is the field size in bytes).
 * @param fill Character used to fill the field.
 * @param oldStr Substring to replace.
 * @param newStr Replacement.
 * @param refreshPeriod Restore the event every this many iterations (the first one included).
 */
void runReplace(
    benchmark::State& state, char fill, const std::string& oldStr, const std::string& newStr, int64_t refreshPeriod)
{
    const auto n = static_cast<size_t>(state.range(0));

    Context ctx {};
    ctx.assetName = "decoder/bench/0";
    auto buildCtx = std::make_shared<BuildCtx>(
        false, ctx, nullptr, nullptr, nullptr, std::make_shared<builder::AllowedFields>(), nullptr, false);

    const std::vector<OpArg> args {std::make_shared<Value>(json::Json(fmt::format("\"{}\"", oldStr).c_str())),
                                   std::make_shared<Value>(json::Json(fmt::format("\"{}\"", newStr).c_str()))};
    auto op = opBuilderHelperStringReplace(Reference {"target"}, args, buildCtx);

    json::Json original;
    original.setObject();
    original.setString(std::string(n, fill), "/target");

    base::Event event;
    int64_t counter = 0;
    for (auto _ : state)
    {
        if (counter++ % refreshPeriod == 0)
        {
            state.PauseTiming();
            event = std::make_shared<json::Json>(original);
            state.ResumeTiming();
        }
        auto result = op(event);
        benchmark::DoNotOptimize(result);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * state.range(0));
}

// Every byte matches and the replacement is longer (output grows).
void BM_ReplaceHelper_Grow(benchmark::State& state)
{
    runReplace(state, '-', "-", "++", 1);
}

// Every byte matches and the replacement is empty (output shrinks).
void BM_ReplaceHelper_Shrink(benchmark::State& state)
{
    runReplace(state, '-', "-", "", 1);
}

// No match: the field is left untouched, so the event is restored only periodically.
void BM_ReplaceHelper_Plain(benchmark::State& state)
{
    runReplace(state, 'a', "-", "++", 64);
}

BENCHMARK(BM_ReplaceHelper_Grow)->Arg(16 << 10)->Arg(64 << 10)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ReplaceHelper_Shrink)->Arg(16 << 10)->Arg(64 << 10)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ReplaceHelper_Plain)->Arg(16 << 10)->Arg(64 << 10)->Unit(benchmark::kMicrosecond);

} // namespace
