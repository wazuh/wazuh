// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/baseTypes.hpp>
#include <base/json.hpp>
#include <builder/allowedFields.hpp>
#include <schemf/ivalidator.hpp>

#include "builders/argument.hpp"
#include "builders/buildCtx.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

namespace
{

using namespace builder::builders;

/**
 * @brief Minimal schema validator: no field is known to the schema, so the helpers skip the type checks.
 */
class NoFieldsValidator final : public schemf::IValidator
{
public:
    schemf::Type getType(const DotPath&) const override { return schemf::Type::ERROR; }
    json::Json::Type getJsonType(const DotPath&) const override { return json::Json::Type::Null; }
    std::unordered_set<json::Json::Type> getJsonTypes(const DotPath&) const override { return {}; }
    bool hasField(const DotPath&) const override { return false; }

    base::RespOrError<schemf::TargetFieldKind> validateTargetField(const DotPath&) const override
    {
        return schemf::TargetFieldKind::SCHEMA;
    }

    base::RespOrError<schemf::ValidationResult> validate(const DotPath&, const schemf::ValidationToken&) const override
    {
        return schemf::ValidationResult {};
    }

    base::RespOrError<schemf::ValidationResult> validate(const DotPath&, const json::Json&) const override
    {
        return schemf::ValidationResult {};
    }
};

constexpr size_t kBatch = 256;

/**
 * @brief Batch size: a fixed batch of kBatch events below firstSingleSize, one event per iteration from there up.
 *
 * A batch of 1 means one PauseTiming/ResumeTiming per iteration, so it is used only from the sizes where kBatch copies
 * of the event would take too much memory: BM_DeleteFieldsWithValue switches at N >= 1024.
 */
size_t batchFor(const benchmark::State& state, int64_t firstSingleSize)
{
    return state.range(0) >= firstSingleSize ? 1 : kBatch;
}

std::shared_ptr<BuildCtx> makeCtx()
{
    Context ctx {};
    ctx.assetName = "decoder/bench/0";
    ctx.opName = "bench";
    return std::make_shared<BuildCtx>(false,
                                      ctx,
                                      nullptr,
                                      nullptr,
                                      std::make_shared<NoFieldsValidator>(),
                                      std::make_shared<builder::AllowedFields>(),
                                      nullptr,
                                      false);
}

std::shared_ptr<Value> makeValue(const char* jsonText)
{
    return std::make_shared<Value>(json::Json(jsonText));
}

/// Event text `{"arr":[<element(i)> x n]}`.
template<typename F>
std::string makeArrayText(size_t n, F&& element)
{
    std::string text = R"({"arr":[)";
    for (size_t i = 0; i < n; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += element(i);
    }
    text += "]}";
    return text;
}

// Shared body of the two map benchmarks: the event is not mutated, so it is parsed once.
void runMap(benchmark::State& state, const MapOp& op, const std::string& text, size_t members)
{
    const base::Event event = std::make_shared<json::Json>(text.c_str());
    // input_bytes is the size of the input event text.
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // Untimed guard: runs the whole op once.
    {
        const auto check = op(event);
        if (!check || !check.payload().isObject() || check.payload().size() != members)
        {
            state.SkipWithError("the op did not produce the expected members");
            return;
        }
    }

    for (auto _ : state)
    {
        auto result = op(event);
        benchmark::DoNotOptimize(result);
    }
}

// array_to_object($arr, 'key', 'value')
void BM_ArrayToObject(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto text =
        makeArrayText(n, [](size_t i) { return R"({"key":"k)" + std::to_string(i) + R"(","value":"v"})"; });

    auto buildCtx = makeCtx();
    const auto op = opBuilderHelperArrayObjToMapkv(
        {std::make_shared<Reference>("arr"), makeValue("\"key\""), makeValue("\"value\"")}, buildCtx);
    runMap(state, op, text, n);
}

// array_to_object_changes($arr, 'key', 'new', 'old')
void BM_ArrayToObjectChanges(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto text =
        makeArrayText(n, [](size_t i) { return R"({"key":"k)" + std::to_string(i) + R"(","new":"n","old":"o"})"; });

    auto buildCtx = makeCtx();
    const auto op = opBuilderHelperArrayExtractKeyObj(
        {std::make_shared<Reference>("arr"), makeValue("\"key\""), makeValue("\"new\""), makeValue("\"old\"")},
        buildCtx);
    runMap(state, op, text, n);
}

// delete_fields_with_value('del') over `target`: even members hold 'del', odd ones 'keep'.
// The op mutates the event, so a batch of fresh copies is restored outside the timed region.
void BM_DeleteFieldsWithValue(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));

    std::string text = R"({"target":{)";
    for (size_t i = 0; i < n; ++i)
    {
        if (i != 0)
        {
            text += ',';
        }
        text += R"("k)" + std::to_string(i) + R"(":")" + (i % 2 == 0 ? "del" : "keep") + '"';
    }
    text += "}}";

    auto buildCtx = makeCtx();
    const auto op = opBuilderHelperDeleteFieldsWithValue(Reference {"target"}, {makeValue("\"del\"")}, buildCtx);

    const json::Json original(text.c_str());

    // input_bytes is the size of the input event text.
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // Untimed guard: runs the whole op once.
    {
        base::Event check = std::make_shared<json::Json>(original);
        const auto result = op(check);
        if (!result || result.payload()->size("/target") != n / 2)
        {
            state.SkipWithError("the op did not leave the expected members");
            return;
        }
    }

    const size_t batch = batchFor(state, 1024);
    std::vector<base::Event> events(batch);

    while (state.KeepRunningBatch(static_cast<benchmark::IterationCount>(batch)))
    {
        state.PauseTiming();
        for (auto& event : events)
        {
            event = std::make_shared<json::Json>(original);
        }
        state.ResumeTiming();

        for (auto& event : events)
        {
            auto result = op(event);
            benchmark::DoNotOptimize(result);
        }
    }
}

} // namespace

// =============================================================================
// Registrations: a range sweep per benchmark. The helpers that build an object from an array run every size the same
// way, plus two small sizes for the per-event cost, and so does delete_fields_with_value.
// =============================================================================

// Small arrays: per-event cost with few elements.
BENCHMARK(BM_ArrayToObject)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ArrayToObjectChanges)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_ArrayToObject)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ArrayToObjectChanges)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_DeleteFieldsWithValue)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_DeleteFieldsWithValue)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);
