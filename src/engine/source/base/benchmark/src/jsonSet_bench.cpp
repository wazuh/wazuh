// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <cstdint>
#include <string>
#include <vector>

#include <base/json.hpp>

using namespace json;

// =============================================================================
// Cost of building JSON objects: how the setters, merge and eraseIfKey scale with the number of sibling members.
// =============================================================================

namespace
{

constexpr int64_t kBatch = 256;

/**
 * @brief Batch size: a fixed batch of kBatch documents below firstSingleSize, one document per iteration from there up.
 *
 * A batch of 1 means one PauseTiming/ResumeTiming per iteration, so it is used only where the timed body takes about a
 * millisecond or more: merges switch at N >= 1024, JsonEraseIfKey at N >= 16384.
 */
int64_t batchFor(const benchmark::State& state, int64_t firstSingleSize)
{
    return state.range(0) >= firstSingleSize ? 1 : kBatch;
}

/** @brief Paths "<prefix>k0" ... "<prefix>k<n-1>". */
std::vector<std::string> makePaths(int64_t n, const std::string& prefix)
{
    std::vector<std::string> paths;
    paths.reserve(static_cast<size_t>(n));
    for (int64_t i = 0; i < n; ++i)
    {
        paths.push_back(prefix + "k" + std::to_string(i));
    }
    return paths;
}

int64_t totalBytes(const std::vector<std::string>& values)
{
    int64_t total = 0;
    for (const auto& v : values)
    {
        total += static_cast<int64_t>(v.size());
    }
    return total;
}

/** @brief Object text with n members "<prefix><i>": "v<i>". */
std::string makeObjectText(int64_t n, const std::string& prefix)
{
    std::string text = "{";
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        text += "\"" + prefix + std::to_string(i) + "\":\"v" + std::to_string(i) + "\"";
    }
    text += '}';
    return text;
}

/** @brief Array text with n strings "<prefix><i>". */
std::string makeArrayText(int64_t n, const std::string& prefix)
{
    std::string text = "[";
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        text += "\"" + prefix + std::to_string(i) + "\"";
    }
    text += ']';
    return text;
}

/** @brief Refills the batch with copies of the template document (call between PauseTiming and ResumeTiming). */
void refill(std::vector<Json>& docs, const Json& templ, int64_t batch)
{
    docs.clear();
    for (int64_t i = 0; i < batch; ++i)
    {
        docs.emplace_back(templ);
    }
}

// =============================================================================
// Setters
// =============================================================================

// In the setters, input_bytes is the total length of the JSON-pointer paths written; the values are not counted.

void BM_JsonSetString_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        for (const auto& path : paths)
        {
            doc.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_JsonSet_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    const Json value(R"({"a":1,"b":"x"})");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        for (const auto& path : paths)
        {
            doc.set(path, value);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_JsonSetString_NestedSiblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/a/b/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        for (const auto& path : paths)
        {
            doc.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// Control: the same key every time, must be linear.
void BM_JsonSetString_SameKey(benchmark::State& state)
{
    const std::string path = "/k0";
    state.counters["input_bytes"] = static_cast<double>(path.size() * static_cast<size_t>(state.range(0)));

    for (auto _ : state)
    {
        Json doc("{}");
        for (int64_t i = 0; i < state.range(0); ++i)
        {
            doc.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// =============================================================================
// Merge
// =============================================================================

/**
 * @brief Shared body of the merge benchmarks: merges srcText into fresh copies of dstText.
 *
 * input_bytes is the serialized size of the source document.
 */
void runMerge(benchmark::State& state, const std::string& srcText, const std::string& dstText, size_t expectedSize)
{
    const Json src(srcText.c_str());
    const Json dstTemplate(dstText.c_str());
    state.counters["input_bytes"] = static_cast<double>(srcText.size());

    // Untimed guard: runs the whole merge once, so the wall clock of single-iteration sizes is about twice the
    // reported time.
    {
        Json check(dstTemplate);
        check.merge(false, src);
        if (check.size() != expectedSize)
        {
            state.SkipWithError("the merge did not produce the expected size");
            return;
        }
    }

    const auto batch = batchFor(state, 1024);
    std::vector<Json> docs;
    docs.reserve(static_cast<size_t>(batch));
    while (state.KeepRunningBatch(batch))
    {
        state.PauseTiming();
        refill(docs, dstTemplate, batch);
        state.ResumeTiming();
        for (auto& doc : docs)
        {
            doc.merge(false, src);
            benchmark::DoNotOptimize(doc);
        }
    }
}

void BM_JsonMerge_ObjectDisjoint(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeObjectText(n, "s"), makeObjectText(n, "d"), static_cast<size_t>(2 * n));
}

void BM_JsonMerge_ObjectOverlap(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeObjectText(n, "k"), makeObjectText(n, "k"), static_cast<size_t>(n));
}

void BM_JsonMerge_Array(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeArrayText(n, "s"), makeArrayText(n, "d"), static_cast<size_t>(2 * n));
}

// =============================================================================
// eraseIfKey
// =============================================================================

void BM_JsonEraseIfKey(benchmark::State& state)
{
    const auto n = state.range(0);
    const auto text = makeObjectText(n, "k");
    const Json templ(text.c_str());
    // input_bytes is the serialized size of the document the keys are erased from.
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // True for even i: the key is "k<i>", the parity is the one of its last digit.
    const auto evenKey = [](const std::string& key)
    {
        return key.size() > 1 && ((key.back() - '0') % 2) == 0;
    };

    // Untimed guard: runs the whole erase once, so the wall clock of single-iteration sizes is about twice the
    // reported time.
    {
        Json check(templ);
        const auto erased = check.eraseIfKey(evenKey);
        if (!erased || check.size() != static_cast<size_t>(n - n / 2))
        {
            state.SkipWithError("eraseIfKey did not leave the expected members");
            return;
        }
    }

    const auto batch = batchFor(state, 16384);
    std::vector<Json> docs;
    docs.reserve(static_cast<size_t>(batch));
    while (state.KeepRunningBatch(batch))
    {
        state.PauseTiming();
        refill(docs, templ, batch);
        state.ResumeTiming();
        for (auto& doc : docs)
        {
            const auto erased = doc.eraseIfKey(evenKey);
            benchmark::DoNotOptimize(erased);
            benchmark::DoNotOptimize(doc);
        }
    }
}

} // namespace

// =============================================================================
// Registrations: a range sweep and a single large run per benchmark.
// =============================================================================

#define REGISTER_SCALING_BENCH(name)                                                                                   \
    BENCHMARK(name)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);                              \
    BENCHMARK(name)->Arg(65536)->Iterations(1)->Unit(benchmark::kMicrosecond)

REGISTER_SCALING_BENCH(BM_JsonSetString_Siblings);
REGISTER_SCALING_BENCH(BM_JsonSet_Siblings);
REGISTER_SCALING_BENCH(BM_JsonSetString_NestedSiblings);
REGISTER_SCALING_BENCH(BM_JsonSetString_SameKey);
REGISTER_SCALING_BENCH(BM_JsonMerge_ObjectDisjoint);
REGISTER_SCALING_BENCH(BM_JsonMerge_ObjectOverlap);
// The range sweep only: the single large run is not registered for the array merge.
BENCHMARK(BM_JsonMerge_Array)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);
REGISTER_SCALING_BENCH(BM_JsonEraseIfKey);
