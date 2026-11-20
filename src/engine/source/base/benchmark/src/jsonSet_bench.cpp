// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/jsonPathWriter.hpp>

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
 * A batch of 1 means one PauseTiming/ResumeTiming per iteration, so it is used only from the sizes where kBatch copies
 * of the document would take too much memory: merges switch at N >= 1024, JsonEraseIfKey at N >= 16384.
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

/** @brief Shared body of BM_JsonSetString_Siblings and BM_JsonSetString_Crossover: state.range(0) sibling members. */
void runJsonSetStringSiblings(benchmark::State& state)
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

void BM_JsonSetString_Siblings(benchmark::State& state)
{
    runJsonSetStringSiblings(state);
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
 * input_bytes is the serialized size of the source document. With alwaysFullBatch every batch holds kBatch documents,
 * for the benchmarks whose timed body is small whatever the size of the destination; otherwise the batch follows the
 * document size (batchFor).
 */
void runMerge(benchmark::State& state,
              const std::string& srcText,
              const std::string& dstText,
              size_t expectedSize,
              bool isRecursive = false,
              bool alwaysFullBatch = false)
{
    const Json src(srcText.c_str());
    const Json dstTemplate(dstText.c_str());
    state.counters["input_bytes"] = static_cast<double>(srcText.size());

    // Untimed guard: runs the whole merge once.
    {
        Json check(dstTemplate);
        check.merge(isRecursive, src);
        if (check.size() != expectedSize)
        {
            state.SkipWithError("the merge did not produce the expected size");
            return;
        }
    }

    const auto batch = alwaysFullBatch ? kBatch : batchFor(state, 1024);
    std::vector<Json> docs;
    docs.reserve(static_cast<size_t>(batch));
    while (state.KeepRunningBatch(batch))
    {
        state.PauseTiming();
        refill(docs, dstTemplate, batch);
        state.ResumeTiming();
        for (auto& doc : docs)
        {
            doc.merge(isRecursive, src);
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

/** @brief Object text with n members "k<i>": a small object each; the members differ between source and destination. */
std::string makeNestedObjectText(int64_t n, bool isSource)
{
    std::string text = "{";
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        const auto id = std::to_string(i);
        text += "\"k" + id + "\":";
        text += isSource ? "{\"a\":\"s" + id + "\",\"b\":2,\"c\":3}" : "{\"a\":\"d" + id + "\",\"b\":1}";
    }
    text += '}';
    return text;
}

/** @brief Same keys in source and destination, each value a small object, merged recursively: size stays N. */
void BM_JsonMerge_ObjectRecursive(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeNestedObjectText(n, true), makeNestedObjectText(n, false), static_cast<size_t>(n), true);
}

/** @brief Small source (8 members: 4 new names, 4 already in the destination) into a destination of N members. */
void BM_JsonMerge_SmallIntoWide(benchmark::State& state)
{
    const auto n = state.range(0);
    std::string src = "{";
    for (int64_t i = 0; i < 4; ++i)
    {
        src += "\"new" + std::to_string(i) + "\":\"n" + std::to_string(i) + "\",";
    }
    for (int64_t i = 0; i < 4; ++i)
    {
        // Names spread over the destination.
        const auto idx = (i * n) / 4;
        src += "\"d" + std::to_string(idx) + "\":\"m" + std::to_string(i) + "\"";
        if (i < 3)
        {
            src += ',';
        }
    }
    src += '}';
    runMerge(state, src, makeObjectText(n, "d"), static_cast<size_t>(n + 4), false, true);
}

/**
 * @brief Merges around the point where the member index is built: range(0) = S source members, range(1) = D
 * destination members, range(2) = population (0: source names disjoint from the destination; 1: source names present
 * in it, taken from its first members; 2: present in it, taken from its last members).
 *
 * With populations 1 and 2 and S > D the source names wrap around the destination names, so a name repeats inside the
 * source.
 */
void BM_JsonMerge_Crossover(benchmark::State& state)
{
    const auto s = state.range(0);
    const auto d = state.range(1);
    const auto population = state.range(2);
    if (population != 0)
    {
        std::string src = "{";
        for (int64_t i = 0; i < s; ++i)
        {
            if (i > 0)
            {
                src += ',';
            }
            const auto hit = population == 1 ? i % d : d - 1 - (i % d);
            src += "\"d" + std::to_string(hit) + "\":\"s" + std::to_string(i) + "\"";
        }
        src += '}';
        runMerge(state, src, makeObjectText(d, "d"), static_cast<size_t>(d), false, true);
    }
    else
    {
        runMerge(state, makeObjectText(s, "s"), makeObjectText(d, "d"), static_cast<size_t>(s + d), false, true);
    }
}

/**
 * @brief Source position at which a merge of the given population finds its member index built, following the rule
 * of Json::merge: the members visited by its scans exceed MERGE_INDEX_SCAN_FACTOR times those of the destination.
 */
int64_t crossoverIndexBuiltAt(int64_t d, int64_t population)
{
    const size_t factor = Json::MERGE_INDEX_SCAN_FACTOR;
    size_t scanned = 0;
    auto count = static_cast<size_t>(d);
    for (int64_t i = 0;; ++i)
    {
        if (scanned > factor * count)
        {
            return i;
        }
        if (population == 0)
        {
            // A miss visits every member and adds one
            scanned += count;
            ++count;
        }
        else
        {
            const auto hit = population == 1 ? i % d : d - 1 - (i % d);
            scanned += static_cast<size_t>(hit) + 1;
        }
    }
}

/**
 * @brief Fills the (S, D, population) grid of BM_JsonMerge_Crossover without duplicates: a few small sources, and
 * sources that end half way to the index, just after it is built (the index is paid for and hardly used: the least
 * favourable point) and well after it.
 */
void crossoverGrid(benchmark::internal::Benchmark* bench)
{
    for (const int64_t d : {64, 256, 1024})
    {
        for (const int64_t population : {0, 1, 2})
        {
            const auto built = crossoverIndexBuiltAt(d, population);
            std::vector<int64_t> sources {1, 8, 32, built / 2, built + 1, built + 8, built + 64, 2 * built};
            std::sort(sources.begin(), sources.end());
            sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
            for (const auto s : sources)
            {
                bench->Args({s, d, population});
            }
        }
    }
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
        if (!erased || check.size() != static_cast<size_t>(n / 2))
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

// =============================================================================
// PathWriter: the same workloads through json::PathWriter, one document and one writer per iteration.
// =============================================================================

// input_bytes is the total length of the JSON-pointer paths passed to the writer; the values are not counted.

void BM_PathWriterSetString_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_PathWriterSet_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    const Json value(R"({"a":1,"b":"x"})");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.set(path, value);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_PathWriterSetString_NestedSiblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/a/b/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_PathWriterSetStringAsMembers_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.setStringAsMembers("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// Per key: exists + isObject on "/k<i>", then setString on "/k<i>/#text"; a second pass of exists + isObject over all
// the keys written. input_bytes counts every path passed to the writer: the key twice and the text path once in the
// first pass, the key twice in the second.
void BM_PathWriterXmlLike_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    std::vector<std::string> textPaths;
    textPaths.reserve(paths.size());
    for (const auto& path : paths)
    {
        textPaths.push_back(path + "/#text");
    }
    state.counters["input_bytes"] = static_cast<double>(4 * totalBytes(paths) + totalBytes(textPaths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (size_t i = 0; i < paths.size(); ++i)
        {
            const bool present = writer.exists(paths[i]);
            const bool object = writer.isObject(paths[i]);
            benchmark::DoNotOptimize(present);
            benchmark::DoNotOptimize(object);
            writer.setString("v", textPaths[i]);
        }
        for (const auto& path : paths)
        {
            const bool present = writer.exists(path);
            const bool object = writer.isObject(path);
            benchmark::DoNotOptimize(present);
            benchmark::DoNotOptimize(object);
        }
        benchmark::DoNotOptimize(doc);
    }
}

void BM_PathWriterAppendString_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.appendString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// Keys that share a 64-byte prefix: "/" + 64 x 'p' + "<i>".
void BM_PathWriterSetString_CollidingPrefix(benchmark::State& state)
{
    const std::string prefix = "/" + std::string(64, 'p');
    std::vector<std::string> paths;
    paths.reserve(static_cast<size_t>(state.range(0)));
    for (int64_t i = 0; i < state.range(0); ++i)
    {
        paths.push_back(prefix + std::to_string(i));
    }
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc);
        for (const auto& path : paths)
        {
            writer.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// =============================================================================
// Index threshold sweep: range(0) = number of sibling members N, range(1) = index threshold T.
// =============================================================================

void BM_PathWriterThreshold_Siblings(benchmark::State& state)
{
    const auto paths = makePaths(state.range(0), "/");
    const auto threshold = static_cast<size_t>(state.range(1));
    state.counters["input_bytes"] = static_cast<double>(totalBytes(paths));

    for (auto _ : state)
    {
        Json doc("{}");
        PathWriter writer(doc, threshold);
        for (const auto& path : paths)
        {
            writer.setString("v", path);
        }
        benchmark::DoNotOptimize(doc);
    }
}

// Json side of the threshold sweep: the same workload as BM_JsonSetString_Siblings at the N of each (N, T) pair.
void BM_JsonSetString_Crossover(benchmark::State& state)
{
    runJsonSetStringSiblings(state);
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
// The merges between objects run every size the same way.
BENCHMARK(BM_JsonMerge_ObjectDisjoint)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_JsonMerge_ObjectOverlap)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_JsonMerge_ObjectRecursive)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond);
// Always kBatch documents per batch, so its sizes stop where that many copies stay small.
BENCHMARK(BM_JsonMerge_SmallIntoWide)->RangeMultiplier(4)->Range(16, 4096)->Unit(benchmark::kMicrosecond);
// The range sweep only: the single large run is not registered for the array merge.
BENCHMARK(BM_JsonMerge_Array)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);
REGISTER_SCALING_BENCH(BM_JsonEraseIfKey);

// =============================================================================
// PathWriter registrations: one range sweep, expected to scale almost linearly.
// =============================================================================

#define REGISTER_PATHWRITER_BENCH(name)                                                                                \
    BENCHMARK(name)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond)

REGISTER_PATHWRITER_BENCH(BM_PathWriterSetString_Siblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterSet_Siblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterSetString_NestedSiblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterSetStringAsMembers_Siblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterXmlLike_Siblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterAppendString_Siblings);
REGISTER_PATHWRITER_BENCH(BM_PathWriterSetString_CollidingPrefix);

// Small sizes (the 16 comes from the range) for the three writer benchmarks and their Json counterparts.
#define REGISTER_SMALL_SIZES_BENCH(name) BENCHMARK(name)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond)

REGISTER_SMALL_SIZES_BENCH(BM_PathWriterSetString_Siblings);
REGISTER_SMALL_SIZES_BENCH(BM_PathWriterSet_Siblings);
REGISTER_SMALL_SIZES_BENCH(BM_PathWriterSetString_NestedSiblings);
REGISTER_SMALL_SIZES_BENCH(BM_JsonSetString_Siblings);
REGISTER_SMALL_SIZES_BENCH(BM_JsonSet_Siblings);
REGISTER_SMALL_SIZES_BENCH(BM_JsonSetString_NestedSiblings);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ObjectDisjoint);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ObjectOverlap);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ObjectRecursive);

// Threshold sweep: T in {16, 32, 64, 128}, N in {T + 2, 2T, 4T}.
BENCHMARK(BM_PathWriterThreshold_Siblings)
    ->Args({18, 16})
    ->Args({32, 16})
    ->Args({64, 16})
    ->Args({34, 32})
    ->Args({64, 32})
    ->Args({128, 32})
    ->Args({66, 64})
    ->Args({128, 64})
    ->Args({256, 64})
    ->Args({130, 128})
    ->Args({256, 128})
    ->Args({512, 128})
    ->Unit(benchmark::kMicrosecond);

// The distinct N of the pairs above.
BENCHMARK(BM_JsonSetString_Crossover)
    ->Arg(18)
    ->Arg(32)
    ->Arg(34)
    ->Arg(64)
    ->Arg(66)
    ->Arg(128)
    ->Arg(130)
    ->Arg(256)
    ->Arg(512)
    ->Unit(benchmark::kMicrosecond);

// Merge crossover: the (S, D, population) grid, built programmatically.
BENCHMARK(BM_JsonMerge_Crossover)->Apply(crossoverGrid)->Unit(benchmark::kMicrosecond);
