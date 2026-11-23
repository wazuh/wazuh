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
// Cost of building and editing JSON objects: how the setters, merge, the erase functions and object comparison scale
// with the size of their input.
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

/** @brief The source holds the elements of the destination: every lookup finds its element and nothing is added. */
void BM_JsonMerge_ArrayOverlap(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeArrayText(n, "d"), makeArrayText(n, "d"), static_cast<size_t>(n));
}

/** @brief Array text with n objects {"id":<i>,"v":"s<i>"}, i from first on. */
std::string makeObjectArrayText(int64_t n, int64_t first)
{
    std::string text = "[";
    for (int64_t i = first; i < first + n; ++i)
    {
        if (i > first)
        {
            text += ',';
        }
        const auto id = std::to_string(i);
        text += "{\"id\":" + id + ",\"v\":\"s" + id + "\"}";
    }
    text += ']';
    return text;
}

/** @brief Object elements, the first half of the source already in the destination. */
void BM_JsonMerge_ArrayObjects(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state, makeObjectArrayText(n, n / 2), makeObjectArrayText(n, 0), static_cast<size_t>(n + (n - n / 2)));
}

/** @brief Array text with the numbers first .. first + n - 1, written as integers or as doubles ("<i>.0"). */
std::string makeNumberArrayText(int64_t n, int64_t first, bool asDouble)
{
    std::string text = "[";
    for (int64_t i = first; i < first + n; ++i)
    {
        if (i > first)
        {
            text += ',';
        }
        text += std::to_string(i) + (asDouble ? ".0" : "");
    }
    text += ']';
    return text;
}

/** @brief Doubles merged into integers: an integer equals the double of the same value, so half of them are found. */
void BM_JsonMerge_ArrayMixedNumbers(benchmark::State& state)
{
    const auto n = state.range(0);
    runMerge(state,
             makeNumberArrayText(n, n / 2, true),
             makeNumberArrayText(n, 0, false),
             static_cast<size_t>(n + (n - n / 2)));
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

/**
 * @brief Array merges around the point where the hash index is built: range(0) = S source elements, range(1) = D
 * destination elements "d<i>", range(2) = population (0: source strings absent from the destination; 1: source
 * strings taken from the destination in order, wrapping around, so every one is found).
 */
void BM_JsonMerge_ArrayCrossover(benchmark::State& state)
{
    const auto s = state.range(0);
    const auto d = state.range(1);
    if (state.range(2) == 0)
    {
        runMerge(state, makeArrayText(s, "s"), makeArrayText(d, "d"), static_cast<size_t>(s + d));
        return;
    }
    std::string src = "[";
    for (int64_t i = 0; i < s; ++i)
    {
        src += (i > 0 ? ",\"d" : "\"d") + std::to_string(i % d) + "\"";
    }
    src += ']';
    runMerge(state, src, makeArrayText(d, "d"), static_cast<size_t>(d));
}

/**
 * @brief Elements that keep the scan: objects with a repeated name ({"a":<i>,"a":<i>}), half of the source present.
 * Expected to grow quadratically: rapidjson's operator== lets such an object equal objects with other names, so no
 * hash can be used for them.
 */
void BM_JsonMerge_ArrayIrregular(benchmark::State& state)
{
    const auto n = state.range(0);
    const auto text = [](int64_t first, int64_t count)
    {
        std::string out = "[";
        for (int64_t i = first; i < first + count; ++i)
        {
            const auto id = std::to_string(i);
            out += (i > first ? ",{\"a\":" : "{\"a\":") + id + ",\"a\":" + id + "}";
        }
        return out + "]";
    };
    runMerge(state, text(n / 2, n), text(0, n), static_cast<size_t>(n + (n - n / 2)));
}

/**
 * @brief Distinct integers from 2^62, half of the source present: integers that round to the same double share a hash
 * bucket (at 2^62, 1024 consecutive integers per double), the bound of the hash index for integers above 2^53.
 */
void BM_JsonMerge_ArrayBigIntegers(benchmark::State& state)
{
    const auto n = state.range(0);
    const auto text = [](int64_t first, int64_t count)
    {
        std::string out = "[";
        for (int64_t i = first; i < first + count; ++i)
        {
            out += (i > first ? "," : "") + std::to_string((int64_t {1} << 62) + i);
        }
        return out + "]";
    };
    runMerge(state, text(n / 2, n), text(0, n), static_cast<size_t>(n + (n - n / 2)));
}

/** @brief Object text: a chain of depth objects under "c", the innermost holding t members "k<i>": "<prefix><i>". */
std::string makeChainText(int64_t depth, int64_t t, const std::string& prefix)
{
    std::string text;
    for (int64_t level = 0; level < depth; ++level)
    {
        text += "{\"c\":";
    }
    text += '{';
    for (int64_t i = 0; i < t; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        text += "\"k" + std::to_string(i) + "\":\"" + prefix + std::to_string(i) + "\"";
    }
    text += '}';
    text.append(static_cast<size_t>(depth), '}');
    return text;
}

/**
 * @brief Recursive merge through a chain of range(1) objects into a bottom object of range(0) members, same names on
 * both sides: the merge descends the chain and overwrites every bottom member.
 *
 * pool_bytes is the growth of the destination's allocator over one merge (Json::getUsedMemory).
 */
void BM_JsonMerge_RecursiveCopy(benchmark::State& state)
{
    const auto t = state.range(0);
    const auto depth = state.range(1);
    const auto srcText = makeChainText(depth, t, "s");
    const auto dstText = makeChainText(depth, t, "d");

    // Untimed guard: the bottom holds the source values, and the pool growth of one merge.
    {
        const Json src(srcText.c_str());
        Json check(dstText.c_str());
        std::string bottom;
        for (int64_t level = 0; level < depth; ++level)
        {
            bottom += "/c";
        }
        const auto before = check.getUsedMemory();
        check.merge(true, src);
        state.counters["pool_bytes"] = static_cast<double>(check.getUsedMemory() - before);
        const auto last = std::to_string(t - 1);
        if (!check.equalsString(bottom + "/k0", "s0") || !check.equalsString(bottom + "/k" + last, "s" + last))
        {
            state.SkipWithError("the recursive merge did not write the source values at the bottom");
            return;
        }
    }

    runMerge(state, srcText, dstText, 1, true);
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

/** @brief Object text with n members "k<i>": {"k":1,"x":2}. */
std::string makeObjectOfObjectsText(int64_t n)
{
    std::string text = "{";
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        text += "\"k" + std::to_string(i) + "\":{\"k\":1,\"x\":2}";
    }
    text += '}';
    return text;
}

/** @brief Recursive eraseIfKey over N object members, erasing "x" from each of them: every member is recursed into. */
void BM_JsonEraseIfKey_Recursive(benchmark::State& state)
{
    const auto n = state.range(0);
    const auto text = makeObjectOfObjectsText(n);
    const Json templ(text.c_str());
    state.counters["input_bytes"] = static_cast<double>(text.size());

    const auto isX = [](const std::string& key)
    {
        return key == "x";
    };

    // Untimed guard: runs the whole erase once.
    {
        Json check(templ);
        const auto erased = check.eraseIfKey(isX, true);
        if (!erased || check.size() != static_cast<size_t>(n) || check.exists("/k0/x")
            || check.exists("/k" + std::to_string(n - 1) + "/x"))
        {
            state.SkipWithError("eraseIfKey did not erase the nested members");
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
            const auto erased = doc.eraseIfKey(isX, true);
            benchmark::DoNotOptimize(erased);
            benchmark::DoNotOptimize(doc);
        }
    }
}

// =============================================================================
// eraseRootKeysByPrefix
// =============================================================================

/** @brief Root of N members, the even ones named "_k<i>" and erased, the odd ones "k<i>" and kept. */
void BM_JsonEraseRootKeysByPrefix(benchmark::State& state)
{
    const auto n = state.range(0);
    std::string text = "{";
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ',';
        }
        text += std::string(i % 2 == 0 ? "\"_k" : "\"k") + std::to_string(i) + "\":\"v" + std::to_string(i) + "\"";
    }
    text += '}';
    const Json templ(text.c_str());
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // Untimed guard: runs the whole erase once.
    {
        Json check(templ);
        check.eraseRootKeysByPrefix("_");
        if (check.size() != static_cast<size_t>(n / 2) || check.exists("/_k0"))
        {
            state.SkipWithError("eraseRootKeysByPrefix did not leave the expected members");
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
            doc.eraseRootKeysByPrefix("_");
            benchmark::DoNotOptimize(doc);
        }
    }
}

// =============================================================================
// Object comparison
// =============================================================================

/** @brief Object text with n members "k<i>": i, in reverse order when reversed. */
std::string makeIntObjectText(int64_t n, bool reversed)
{
    std::string text = "{";
    for (int64_t j = 0; j < n; ++j)
    {
        if (j > 0)
        {
            text += ',';
        }
        const auto id = std::to_string(reversed ? n - 1 - j : j);
        text += "\"k" + id + "\":" + id;
    }
    text += '}';
    return text;
}

/** @brief Json::equals on two equal objects of range(0) members, the second in the same (0) or reversed (1) order. */
void BM_JsonEquals_Object(benchmark::State& state)
{
    const auto m = state.range(0);
    const Json lhs(makeIntObjectText(m, false).c_str());
    const Json rhs(makeIntObjectText(m, state.range(1) == 1).c_str());
    if (!lhs.equals("", rhs))
    {
        state.SkipWithError("the objects do not compare equal");
        return;
    }

    for (auto _ : state)
    {
        benchmark::DoNotOptimize(lhs.equals("", rhs));
    }
}

/** @brief The same comparison through operator== of json::Json. */
void BM_JsonOperatorEq_Object(benchmark::State& state)
{
    const auto m = state.range(0);
    const Json lhs(makeIntObjectText(m, false).c_str());
    const Json rhs(makeIntObjectText(m, state.range(1) == 1).c_str());
    if (!(lhs == rhs))
    {
        state.SkipWithError("the objects do not compare equal");
        return;
    }

    for (auto _ : state)
    {
        benchmark::DoNotOptimize(lhs == rhs);
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
// The array merges: distinct elements, every element found, object elements, integers against doubles.
REGISTER_SCALING_BENCH(BM_JsonMerge_Array);
REGISTER_SCALING_BENCH(BM_JsonMerge_ArrayOverlap);
REGISTER_SCALING_BENCH(BM_JsonMerge_ArrayObjects);
REGISTER_SCALING_BENCH(BM_JsonMerge_ArrayMixedNumbers);
// The two bounds of the hash index: elements that keep the scan, and integers that share a bucket.
BENCHMARK(BM_JsonMerge_ArrayIrregular)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_JsonMerge_ArrayBigIntegers)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);
// Array merge crossover: (S, D, population) around the point where the index is built.
BENCHMARK(BM_JsonMerge_ArrayCrossover)
    ->ArgsProduct({{1, 4, 16, 64, 256, 1024, 4096}, {16, 256, 4096}, {0, 1}})
    ->Unit(benchmark::kMicrosecond);
// Recursive merge through a chain: (bottom members, depth of the chain).
BENCHMARK(BM_JsonMerge_RecursiveCopy)
    ->ArgsProduct({{1024, 4096, 16384}, {1, 4, 16, 64}})
    ->Unit(benchmark::kMicrosecond);
REGISTER_SCALING_BENCH(BM_JsonEraseIfKey);
REGISTER_SCALING_BENCH(BM_JsonEraseIfKey_Recursive);
REGISTER_SCALING_BENCH(BM_JsonEraseRootKeysByPrefix);
// Object comparison: (members, order of the second object).
BENCHMARK(BM_JsonEquals_Object)
    ->ArgsProduct({benchmark::CreateRange(16, 16384, 4), {0, 1}})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_JsonOperatorEq_Object)
    ->ArgsProduct({benchmark::CreateRange(16, 16384, 4), {0, 1}})
    ->Unit(benchmark::kMicrosecond);

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
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_Array);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ArrayOverlap);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ArrayObjects);
REGISTER_SMALL_SIZES_BENCH(BM_JsonMerge_ArrayMixedNumbers);
REGISTER_SMALL_SIZES_BENCH(BM_JsonEraseIfKey);
REGISTER_SMALL_SIZES_BENCH(BM_JsonEraseIfKey_Recursive);
REGISTER_SMALL_SIZES_BENCH(BM_JsonEraseRootKeysByPrefix);

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
