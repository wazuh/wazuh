// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <cstdint>
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include <base/json.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parser.hpp>

// Cost of the JSON-building stage of the kv and xml parsers against the number of members written into one object.
// Every timed iteration runs the three stages (hlp::parser::run) on a fresh, empty event.

namespace
{

const std::string TARGET = "/out";

/** @brief Post-conditions on the parsed event: each JSON pointer must have the given size (members or elements). */
using SizeChecks = std::vector<std::pair<std::string, size_t>>;

hlp::Params kvParams()
{
    return hlp::Params {"kv", TARGET, {}, {"=", " ", "'", "\\"}};
}

hlp::Params xmlParams(bool windows = false)
{
    hlp::Params params {"xml", TARGET, {""}, {}};
    if (windows)
    {
        params.options = {"windows"};
    }
    return params;
}

bool checkSizes(const json::Json& probe, const SizeChecks& checks)
{
    for (const auto& [pointer, expected] : checks)
    {
        try
        {
            if (probe.size(pointer) != expected)
            {
                return false;
            }
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
    return true;
}

// Parses text once to validate it, then times hlp::parser::run on a fresh event per iteration.
void runParser(benchmark::State& state,
               const hlp::parser::Parser& parser,
               const std::string& text,
               const SizeChecks& checks)
{
    // input_bytes is the size of the input text.
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // Untimed guard: runs the whole parse once, so the wall clock of single-iteration sizes is about twice the
    // reported time.
    {
        json::Json probe;
        const auto err = hlp::parser::run(parser, text, probe);
        if (err.has_value())
        {
            state.SkipWithError("parse failed");
            return;
        }
        if (!checkSizes(probe, checks))
        {
            state.SkipWithError("the parser did not write the expected members");
            return;
        }
    }

    for (auto _ : state)
    {
        json::Json event;
        auto err = hlp::parser::run(parser, text, event);
        benchmark::DoNotOptimize(err);
        benchmark::DoNotOptimize(event);
    }
}

/** @brief kv text "<prefix>k0=v <prefix>k1=v ...". */
std::string kvText(int64_t n, const std::string& prefix)
{
    std::string text;
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ' ';
        }
        text += prefix + "k" + std::to_string(i) + "=v";
    }
    return text;
}

std::string xmlSiblings(int64_t n)
{
    std::string text = "<r>";
    for (int64_t i = 0; i < n; ++i)
    {
        const auto name = "k" + std::to_string(i);
        text += "<" + name + ">v</" + name + ">";
    }
    text += "</r>";
    return text;
}

std::string xmlAttributes(int64_t n)
{
    std::string text = "<r";
    for (int64_t i = 0; i < n; ++i)
    {
        text += " k" + std::to_string(i) + "=\"v\"";
    }
    text += " />";
    return text;
}

constexpr int64_t WIDE_SIBLINGS = 64;

/** @brief WIDE_SIBLINGS children "s0" ... "s63" of "r", each with n / WIDE_SIBLINGS attributes. */
std::string xmlAttributesWide(int64_t n)
{
    const int64_t perNode = n / WIDE_SIBLINGS;
    std::string text = "<r>";
    for (int64_t s = 0; s < WIDE_SIBLINGS; ++s)
    {
        text += "<s" + std::to_string(s);
        for (int64_t i = 0; i < perNode; ++i)
        {
            text += " k" + std::to_string(i) + "=\"v\"";
        }
        text += " />";
    }
    text += "</r>";
    return text;
}

std::string xmlWindowsData(int64_t n)
{
    std::string text = "<EventData>";
    for (int64_t i = 0; i < n; ++i)
    {
        text += "<Data Name=\"k" + std::to_string(i) + "\">v</Data>";
    }
    text += "</EventData>";
    return text;
}

std::string xmlRepeatedSibling(int64_t n)
{
    std::string text = "<r>";
    for (int64_t i = 0; i < n; ++i)
    {
        text += "<a>v</a>";
    }
    text += "</r>";
    return text;
}

void BM_ParseKv_Flat(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvText(state.range(0), ""), {{"/out", n}});
}

void BM_ParseKv_Dotted(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvText(state.range(0), "a."), {{"/out/a", n}});
}

void BM_ParseXml_Siblings(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblings(state.range(0)), {{"/out/r", n}});
}

void BM_ParseXml_Attributes(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlAttributes(state.range(0)), {{"/out/r", n}});
}

void BM_ParseXml_AttributesWide(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state,
              parser,
              xmlAttributesWide(state.range(0)),
              {{"/out/r", static_cast<size_t>(WIDE_SIBLINGS)}, {"/out/r/s0", n / WIDE_SIBLINGS}});
}

void BM_ParseXml_WindowsData(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams(true));
    runParser(state, parser, xmlWindowsData(state.range(0)), {{"/out/EventData", n}});
}

void BM_ParseXml_RepeatedSibling(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlRepeatedSibling(state.range(0)), {{"/out/r/a", n}});
}

} // namespace

// =============================================================================
// Registrations: a range sweep and a single large run per benchmark.
// =============================================================================

#define REGISTER_SCALING_BENCH(name)                                                                                   \
    BENCHMARK(name)->RangeMultiplier(4)->Range(16, 16384)->Unit(benchmark::kMicrosecond);                              \
    BENCHMARK(name)->Arg(65536)->Iterations(1)->Unit(benchmark::kMicrosecond)

REGISTER_SCALING_BENCH(BM_ParseKv_Flat);
REGISTER_SCALING_BENCH(BM_ParseKv_Dotted);
REGISTER_SCALING_BENCH(BM_ParseXml_Siblings);
REGISTER_SCALING_BENCH(BM_ParseXml_Attributes);
// Starts at 64: one attribute per sibling at least.
BENCHMARK(BM_ParseXml_AttributesWide)->RangeMultiplier(4)->Range(64, 16384)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_AttributesWide)->Arg(65536)->Iterations(1)->Unit(benchmark::kMicrosecond);
REGISTER_SCALING_BENCH(BM_ParseXml_WindowsData);
// The memory of this case grows with the square of N: about 144 MiB at 4 096 and about 2.1 GiB at 16 384 in a Release
// build, so larger sizes are not registered. --benchmark_filter cannot add sizes: to run a larger one, edit this range
// locally (for example Range(16, 16384)) and filter on ^BM_ParseXml_RepeatedSibling/16384$.
BENCHMARK(BM_ParseXml_RepeatedSibling)->RangeMultiplier(4)->Range(16, 4096)->Unit(benchmark::kMicrosecond);
