// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Allocation failures while the kv and xml parsers build their documents, driven through json::BaseAllocator::failAt
// (the n-th base allocation of the thread throws std::bad_alloc and the counter goes back to zero).
//
// Contract under test: the semantic parsers of kv and xml build a local json::Json through a json::PathWriter and only
// then return a mapper that sets the whole document in the event (json::Json::set, strong guarantee). A
// std::bad_alloc while the document is built leaves hlp::parser::run() before anything is mapped; the parser never maps
// a partial document.
//
// Harness. Each case runs one parser over several inputs, each with the target field set and empty and with the trace
// on and off. For every variant the parser is built first, outside the injected region; the injected region is the
// whole hlp::parser::run() call (syntax, semantic and mapping phases). Then:
//  - a warm-up run without injection, because some statics allocate once per process on first use;
//  - a clean pass on a new event {"keep":"v"} that counts K, the base allocations of run() (failAt set high, the rest
//    read back), and whose resulting event is the reference;
//  - for every n in 1..K: a new event {"keep":"v"}, failAt = n, run(), and the counter read back and reset by a RAII
//    guard whatever happens. Every n is checked, whether run() threw or not:
//      - propagated (std::bad_alloc escapes): the serialized event is exactly the one before run();
//      - absorbed (no exception and the counter reached zero: the failure hit the writer index after a member was
//        attached, and the index dropped its entry): run() reports no error and the event equals the reference.
//    A base::Error, any other exception, an event that is neither of those, or an n whose allocation was never
//    reached is a test failure.
// Each input asserts propagated + absorbed = K, its minimum K and how many points it expects to be absorbed.

#include <gtest/gtest.h>

#include <cstddef>
#include <exception>
#include <iostream>
#include <new>
#include <optional>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/jsonPathWriter.hpp>

#include <hlp/hlp.hpp>
#include <hlp/parser.hpp>

namespace
{

constexpr std::size_t BIG = 100 * 1024;           ///< Above the 64 KB pool block: every copy is a base allocation.
constexpr std::size_t CLEAN_BUDGET = 100'000'000; ///< failAt of the counting pass: never reached.
constexpr std::size_t WIDE = 200;                 ///< Above the writer index threshold.
constexpr std::size_t REPEATED = 40;              ///< Repeated xml siblings.
constexpr std::size_t MAX_REPORTED = 5;           ///< Failing points reported per variant before the sweep stops.

static_assert(WIDE > json::PathWriter::DEFAULT_INDEX_THRESHOLD);

const std::string START_EVENT = R"({"keep":"v"})";
const std::string TARGET = "/out";

using Factory = hlp::parser::Parser (*)(const hlp::Params&);

/// An event for a failure message: long values (BIG) are cut.
std::string shorten(const std::string& text)
{
    constexpr std::size_t keep = 300;
    if (text.size() <= keep)
    {
        return text;
    }
    return fmt::format("{}... ({} bytes)", text.substr(0, keep), text.size());
}

/// Resets the hook whatever happens, a fatal assertion included.
struct FailAtGuard
{
    explicit FailAtGuard(std::size_t n) { json::BaseAllocator::failAt = n; }
    ~FailAtGuard() { json::BaseAllocator::failAt = 0; }
    FailAtGuard(const FailAtGuard&) = delete;
    FailAtGuard& operator=(const FailAtGuard&) = delete;
};

/// How many injection points an input expects to be absorbed by the writer index.
enum class Absorption
{
    None,      ///< No object crosses the index threshold: every point propagates.
    AtLeastOne ///< An object crosses the threshold: at least one point is absorbed.
};

struct Input
{
    std::string label;
    hlp::Options options;
    std::string text;
    std::size_t minK;
    std::optional<Absorption> absorption; ///< Unset: the input asserts no split.
};

struct Tally
{
    std::size_t k = 0;
    std::size_t propagated = 0;
    std::size_t absorbed = 0;
};

/// One run() over a new {"keep":"v"} event, failAt = budget during the call.
struct Attempt
{
    bool threw = false;     ///< std::bad_alloc escaped run().
    std::string otherThrow; ///< Any other exception escaped run().
    bool reportedError = false;
    std::string error;
    std::size_t remaining = 0; ///< failAt read back after run().
    std::string before;        ///< Event before run().
    std::string after;         ///< Event after run().
};

Attempt attempt(const hlp::parser::Parser& parser, const std::string& text, bool trace, std::size_t budget)
{
    Attempt result;
    json::Json event {START_EVENT.c_str()};
    result.before = event.str();
    {
        FailAtGuard guard(budget);
        try
        {
            const auto err = hlp::parser::run(parser, text, event, trace);
            if (err)
            {
                result.reportedError = true;
                result.error = err->message;
            }
        }
        catch (const std::bad_alloc&)
        {
            result.threw = true;
        }
        catch (const std::exception& e)
        {
            result.otherThrow = e.what();
        }
        catch (...)
        {
            result.otherThrow = "unknown exception";
        }
        result.remaining = json::BaseAllocator::failAt;
    }
    result.after = event.str();
    return result;
}

/// Counts K with a clean pass, then fails each base allocation of run() in turn and checks the event every time.
Tally sweep(Factory factory, const hlp::Stop& stop, const Input& input, const std::string& target, bool trace)
{
    SCOPED_TRACE(fmt::format("input='{}' target='{}' trace={}", input.label, target, trace));
    Tally tally;

    // Built before the counter is armed: building the parser must not consume it
    const hlp::Params params {"injectionParser", target, stop, input.options};
    const auto parser = factory(params);

    // Warm-up: statics that allocate once per process on first use
    const auto warm = attempt(parser, input.text, trace, 0);
    if (warm.threw || !warm.otherThrow.empty() || warm.reportedError)
    {
        ADD_FAILURE() << "warm-up run failed: threw=" << warm.threw << " other='" << warm.otherThrow << "' error='"
                      << warm.error << "'";
        return tally;
    }

    // Clean pass: counts K and gives the reference
    const auto clean = attempt(parser, input.text, trace, CLEAN_BUDGET);
    if (clean.threw || !clean.otherThrow.empty() || clean.reportedError)
    {
        ADD_FAILURE() << "clean pass failed: threw=" << clean.threw << " other='" << clean.otherThrow << "' error='"
                      << clean.error << "'";
        return tally;
    }
    if (clean.remaining == 0)
    {
        ADD_FAILURE() << "the counting pass ran out of budget";
        return tally;
    }
    tally.k = CLEAN_BUDGET - clean.remaining;
    const std::string& reference = clean.after;
    EXPECT_EQ(reference, warm.after) << "the clean pass and the warm-up mapped different events";
    if (target.empty())
    {
        EXPECT_EQ(reference, START_EVENT) << "nothing is mapped without a target field";
    }
    else
    {
        json::Json mapped {reference.c_str()};
        EXPECT_TRUE(mapped.isObject(TARGET)) << "the reference holds no parsed document: " << shorten(reference);
        EXPECT_TRUE(mapped.isString("/keep")) << "the reference lost the event it started from: " << shorten(reference);
    }

    std::size_t failing = 0;
    for (std::size_t n = 1; n <= tally.k && failing < MAX_REPORTED; ++n)
    {
        SCOPED_TRACE(fmt::format("failAt = {} of K = {}", n, tally.k));
        const auto got = attempt(parser, input.text, trace, n);

        bool ok = true;
        if (!got.otherThrow.empty())
        {
            ok = false;
            ADD_FAILURE() << "an exception other than std::bad_alloc escaped run(): " << got.otherThrow;
        }
        else if (got.remaining != 0)
        {
            ok = false;
            ADD_FAILURE() << "point " << n << " not reached (" << got.remaining << " left, threw=" << got.threw << ")";
        }
        else if (got.threw)
        {
            ++tally.propagated;
            if (got.after != got.before)
            {
                ok = false;
                ADD_FAILURE() << "a propagated failure changed the event\n  before: " << got.before
                              << "\n  after:  " << shorten(got.after);
            }
        }
        else
        {
            ++tally.absorbed;
            if (got.reportedError)
            {
                ok = false;
                ADD_FAILURE() << "an absorbed failure became a base::Error: '" << got.error << "'";
            }
            if (got.after != reference)
            {
                ok = false;
                ADD_FAILURE() << "an absorbed failure mapped a document other than the reference\n  reference: "
                              << shorten(reference) << "\n  got:       " << shorten(got.after);
            }
        }

        if (!ok)
        {
            ++failing;
        }
    }

    if (failing < MAX_REPORTED)
    {
        EXPECT_EQ(tally.propagated + tally.absorbed, tally.k) << "every point is either propagated or absorbed";
    }
    else
    {
        ADD_FAILURE() << "sweep stopped after " << MAX_REPORTED << " failing points";
    }
    return tally;
}

/// Runs every input with the target field set and empty and with the trace on and off, and asserts its minimum K
/// and its split between propagated and absorbed points.
void checkInputs(Factory factory, const hlp::Stop& stop, const std::vector<Input>& inputs)
{
    for (const auto& input : inputs)
    {
        for (const std::string& target : {TARGET, std::string {}})
        {
            for (const bool trace : {true, false})
            {
                const auto tally = sweep(factory, stop, input, target, trace);
                const auto label = fmt::format("input='{}' target='{}' trace={}: K={} propagated={} absorbed={}",
                                               input.label,
                                               target,
                                               trace,
                                               tally.k,
                                               tally.propagated,
                                               tally.absorbed);
                std::cout << "[ SWEEP    ] " << label << std::endl;
                EXPECT_GE(tally.k, input.minK) << label;
                if (input.absorption == Absorption::None)
                {
                    EXPECT_EQ(tally.absorbed, 0u) << label;
                }
                else if (input.absorption == Absorption::AtLeastOne)
                {
                    EXPECT_GE(tally.absorbed, 1u) << label;
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ inputs

const hlp::Options KV_OPTIONS {"=", " ", "\"", "\\"};
const hlp::Options XML_WINDOWS {"windows"};

/// 8 pairs: one BIG value, a nested key a.b.c and a quoted value with an escaped quote.
std::string kvNarrow()
{
    return fmt::format(R"(first=one big={} a.b.c=nested quoted="say \"hi\" now" k5=v5 k6=v6 k7=v7 last=end)",
                       std::string(BIG, 'x'));
}

/// WIDE pairs, the last one repeating an earlier key.
std::string kvWide()
{
    std::string text;
    for (std::size_t i = 0; i + 1 < WIDE; ++i)
    {
        text += fmt::format("k{:03}=v{:03} ", i, i);
    }
    text += "k050=again";
    return text;
}

/// 3 levels with attributes and a BIG text.
std::string xmlLevels()
{
    return fmt::format(R"(<root id="r"><middle kind="m"><leaf lang="en">{}</leaf></middle></root>)",
                       std::string(BIG, 'x'));
}

/// WIDE distinct siblings.
std::string xmlWideSiblings()
{
    std::string text = "<root>";
    for (std::size_t i = 0; i < WIDE; ++i)
    {
        text += fmt::format("<e{:03}>v{:03}</e{:03}>", i, i, i);
    }
    return text + "</root>";
}

/// REPEATED siblings with the same name and children: the second wraps the first in an array, the rest are appended.
std::string xmlRepeatedSiblings()
{
    std::string text = "<root>";
    for (std::size_t i = 0; i < REPEATED; ++i)
    {
        text += fmt::format(R"(<item n="{}"><name>name{}</name><value>{}</value></item>)", i, i, i);
    }
    return text + "</root>";
}

/// A windows event: Event is skipped, Data with a Name becomes a member, Data without one an array element.
std::string xmlWindowsEvent()
{
    return R"(<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID></System>)"
           R"(<EventData><Data Name="SubjectUserName">bob</Data><Data Name="LogonType">2</Data></EventData>)"
           R"(<UserData><Data>first</Data><Data>second</Data></UserData></Event>)";
}

} // namespace

TEST(ObjectBuildInjectionTest, KvParseNeverMapsAPartialDocument)
{
    checkInputs(&hlp::parsers::getKVParser,
                hlp::Stop {},
                {
                    {"8 pairs", KV_OPTIONS, kvNarrow(), 8, Absorption::None},
                    {"200 pairs, one key repeated", KV_OPTIONS, kvWide(), 1, Absorption::AtLeastOne},
                });
}

TEST(ObjectBuildInjectionTest, XmlParseNeverMapsAPartialDocument)
{
    checkInputs(&hlp::parsers::getXMLParser,
                hlp::Stop {""},
                {
                    {"3 levels", {}, xmlLevels(), 3, std::nullopt},
                    {"200 distinct siblings", {}, xmlWideSiblings(), 1, Absorption::AtLeastOne},
                    {"40 repeated siblings", {}, xmlRepeatedSiblings(), REPEATED, std::nullopt},
                    {"windows event", XML_WINDOWS, xmlWindowsEvent(), 1, std::nullopt},
                });
}
