// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of the delete_fields_with_value transform helper: the production helper is compared with a
// literal copy of the implementation it had before it deleted the members equal to the value in a single pass. The
// copy lives in namespace legacy; the begin/end comments name the file and the lines the block was taken from in the
// revision before that change. Only the enclosing namespace differs: the trace macros and the utils::assert*
// functions are shared with production.
//
// The copy pins the output of the helper. A change that alters its output on purpose is applied to the legacy copy
// as well, or the cases it affects are retired. The NamesWithNul case is such a change: it compares production with
// a written expectation and asserts that the copy gives another event.
#include "builders/baseBuilders_test.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/name.hpp>

#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/utils.hpp"

namespace legacy
{
using namespace builder::builders;

// BEGIN copy of opBuilderHelperMap.cpp:2789-2877
TransformOp opBuilderHelperDeleteFieldsWithValue(const Reference& targetField,
                                                 const std::vector<OpArg>& opArgs,
                                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    const auto assetType = base::Name(buildCtx->context().assetName).parts().front();
    if (!buildCtx->allowedFields().check(assetType, targetField.dotPath()))
    {
        throw std::runtime_error(fmt::format("Field '{}' is not allowed", targetField.dotPath()));
    }

    builder::builders::utils::assertSize(opArgs, 1);

    const bool argIsValue = opArgs[0]->isValue();

    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: Target field '{}' type is not object or not exist", name, targetField.dotPath());
    const auto failureTrace2 = fmt::format("[{}] -> Failure: ", name);

    const auto isTestMode = buildCtx->isTestMode();
    const auto tgtPath = targetField.jsonPath();

    // Literal comparison value: share the Value's compact document
    const std::shared_ptr<const json::Json> capturedVal =
        argIsValue ? std::static_pointer_cast<Value>(opArgs[0])->sharedValue() : nullptr;

    const std::optional<std::string> refPath =
        (!argIsValue) ? std::optional<std::string>(std::static_pointer_cast<Reference>(opArgs[0])->jsonPath())
                      : std::nullopt;

    return [isTestMode, tgtPath, successTrace, failureTrace1, failureTrace2, capturedVal, refPath](
               base::Event event) -> TransformResult
    {
        if (!event->isObject(tgtPath))
        {
            RETURN_FAILURE(isTestMode, event, failureTrace1);
        }

        auto fieldsOpt = event->getFields(tgtPath);
        if (!fieldsOpt)
        {
            RETURN_FAILURE(isTestMode, event, failureTrace1);
        }

        // Comparison value: the shared literal, or a per-event snapshot of the reference.
        const json::Json* cmp = capturedVal.get();
        std::optional<json::Json> refSnap;
        if (cmp == nullptr && refPath)
        {
            try
            {
                refSnap = event->getJson(*refPath);
                if (refSnap)
                {
                    cmp = &*refSnap;
                }
            }
            catch (const std::runtime_error& e)
            {
                RETURN_FAILURE(isTestMode, event, failureTrace2 + e.what());
            }
        }

        const auto& fields = *fieldsOpt;

        std::string childPath;

        for (const auto& k : fields)
        {
            childPath.assign(tgtPath);
            childPath.append(json::Json::formatJsonPath(k, true));

            try
            {
                if (cmp != nullptr && event->equals(childPath, *cmp))
                {
                    (void)event->erase(childPath);
                }
            }
            catch (const std::exception& e)
            {
                RETURN_FAILURE(isTestMode, event, failureTrace2 + e.what());
            }
        }

        RETURN_SUCCESS(isTestMode, event, successTrace);
    };
}
// END copy of opBuilderHelperMap.cpp:2789-2877

} // namespace legacy

namespace
{
const std::string OP_NAME = "diffOp";
const std::string TARGET = "target";

/// What one build plus one application of the helper did.
struct RunResult
{
    bool threw = false;
    std::string what;
    bool success = false;
    std::string trace;
    std::string event;

    bool operator==(const RunResult& other) const
    {
        return threw == other.threw && what == other.what && success == other.success && trace == other.trace
               && event == other.event;
    }
};

std::string describe(const RunResult& run)
{
    return fmt::format(
        "threw={} what='{}' success={} trace='{}' event={}", run.threw, run.what, run.success, run.trace, run.event);
}

/// Result of comparing one input: the production side in test mode.
struct Outcome
{
    bool equal = false;
    bool success = false;
    bool changed = false; // no throw, success and the event differs from the input (a member was erased)
    std::string trace;
};

/// Counts the comparisons of a case and those where at least one member was erased.
struct Tally
{
    std::size_t compared = 0;
    std::size_t changed = 0;

    void add(const Outcome& out)
    {
        ++compared;
        if (out.equal && out.changed)
        {
            ++changed;
        }
    }
};

struct Pair
{
    RunResult production;
    RunResult legacyCopy;
};

std::size_t pick(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

std::string seedLabel(const char* what, std::uint32_t seed)
{
    return fmt::format("{} seed={}", what, seed);
}

std::string argsText(const std::vector<builder::builders::OpArg>& args)
{
    std::string text;
    for (const auto& arg : args)
    {
        text += " " + arg->str();
    }
    return text;
}

class DeleteFieldsWithValueDiff : public BaseBuilderTest
{
protected:
    bool testMode_ = false;

    void SetUp() override
    {
        BaseBuilderTest::SetUp();
        mocks->context.opName = OP_NAME;
        EXPECT_CALL(*mocks->ctx, context()).Times(testing::AnyNumber());
        EXPECT_CALL(*mocks->ctx, allowedFields()).Times(testing::AnyNumber());
        EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::ReturnPointee(&testMode_));
        EXPECT_CALL(*mocks->allowedFields, check(testing::_, testing::_)).WillRepeatedly(testing::Return(true));
    }

    /// Builds the production helper or its copy and applies it to an event made from @p text (the operation mutates
    /// its event: every call gets its own).
    RunResult
    runOne(bool useCopy, bool testMode, const std::vector<builder::builders::OpArg>& args, const std::string& text)
    {
        testMode_ = testMode;
        RunResult run;
        try
        {
            const auto reference = builder::builders::Reference {TARGET};
            const auto op = useCopy
                                ? legacy::opBuilderHelperDeleteFieldsWithValue(reference, args, mocks->ctx)
                                : builder::builders::opBuilderHelperDeleteFieldsWithValue(reference, args, mocks->ctx);
            base::Event event = std::make_shared<json::Json>(text.c_str());
            const auto result = op(event);
            run.success = result.success();
            run.trace = result.trace();
            run.event = result.payload()->str();
        }
        catch (const std::exception& e)
        {
            run.threw = true;
            run.what = e.what();
        }
        return run;
    }

    Pair runBoth(bool testMode, const std::vector<builder::builders::OpArg>& args, const std::string& text)
    {
        return Pair {runOne(false, testMode, args, text), runOne(true, testMode, args, text)};
    }

    /**
     * @brief Runs the production helper and its copy, with the trace on and off, on the same event text and reports
     * any difference in success, trace and whole event together with @p label (seed), the arguments and the event.
     */
    Outcome
    compareAll(const std::vector<builder::builders::OpArg>& args, const std::string& text, const std::string& label)
    {
        const auto original = json::Json {text.c_str()}.str();

        Outcome out;
        for (const bool testMode : {true, false})
        {
            const auto both = runBoth(testMode, args, text);
            if (!(both.production == both.legacyCopy))
            {
                ADD_FAILURE() << label << " testMode=" << testMode << "\n  args:" << argsText(args)
                              << "\n  event: " << text << "\n  production: " << describe(both.production)
                              << "\n  legacy:     " << describe(both.legacyCopy);
                return out;
            }
            if (testMode)
            {
                out.success = both.production.success;
                out.trace = both.production.trace;
                out.changed = !both.production.threw && both.production.success && both.production.event != original;
            }
        }
        out.equal = true;
        return out;
    }
};

// Size from which a target object counts as wide here: only a reference for the generators, the helper works the
// same way for every size.
constexpr std::size_t WIDE_THRESHOLD = 128;

// ---------------------------------------------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------------------------------------------

// Values: the first six are the literal arguments of the helper (string, number, bool, null, object, array)
const std::vector<std::string> VALUE_POOL = {R"("s")", "1", "true", "null", R"({"x":1})", "[1,2]", R"("t")", "2"};
constexpr std::size_t LITERAL_KINDS = 6;
constexpr std::size_t ARG_KINDS = 9; // six literals, a reference present, absent and inside the target object

// Names: a small alphabet so that they repeat, an empty one and some that need escaping (no names with a NUL)
const std::vector<std::string> NAME_POOL = {
    R"("a")", R"("b")", R"("c")", R"("d")", R"("e")", R"("")", R"("x/y")", R"("~")", R"("a.b")", R"("%41")"};

struct Generated
{
    std::vector<builder::builders::OpArg> args;
    std::string text;
    std::string label;
};

std::vector<builder::builders::OpArg> argsFor(std::size_t kind)
{
    if (kind < LITERAL_KINDS)
    {
        return {makeValue(VALUE_POOL[kind])};
    }
    if (kind == LITERAL_KINDS)
    {
        return {makeRef("ref")};
    }
    if (kind == LITERAL_KINDS + 1)
    {
        return {makeRef("missing")};
    }
    return {makeRef(TARGET + ".a")};
}

const char* kindName(std::size_t kind)
{
    static const char* names[ARG_KINDS] = {
        "string", "number", "bool", "null", "object", "array", "ref present", "ref absent", "ref inside"};
    return names[kind];
}

Generated generated(std::uint32_t seed)
{
    std::mt19937 rng(seed);
    const auto kind = seed % ARG_KINDS;

    std::string members;
    const auto count = pick(rng, 41);
    for (std::size_t i = 0; i < count; ++i)
    {
        members += (i == 0 ? "" : ",") + NAME_POOL[pick(rng, NAME_POOL.size())] + ":"
                   + VALUE_POOL[pick(rng, VALUE_POOL.size())];
    }
    const auto text =
        fmt::format(R"({{"{}":{{{}}},"ref":{}}})", TARGET, members, VALUE_POOL[pick(rng, VALUE_POOL.size())]);
    return {argsFor(kind), text, seedLabel("generated", seed) + " arg=" + kindName(kind)};
}

/// 140-239 distinct names followed by up to 24 members that repeat a name of the 34th member or a later one (always
/// after the 129th member); every value of the pool is present.
Generated wide(std::uint32_t seed)
{
    std::mt19937 rng(seed);
    const auto kind = seed % ARG_KINDS;

    const auto distinct = 140 + pick(rng, 100);
    std::string members;
    for (std::size_t i = 0; i < distinct; ++i)
    {
        members += (i == 0 ? "" : ",") + fmt::format(R"("k{}":{})", i, VALUE_POOL[i % VALUE_POOL.size()]);
    }
    const auto repeats = 1 + pick(rng, 24);
    for (std::size_t r = 0; r < repeats; ++r)
    {
        members += fmt::format(R"(,"k{}":{})", 33 + pick(rng, distinct - 33), VALUE_POOL[pick(rng, VALUE_POOL.size())]);
    }
    // The reference inside the object names its first member
    const auto text =
        fmt::format(R"({{"{}":{{{}}},"ref":{}}})", TARGET, members, VALUE_POOL[pick(rng, VALUE_POOL.size())]);
    auto args = argsFor(kind);
    if (kind == ARG_KINDS - 1)
    {
        args = {makeRef(TARGET + ".k0")};
    }
    return {args,
            text,
            seedLabel("wide", seed) + fmt::format(" arg={} distinct={} repeats={}", kindName(kind), distinct, repeats)};
}

static_assert(140 > WIDE_THRESHOLD, "the wide targets must hold more members than the wide reference size");
} // namespace

// ---------------------------------------------------------------------------------------------------------------
// Generated inputs
// ---------------------------------------------------------------------------------------------------------------

TEST_F(DeleteFieldsWithValueDiff, Generated)
{
    Tally tally;
    for (std::uint32_t seed = 0; seed < 300 && !HasFailure(); ++seed)
    {
        const auto input = generated(seed);
        tally.add(compareAll(input.args, input.text, input.label));
    }
    EXPECT_EQ(tally.compared, 300u);
    EXPECT_GE(tally.changed, 150u);

    // wide: more than 128 members, names repeated after the 129th member
    Tally wideTally;
    for (std::uint32_t seed = 1000; seed < 1030 && !HasFailure(); ++seed)
    {
        const auto input = wide(seed);
        const auto out = compareAll(input.args, input.text, input.label);
        wideTally.add(out);
        // Every kind but the absent reference erases members of a wide object
        if (seed % ARG_KINDS != LITERAL_KINDS + 1)
        {
            EXPECT_TRUE(out.changed) << input.label;
        }
    }
    EXPECT_EQ(wideTally.compared, 30u);
    EXPECT_GE(wideTally.changed, 25u);
}

// ---------------------------------------------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------------------------------------------

TEST_F(DeleteFieldsWithValueDiff, Failures)
{
    const std::string failure =
        fmt::format("[{}] -> Failure: Target field '{}' type is not object or not exist", OP_NAME, TARGET);

    struct Row
    {
        const char* name;
        std::string text;
    };
    const std::vector<Row> rows = {
        {"target absent", R"({"other":{"a":1},"ref":1})"},
        {"target is a number", R"({"target":5,"ref":5})"},
        {"target is a string", R"({"target":"s","ref":"s"})"},
        {"target is an array", R"({"target":[1,2],"ref":1})"},
        {"target is null", R"({"target":null,"ref":null})"},
        {"target is a bool", R"({"target":true,"ref":true})"},
    };

    for (const auto& row : rows)
    {
        for (std::size_t kind = 0; kind < ARG_KINDS; ++kind)
        {
            const auto label = fmt::format("{} arg={}", row.name, kindName(kind));
            const auto out = compareAll(argsFor(kind), row.text, label);
            EXPECT_TRUE(out.equal) << label;
            EXPECT_FALSE(out.success) << label;
            EXPECT_EQ(out.trace, failure) << label;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Names with a NUL character: written expectation. Production must erase the members equal to the value and never a
// member of another name; the copy erases by a name cut at the NUL, so it gives another event. This case fails until
// the production helper no longer goes through the cut name.
// ---------------------------------------------------------------------------------------------------------------

TEST_F(DeleteFieldsWithValueDiff, NamesWithNul)
{
    struct Row
    {
        const char* name;
        std::string text;
        std::string expected;
    };
    const std::vector<Row> rows = {
        {"nul name first", R"({"target":{"a\u0000b":1,"a":2}})", R"({"target":{"a":2}})"},
        {"nul name last", R"({"target":{"a":2,"a\u0000b":1}})", R"({"target":{"a":2}})"},
        {"nul name twice", R"({"target":{"a\u0000b":1,"a\u0000b":1,"a":1}})", R"({"target":{}})"},
    };

    for (const auto& row : rows)
    {
        const auto expected = json::Json {row.expected.c_str()}.str();
        for (const bool testMode : {true, false})
        {
            const auto both = runBoth(testMode, {makeValue("1")}, row.text);
            const auto label = fmt::format("{} testMode={}", row.name, testMode);
            EXPECT_FALSE(both.production.threw) << label << ": " << both.production.what;
            EXPECT_TRUE(both.production.success) << label;
            EXPECT_EQ(both.production.event, expected) << label << "\n  event: " << row.text;
            EXPECT_NE(both.legacyCopy.event, expected)
                << label << ": the copy must give another event\n  event: " << row.text;
        }
    }
}
