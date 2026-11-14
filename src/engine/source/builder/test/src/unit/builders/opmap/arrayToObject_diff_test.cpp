// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential tests of the array_to_object and array_to_object_changes map helpers: the production helpers are
// compared with a literal copy of the implementation they had before they built their result object through
// json::PathWriter. The copy lives in namespace legacy; the begin/end comments name the file and the lines each block
// was taken from in the revision before that change. Only the enclosing namespace differs: the trace macros and the
// utils::assert* functions are shared with production.
//
// The copy pins the output of the helpers. A change that alters their output on purpose is applied to the legacy copy
// as well, or the cases it affects are retired.
#include "builders/baseBuilders_test.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>

#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/utils.hpp"

namespace legacy
{
using namespace builder::builders;

// BEGIN copy of opBuilderHelperMap.cpp:39-39
constexpr auto TRACE_SUCCESS = "[{}] -> Success";
// END copy of opBuilderHelperMap.cpp:39-39

// BEGIN copy of opBuilderHelperMap.cpp:43-43
constexpr auto TRACE_REFERENCE_NOT_FOUND = "[{}] -> Failure: Parameter '{}' reference not found";
// END copy of opBuilderHelperMap.cpp:43-43

// BEGIN copy of opBuilderHelperMap.cpp:1574-1782
// field: array_to_object($array, 'key_path', 'value_path', ['raw_keys'])
MapOp opBuilderHelperArrayObjToMapkv(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    builder::builders::utils::assertSize(opArgs, 3, 4);
    builder::builders::utils::assertRef(opArgs, 0);

    const auto arrayRef = *std::static_pointer_cast<Reference>(opArgs[0]);

    if (buildCtx->validator().hasField(arrayRef.dotPath()))
    {
        auto jType = buildCtx->validator().getJsonType(arrayRef.dotPath());
        if (jType != json::Json::Type::Object)
        {
            throw std::runtime_error(
                fmt::format("Expected array of 'object' but got array of '{}'", json::Json::typeToStr(jType)));
        }
    }

    builder::builders::utils::assertValue(opArgs, 1);
    const auto keyValue = std::static_pointer_cast<Value>(opArgs[1])->value();
    if (!keyValue.isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'", keyValue.typeName()));
    }

    std::string keyName;
    if (keyValue.getString(keyName) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("Failed to get the string value of parameter 2 got type '{}'", keyValue.typeName()));
    }

    if (keyName.empty())
    {
        throw std::runtime_error("Key path cannot be an empty string");
    }
    if (keyName.front() == '/')
    {
        throw std::runtime_error("Key path must be a dot path: a JSON pointer starting with '/' is not accepted");
    }
    const auto keyPointer = json::Json::formatJsonPath(keyName);

    builder::builders::utils::assertValue(opArgs, 2);
    const auto fieldValueJson = std::static_pointer_cast<Value>(opArgs[2])->value();
    if (!fieldValueJson.isString())
    {
        throw std::runtime_error(
            fmt::format("Expected 'string' parameter but got type '{}'", fieldValueJson.typeName()));
    }
    std::string fieldValue;
    if (fieldValueJson.getString(fieldValue) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("Failed to get the string value of parameter 3 got type '{}'", fieldValueJson.typeName()));
    }
    if (fieldValue.empty())
    {
        throw std::runtime_error("Value path cannot be an empty string");
    }
    if (fieldValue.front() == '/')
    {
        throw std::runtime_error("Value path must be a dot path: a JSON pointer starting with '/' is not accepted");
    }
    const auto valuePointer = json::Json::formatJsonPath(fieldValue);

    // Optional 'raw_keys' mode: keep the keys verbatim instead of normalizing them to lowercase snake_case
    bool skipSerializer = false;
    if (opArgs.size() == 4)
    {
        builder::builders::utils::assertValue(opArgs, 3);
        std::string mode;
        if (std::static_pointer_cast<Value>(opArgs[3])->value().getString(mode) != json::RetGet::Success
            || mode != "raw_keys")
        {
            throw std::runtime_error(
                fmt::format("Expected the literal 'raw_keys' as parameter 4 but got {}", opArgs[3]->str()));
        }
        skipSerializer = true;
    }

    const auto normalizeStr = [](std::string_view in) -> std::string
    {
        std::string out;
        out.reserve(in.size());
        bool lastUnderscore = false;

        auto push_underscore = [&]()
        {
            if (!out.empty() && !lastUnderscore)
            {
                out.push_back('_');
                lastUnderscore = true;
            }
        };

        for (unsigned char c : std::string(in))
        {
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<unsigned char>(c + 32);
            }

            if (std::isalnum(c) || c == '_')
            {
                if (c == '_')
                {
                    if (!out.empty() && !lastUnderscore)
                    {
                        out.push_back('_');
                        lastUnderscore = true;
                    }
                }
                else
                {
                    out.push_back(static_cast<char>(c));
                    lastUnderscore = false;
                }
                continue;
            }

            if (c == ' ' || c == '/' || c == '.' || c == '-' || c == '\\' || c == ':')
            {
                push_underscore();
            }
        }

        if (!out.empty() && out.back() == '_')
        {
            out.pop_back();
        }

        return out;
    };

    const std::string traceName = buildCtx->context().opName;
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};
    const std::string failureArrNotFound = fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, arrayRef.dotPath());
    const std::string failureTrace = fmt::format("[{}] -> Failure: Result map is empty", traceName);

    return [normalizeStr,
            keyNamePP = json::PointerPath(keyPointer),
            valuePointer,
            skipSerializer,
            traceName,
            successTrace,
            failureArrNotFound,
            failureTrace,
            isTestMode = buildCtx->isTestMode(),
            arrayPath = arrayRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        const auto arrayOpt = event->getArray(arrayPath);
        if (!arrayOpt.has_value())
        {
            RETURN_FAILURE(isTestMode, json::Json {}, failureArrNotFound);
        }

        json::Json result;
        result.setObject();

        size_t inserts {0};

        try
        {
            for (const auto& element : arrayOpt.value())
            {
                if (!element.isObject())
                {
                    continue;
                }

                std::string keyStr;
                if (element.getString(keyStr, keyNamePP) != json::RetGet::Success || keyStr.empty())
                {
                    continue;
                }

                const auto valueOpt = valuePointer.empty() ? element.getJson() : element.getJson(valuePointer);
                if (!valueOpt.has_value())
                {
                    continue;
                }

                const std::string normalizedKey = skipSerializer ? keyStr : normalizeStr(std::string_view {keyStr});
                if (normalizedKey.empty())
                {
                    continue;
                }

                const std::string basePath = json::Json::formatJsonPath(normalizedKey, /*skipDot=*/true);

                result.set(basePath, valueOpt.value());
                ++inserts;
            }
        }
        catch (const std::exception& e)
        {
            RETURN_FAILURE(isTestMode,
                           json::Json {},
                           fmt::format("[{}] -> Failure: Failed to build object from array: {}", traceName, e.what()));
        }

        if (inserts == 0)
        {
            RETURN_FAILURE(isTestMode, json::Json {}, failureTrace);
        }

        RETURN_SUCCESS(isTestMode, result, successTrace);
    };
}
// END copy of opBuilderHelperMap.cpp:1574-1782

// BEGIN copy of opBuilderHelperMap.cpp:1784-2038
// field: array_to_object_changes($array, 'key_path', 'new_value_path', 'old_value_path', ['raw_keys'])
MapOp opBuilderHelperArrayExtractKeyObj(const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    builder::builders::utils::assertSize(opArgs, 4, 5);
    builder::builders::utils::assertRef(opArgs, 0);

    const auto arrayRef = *std::static_pointer_cast<Reference>(opArgs[0]);

    if (buildCtx->validator().hasField(arrayRef.dotPath()))
    {
        auto jType = buildCtx->validator().getJsonType(arrayRef.dotPath());
        if (jType != json::Json::Type::Object)
        {
            throw std::runtime_error(
                fmt::format("Expected array of 'object' but got array of '{}'", json::Json::typeToStr(jType)));
        }
    }

    builder::builders::utils::assertValue(opArgs, 1);
    const auto keyValue = std::static_pointer_cast<Value>(opArgs[1])->value();
    if (!keyValue.isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'", keyValue.typeName()));
    }
    std::string keyName;
    if (keyValue.getString(keyName) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("Failed to get the string value of parameter 2 got type '{}'", keyValue.typeName()));
    }
    if (keyName.empty())
    {
        throw std::runtime_error("Key path cannot be an empty string");
    }
    if (keyName.front() == '/')
    {
        throw std::runtime_error("Key path must be a dot path: a JSON pointer starting with '/' is not accepted");
    }
    const auto keyPointer = json::Json::formatJsonPath(keyName);

    builder::builders::utils::assertValue(opArgs, 2);
    const auto newValueJson = std::static_pointer_cast<Value>(opArgs[2])->value();
    if (!newValueJson.isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'", newValueJson.typeName()));
    }
    std::string newValuePath;
    if (newValueJson.getString(newValuePath) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("Failed to get the string value of parameter 3 got type '{}'", newValueJson.typeName()));
    }
    if (newValuePath.empty())
    {
        throw std::runtime_error("New value path cannot be an empty string");
    }
    if (newValuePath.front() == '/')
    {
        throw std::runtime_error("New value path must be a dot path: a JSON pointer starting with '/' is not accepted");
    }
    const auto newValuePointer = json::Json::formatJsonPath(newValuePath);

    builder::builders::utils::assertValue(opArgs, 3);
    const auto oldValueJson = std::static_pointer_cast<Value>(opArgs[3])->value();
    if (!oldValueJson.isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'", oldValueJson.typeName()));
    }
    std::string oldValuePath;
    if (oldValueJson.getString(oldValuePath) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("Failed to get the string value of parameter 4 got type '{}'", oldValueJson.typeName()));
    }
    if (oldValuePath.empty())
    {
        throw std::runtime_error("Old value path cannot be an empty string");
    }
    if (oldValuePath.front() == '/')
    {
        throw std::runtime_error("Old value path must be a dot path: a JSON pointer starting with '/' is not accepted");
    }
    const auto oldValuePointer = json::Json::formatJsonPath(oldValuePath);

    // Optional 'raw_keys' mode: keep the keys verbatim instead of normalizing them to lowercase snake_case
    bool skipSerializer = false;
    if (opArgs.size() == 5)
    {
        builder::builders::utils::assertValue(opArgs, 4);
        std::string mode;
        if (std::static_pointer_cast<Value>(opArgs[4])->value().getString(mode) != json::RetGet::Success
            || mode != "raw_keys")
        {
            throw std::runtime_error(
                fmt::format("Expected the literal 'raw_keys' as parameter 5 but got {}", opArgs[4]->str()));
        }
        skipSerializer = true;
    }

    const auto normalizeStr = [](std::string_view in) -> std::string
    {
        std::string out;
        out.reserve(in.size());
        bool lastUnderscore = false;

        auto push_underscore = [&]()
        {
            if (!out.empty() && !lastUnderscore)
            {
                out.push_back('_');
                lastUnderscore = true;
            }
        };

        for (unsigned char c : std::string(in))
        {
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<unsigned char>(c + 32);
            }

            if (std::isalnum(c) || c == '_')
            {
                if (c == '_')
                {
                    if (!out.empty() && !lastUnderscore)
                    {
                        out.push_back('_');
                        lastUnderscore = true;
                    }
                }
                else
                {
                    out.push_back(static_cast<char>(c));
                    lastUnderscore = false;
                }
                continue;
            }

            if (c == ' ' || c == '/' || c == '.' || c == '-' || c == '\\' || c == ':')
            {
                push_underscore();
            }
        }

        if (!out.empty() && out.back() == '_')
        {
            out.pop_back();
        }

        return out;
    };

    const std::string traceName = buildCtx->context().opName;
    const std::string successTrace {fmt::format(TRACE_SUCCESS, traceName)};
    const std::string failureArrNotFound = fmt::format(TRACE_REFERENCE_NOT_FOUND, traceName, arrayRef.dotPath());
    const std::string failureTrace = fmt::format("[{}] -> Failure: Result map is empty", traceName);

    return [normalizeStr,
            keyNamePP = json::PointerPath(keyPointer),
            newValuePointer,
            oldValuePointer,
            skipSerializer,
            traceName,
            successTrace,
            failureArrNotFound,
            failureTrace,
            isTestMode = buildCtx->isTestMode(),
            arrayPath = arrayRef.jsonPath()](base::ConstEvent event) -> MapResult
    {
        const auto arrayOpt = event->getArray(arrayPath);
        if (!arrayOpt.has_value())
        {
            RETURN_FAILURE(isTestMode, json::Json {}, failureArrNotFound);
        }

        json::Json result;
        result.setObject();

        size_t inserts {0};

        try
        {
            for (const auto& element : arrayOpt.value())
            {
                if (!element.isObject())
                {
                    continue;
                }

                std::string keyStr;
                if (element.getString(keyStr, keyNamePP) != json::RetGet::Success || keyStr.empty())
                {
                    continue;
                }

                const auto newValueOpt = newValuePointer.empty() ? element.getJson() : element.getJson(newValuePointer);
                if (!newValueOpt.has_value())
                {
                    continue;
                }

                const auto oldValueOpt = oldValuePointer.empty() ? element.getJson() : element.getJson(oldValuePointer);

                const std::string normalizedKey = skipSerializer ? keyStr : normalizeStr(std::string_view {keyStr});
                if (normalizedKey.empty())
                {
                    continue;
                }

                const std::string basePath = json::Json::formatJsonPath(normalizedKey, /*skipDot=*/true);

                const auto setValue = [&](std::string_view relPath, const json::Json& value)
                {
                    if (relPath.empty())
                    {
                        result.set(basePath, value);
                    }
                    else
                    {
                        result.set(fmt::format("{}{}", basePath, relPath), value);
                    }
                };

                setValue(newValuePointer, newValueOpt.value());
                if (oldValueOpt.has_value())
                {
                    std::string oldValStr;
                    bool skipOld = oldValueOpt->isString() && oldValueOpt->getString(oldValStr) == json::RetGet::Success
                                   && base::utils::string::trim(oldValStr).empty();
                    if (!skipOld)
                    {
                        setValue(oldValuePointer, *oldValueOpt);
                    }
                }

                ++inserts;
            }
        }
        catch (const std::exception& e)
        {
            RETURN_FAILURE(isTestMode,
                           json::Json {},
                           fmt::format("[{}] -> Failure: Failed to build object from array: {}", traceName, e.what()));
        }

        if (inserts == 0)
        {
            RETURN_FAILURE(isTestMode, json::Json {}, failureTrace);
        }

        RETURN_SUCCESS(isTestMode, result, successTrace);
    };
}
// END copy of opBuilderHelperMap.cpp:1784-2038

} // namespace legacy

namespace
{
using Factory = builder::builders::MapOp (*)(const std::vector<builder::builders::OpArg>&,
                                             const std::shared_ptr<const builder::builders::IBuildCtx>&);

enum class HelperKind
{
    ToObject, // array_to_object($arr, key, value [, raw_keys])
    Changes   // array_to_object_changes($arr, key, new, old [, raw_keys])
};

const std::string OP_NAME = "diffOp";

/// What one build plus one application of a helper did.
struct RunResult
{
    bool threw = false;
    std::string what;
    bool success = false;
    std::string trace;
    std::string payload;
    json::Json doc;

    bool operator==(const RunResult& other) const
    {
        return threw == other.threw && what == other.what && success == other.success && trace == other.trace
               && payload == other.payload;
    }
};

std::string describe(const RunResult& run)
{
    return fmt::format("threw={} what='{}' success={} trace='{}' payload={}",
                       run.threw,
                       run.what,
                       run.success,
                       run.trace,
                       run.payload);
}

/// Result of comparing one input: the production side in test mode.
struct Outcome
{
    bool equal = false;
    bool success = false;
    bool productive = false; // no throw, success and a non-empty result
    std::string trace;
    json::Json doc;
};

/// Counts the comparisons of a case and those that succeeded with a non-empty result.
struct Tally
{
    std::size_t compared = 0;
    std::size_t productive = 0;

    void add(const Outcome& out)
    {
        ++compared;
        if (out.equal && out.productive)
        {
            ++productive;
        }
    }
};

std::size_t pick(std::mt19937& rng, std::size_t n)
{
    return static_cast<std::size_t>(rng() % n);
}

std::string seedLabel(const char* what, std::uint32_t seed)
{
    return fmt::format("{} seed={}", what, seed);
}

// The array lives at the event field "arr"; the key, value, new and old paths are dot paths relative to each element
const std::string ARRAY_FIELD = "arr";

std::string jsonString(const std::string& text)
{
    return "\"" + text + "\"";
}

std::string eventText(const std::vector<std::string>& elements)
{
    std::string text = R"({"arr":[)";
    for (std::size_t i = 0; i < elements.size(); ++i)
    {
        text += (i == 0 ? "" : ",") + elements[i];
    }
    return text + "]}";
}

std::vector<builder::builders::OpArg> toObjectArgs(const std::string& valuePath, bool rawKeys)
{
    std::vector<builder::builders::OpArg> args {
        makeRef(ARRAY_FIELD), makeValue(jsonString("k")), makeValue(jsonString(valuePath))};
    if (rawKeys)
    {
        args.push_back(makeValue(jsonString("raw_keys")));
    }
    return args;
}

std::vector<builder::builders::OpArg> changesArgs(const std::string& newPath, const std::string& oldPath, bool rawKeys)
{
    std::vector<builder::builders::OpArg> args {makeRef(ARRAY_FIELD),
                                                makeValue(jsonString("k")),
                                                makeValue(jsonString(newPath)),
                                                makeValue(jsonString(oldPath))};
    if (rawKeys)
    {
        args.push_back(makeValue(jsonString("raw_keys")));
    }
    return args;
}

class ArrayToObjectDiff : public BaseBuilderTest
{
protected:
    bool testMode_ = false;

    void SetUp() override
    {
        BaseBuilderTest::SetUp();
        mocks->context.opName = OP_NAME;
        // The array field is not in the schema; every build of both the production helper and its copy asks for it
        EXPECT_CALL(*mocks->ctx, validator()).Times(testing::AnyNumber());
        EXPECT_CALL(*mocks->ctx, context()).Times(testing::AnyNumber());
        EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::ReturnPointee(&testMode_));
        EXPECT_CALL(*mocks->validator, hasField(testing::_)).WillRepeatedly(testing::Return(false));
    }

    /// Builds the production helper or its copy and applies it to @p event.
    RunResult runOne(HelperKind helper,
                     bool useCopy,
                     bool testMode,
                     const std::vector<builder::builders::OpArg>& args,
                     const std::shared_ptr<const json::Json>& event)
    {
        testMode_ = testMode;
        Factory factory = nullptr;
        if (helper == HelperKind::ToObject)
        {
            factory =
                useCopy ? &legacy::opBuilderHelperArrayObjToMapkv : &builder::builders::opBuilderHelperArrayObjToMapkv;
        }
        else
        {
            factory = useCopy ? &legacy::opBuilderHelperArrayExtractKeyObj
                              : &builder::builders::opBuilderHelperArrayExtractKeyObj;
        }

        RunResult run;
        try
        {
            const auto op = factory(args, mocks->ctx);
            const auto result = op(event);
            run.success = result.success();
            run.trace = result.trace();
            run.doc = json::Json {result.payload()};
            run.payload = run.doc.str();
        }
        catch (const std::exception& e)
        {
            run.threw = true;
            run.what = e.what();
        }
        return run;
    }

    /**
     * @brief Runs the production helper and its copy, with the trace on and off, on the same event and reports any
     * difference in success, trace and whole result together with @p label (seed), the arguments and the event.
     */
    Outcome compareAll(HelperKind helper,
                       const std::vector<builder::builders::OpArg>& args,
                       const std::string& text,
                       const std::string& label)
    {
        const std::shared_ptr<const json::Json> event = std::make_shared<json::Json>(text.c_str());

        Outcome out;
        for (const bool testMode : {true, false})
        {
            const auto now = runOne(helper, false, testMode, args, event);
            const auto before = runOne(helper, true, testMode, args, event);
            if (!(now == before))
            {
                std::string argText;
                for (const auto& arg : args)
                {
                    argText += " " + arg->str();
                }
                ADD_FAILURE() << label << " testMode=" << testMode << "\n  args:" << argText << "\n  event: " << text
                              << "\n  production: " << describe(now) << "\n  legacy:     " << describe(before);
                return out;
            }
            if (testMode)
            {
                out.success = now.success;
                out.trace = now.trace;
                out.productive = !now.threw && now.success && now.doc.isObject() && now.doc.size() > 0;
                out.doc = json::Json {now.doc};
            }
        }
        out.equal = true;
        return out;
    }
};

// Event nodes the writer threshold applies to must hold more than json::PathWriter::DEFAULT_INDEX_THRESHOLD members.
constexpr std::size_t WIDE_THRESHOLD = 128;

// ---------------------------------------------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------------------------------------------

// Keys: a small alphabet so that they repeat, some that normalize to the same text (A b, a_b, a-b), one that
// normalizes to nothing (!!), an empty one, and the ones raw_keys keeps verbatim (/, ~, ., 5, 007)
const std::vector<std::string> KEY_POOL = {R"("a")",
                                           R"("b")",
                                           R"("c")",
                                           R"("A b")",
                                           R"("a_b")",
                                           R"("a-b")",
                                           R"("!!")",
                                           R"("")",
                                           R"("x/y")",
                                           R"("~")",
                                           R"("a.b")",
                                           R"("5")",
                                           R"("007")",
                                           R"("a~1b")"};

const std::vector<std::string> NON_STRING_KEYS = {"5", "null", "true", "{}", "[]", R"({"a":1})"};

const std::vector<std::string> NON_OBJECT_ELEMENTS = {"1", R"("s")", "[1]", "null", "true"};

const std::vector<std::string> VALUE_POOL = {
    "1", R"("s")", "true", "null", R"({"x":1,"y":"s"})", R"({"y":2})", "[1,2]", R"({"x":{"x":3}})"};

/// The member "k": a key from the pool, a non-string value, or no member at all. Ends with a comma when not empty.
std::string keyMember(std::mt19937& rng)
{
    const auto r = pick(rng, 100);
    if (r < 70)
    {
        return R"("k":)" + KEY_POOL[pick(rng, KEY_POOL.size())] + ",";
    }
    if (r < 78)
    {
        return "";
    }
    return R"("k":)" + NON_STRING_KEYS[pick(rng, NON_STRING_KEYS.size())] + ",";
}

std::string trimTrailingComma(std::string members)
{
    if (!members.empty() && members.back() == ',')
    {
        members.pop_back();
    }
    return members;
}

std::string toObjectElement(std::mt19937& rng)
{
    if (pick(rng, 100) < 10)
    {
        return NON_OBJECT_ELEMENTS[pick(rng, NON_OBJECT_ELEMENTS.size())];
    }
    std::string members = keyMember(rng);
    if (pick(rng, 100) >= 12)
    {
        members += R"("v":)" + VALUE_POOL[pick(rng, VALUE_POOL.size())] + ",";
    }
    if (pick(rng, 100) < 20)
    {
        members += R"("z":1,)";
    }
    return "{" + trimTrailingComma(members) + "}";
}

const std::string SHAPE_ARRAY_TO_OBJECT = R"({"0":1,"x":"nx"})";

/// An element for array_to_object_changes: the members k, n, o, v and x. @p shapes counts the elements whose n is an
/// object with the members "0" and "x" (an array that array_to_object_changes('n.0', 'n.x') turns into an object).
std::string changesElement(std::mt19937& rng, bool favourShape, std::size_t& shapes)
{
    if (pick(rng, 100) < 8)
    {
        return NON_OBJECT_ELEMENTS[pick(rng, NON_OBJECT_ELEMENTS.size())];
    }
    std::string members = keyMember(rng);

    const auto n = pick(rng, 100);
    if (n < (favourShape ? 40u : 12u))
    {
        members += R"("n":)" + SHAPE_ARRAY_TO_OBJECT + ",";
        ++shapes;
    }
    else if (n < 55)
    {
        members += R"("n":1,)";
    }
    else if (n < 65)
    {
        members += R"("n":"s",)";
    }
    else if (n < 75)
    {
        members += R"("n":{"x":2},)";
    }
    else if (n < 83)
    {
        members += R"("n":[5,6],)";
    }
    else if (n < 90)
    {
        members += R"("n":null,)";
    }

    static const std::vector<std::string> oldValues = {
        R"("old")", R"("")", R"("  ")", "5", R"({"y":"oy"})", R"({"a":1})", R"({"y":" "})", R"("o2")"};
    if (pick(rng, 100) >= 15)
    {
        members += R"("o":)" + oldValues[pick(rng, oldValues.size())] + ",";
    }

    static const std::vector<std::string> nested = {
        R"({"new":1,"old":"vo"})", R"({"new":{"w":1}})", R"("scalar")", R"({"old":""})", R"({"new":2,"old":"  "})"};
    if (pick(rng, 100) >= 25)
    {
        members += R"("v":)" + nested[pick(rng, nested.size())] + ",";
    }

    static const std::vector<std::string> xs = {R"("xv")", R"("")", "5", R"({"a":1})", R"("  ")"};
    if (pick(rng, 100) < 30)
    {
        members += R"("x":)" + xs[pick(rng, xs.size())] + ",";
    }
    return "{" + trimTrailingComma(members) + "}";
}

std::string generatedToObjectText(std::mt19937& rng)
{
    std::vector<std::string> elements;
    const auto count = pick(rng, 41);
    for (std::size_t i = 0; i < count; ++i)
    {
        elements.push_back(toObjectElement(rng));
    }
    return eventText(elements);
}

std::string generatedChangesText(std::mt19937& rng, bool favourShape, std::size_t& shapes)
{
    std::vector<std::string> elements;
    const auto count = pick(rng, 41);
    for (std::size_t i = 0; i < count; ++i)
    {
        elements.push_back(changesElement(rng, favourShape, shapes));
    }
    return eventText(elements);
}

const std::vector<std::string> VALUE_PATHS = {"v", "v.x", "."};

struct ChangesPaths
{
    std::string newPath;
    std::string oldPath;
};

// Nested, numeric token, array to object, the same path in both, one a prefix of the other (both ways) and the
// whole element ('.') as new, as old and as both
const std::vector<ChangesPaths> CHANGES_PATHS = {{"n", "o"},
                                                 {"n.x", "o.y"},
                                                 {"n.0", "o"},
                                                 {"n.0", "n.x"},
                                                 {"n", "n"},
                                                 {"v", "v.old"},
                                                 {"v.new", "v"},
                                                 {".", "x"},
                                                 {"n", "."},
                                                 {".", "."}};
constexpr std::size_t ARRAY_TO_OBJECT_PATHS_INDEX = 3;

/// 200-600 elements with distinct keys, followed by up to 20 elements that repeat a key of the first ones
/// (always after the 129th element).
std::string wideToObjectText(std::mt19937& rng, std::size_t distinct)
{
    std::vector<std::string> elements;
    for (std::size_t i = 0; i < distinct; ++i)
    {
        elements.push_back(fmt::format(R"({{"k":"key{0}","v":{{"x":{0}}}}})", i));
    }
    const auto repeats = 1 + pick(rng, 20);
    for (std::size_t r = 0; r < repeats; ++r)
    {
        elements.push_back(fmt::format(R"({{"k":"key{}","v":{{"x":"again{}"}}}})", pick(rng, distinct), r));
    }
    // Keys that need escaping, look numeric or normalize to the same text, written twice into the wide result
    for (std::size_t round = 0; round < 2; ++round)
    {
        for (std::size_t j = 0; j < KEY_POOL.size(); ++j)
        {
            elements.push_back(fmt::format(R"({{"k":{},"v":{{"x":"pool{}-{}"}}}})", KEY_POOL[j], j, round));
        }
    }
    return eventText(elements);
}

std::string wideChangesText(std::mt19937& rng, std::size_t distinct)
{
    std::vector<std::string> elements;
    for (std::size_t i = 0; i < distinct; ++i)
    {
        elements.push_back(fmt::format(
            R"({{"k":"key{0}","n":{{"0":{0},"x":"nx{0}"}},"o":{{"y":"oy{0}"}},"v":{{"new":{0},"old":"vo{0}"}},"x":"xv{0}"}})",
            i));
    }
    const auto repeats = 1 + pick(rng, 20);
    for (std::size_t r = 0; r < repeats; ++r)
    {
        const auto key = pick(rng, distinct);
        if (r % 2 == 0)
        {
            // The repeated key brings new values and blank old values: the old value written before stays
            elements.push_back(
                fmt::format(R"({{"k":"key{}","n":{{"0":{},"x":"nr"}},"o":" ","v":{{"new":{},"old":""}},"x":" "}})",
                            key,
                            1000 + r,
                            2000 + r));
        }
        else
        {
            elements.push_back(fmt::format(
                R"({{"k":"key{}","n":{{"0":{},"x":"nr"}},"o":{{"y":"oy{}"}},"v":{{"new":{},"old":"vr{}"}},"x":"xr{}"}})",
                key,
                1000 + r,
                r,
                2000 + r,
                r,
                r));
        }
    }
    // Keys that need escaping, look numeric or normalize to the same text, written twice into the wide result
    for (std::size_t round = 0; round < 2; ++round)
    {
        for (std::size_t j = 0; j < KEY_POOL.size(); ++j)
        {
            elements.push_back(fmt::format(
                R"({{"k":{0},"n":{{"0":{1},"x":"np{2}"}},"o":{{"y":"op{2}"}},"v":{{"new":{1},"old":"vp{2}"}},"x":"xp{2}"}})",
                KEY_POOL[j],
                j,
                round));
        }
    }
    return eventText(elements);
}

} // namespace

// ---------------------------------------------------------------------------------------------------------------
// array_to_object
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ArrayToObjectDiff, ArrayToObjectGenerated)
{
    Tally generated;
    for (std::uint32_t seed = 0; seed < 300 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto& valuePath = VALUE_PATHS[seed % VALUE_PATHS.size()];
        const bool rawKeys = (seed / VALUE_PATHS.size()) % 2 == 1;
        const auto label = seedLabel("generated", seed) + fmt::format(" valuePath={} rawKeys={}", valuePath, rawKeys);
        generated.add(
            compareAll(HelperKind::ToObject, toObjectArgs(valuePath, rawKeys), generatedToObjectText(rng), label));
    }
    EXPECT_EQ(generated.compared, 300u);
    EXPECT_GE(generated.productive, 200u);

    // wide: 200-600 distinct keys (more than 128 members in the result) and repeated keys after the 129th element
    Tally wide;
    for (std::uint32_t seed = 1000; seed < 1030 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto distinct = 200 + pick(rng, 401);
        const auto& valuePath = VALUE_PATHS[seed % VALUE_PATHS.size()];
        const bool rawKeys = (seed / VALUE_PATHS.size()) % 2 == 1;
        const auto label =
            seedLabel("wide", seed) + fmt::format(" distinct={} valuePath={} rawKeys={}", distinct, valuePath, rawKeys);
        const auto out =
            compareAll(HelperKind::ToObject, toObjectArgs(valuePath, rawKeys), wideToObjectText(rng, distinct), label);
        wide.add(out);
        if (out.productive)
        {
            EXPECT_GE(out.doc.size(""), distinct) << label;
            EXPECT_GT(out.doc.size(""), WIDE_THRESHOLD) << label;
        }
    }
    EXPECT_EQ(wide.compared, 30u);
    EXPECT_EQ(wide.productive, 30u);
}

// ---------------------------------------------------------------------------------------------------------------
// array_to_object_changes
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ArrayToObjectDiff, ArrayToObjectChangesGenerated)
{
    Tally generated;
    std::size_t shapes = 0;
    for (std::uint32_t seed = 2000; seed < 2300 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto index = seed % CHANGES_PATHS.size();
        const auto& paths = CHANGES_PATHS[index];
        const bool rawKeys = (seed / CHANGES_PATHS.size()) % 2 == 1;
        const auto label = seedLabel("generated", seed)
                           + fmt::format(" new={} old={} rawKeys={}", paths.newPath, paths.oldPath, rawKeys);
        std::size_t emitted = 0;
        const auto text = generatedChangesText(rng, index == ARRAY_TO_OBJECT_PATHS_INDEX, emitted);
        if (index == ARRAY_TO_OBJECT_PATHS_INDEX)
        {
            shapes += emitted;
        }
        generated.add(compareAll(HelperKind::Changes, changesArgs(paths.newPath, paths.oldPath, rawKeys), text, label));
    }
    EXPECT_EQ(generated.compared, 300u);
    EXPECT_GE(generated.productive, 150u);
    // the n.0 + n.x shape (an object with the members "0" and "x" as n) was emitted on purpose
    EXPECT_GE(shapes, 1u);

    // wide: 200-600 distinct keys (more than 128 members in the result) and repeated keys after the 129th element
    Tally wide;
    for (std::uint32_t seed = 3000; seed < 3030 && !HasFailure(); ++seed)
    {
        std::mt19937 rng(seed);
        const auto distinct = 200 + pick(rng, 401);
        const auto& paths = CHANGES_PATHS[seed % CHANGES_PATHS.size()];
        const bool rawKeys = (seed / CHANGES_PATHS.size()) % 2 == 1;
        const auto label =
            seedLabel("wide", seed)
            + fmt::format(" distinct={} new={} old={} rawKeys={}", distinct, paths.newPath, paths.oldPath, rawKeys);
        const auto out = compareAll(HelperKind::Changes,
                                    changesArgs(paths.newPath, paths.oldPath, rawKeys),
                                    wideChangesText(rng, distinct),
                                    label);
        wide.add(out);
        if (out.productive)
        {
            EXPECT_GE(out.doc.size(""), distinct) << label;
            EXPECT_GT(out.doc.size(""), WIDE_THRESHOLD) << label;
        }
    }
    EXPECT_EQ(wide.compared, 30u);
    EXPECT_EQ(wide.productive, 30u);
}

// ---------------------------------------------------------------------------------------------------------------
// Failures and empty results
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ArrayToObjectDiff, FailuresAndEmpty)
{
    const std::string refNotFound =
        fmt::format("[{}] -> Failure: Parameter '{}' reference not found", OP_NAME, ARRAY_FIELD);
    const std::string emptyMap = fmt::format("[{}] -> Failure: Result map is empty", OP_NAME);

    struct Row
    {
        const char* name;
        std::string text;
        std::string trace;
        bool normalizedKeysOnly;
    };

    // No element gives an insertion in either helper: not objects, no key, empty key, a key that normalizes to
    // nothing, a non-string key, no value (array_to_object) and no new value (array_to_object_changes)
    const std::string noValidElements =
        R"({"arr":[1,"s",null,[1],{},{"k":""},{"v":1,"n":1},{"k":5,"v":1,"n":1},{"k":"a"},{"k":"a","o":"old"}]})";
    // A key that normalizes to nothing is an insertion with raw_keys, so this one runs without it
    const std::string emptyAfterNormalizing = R"({"arr":[{"k":"!!","v":1,"n":1},{"k":"~","v":1,"n":1}]})";

    const std::vector<Row> rows = {
        {"reference not found", R"({"other":1})", refNotFound, false},
        {"reference is not an array", R"({"arr":5})", refNotFound, false},
        {"empty array", R"({"arr":[]})", emptyMap, false},
        {"no valid element", noValidElements, emptyMap, false},
        {"keys normalize to nothing", emptyAfterNormalizing, emptyMap, true},
    };

    for (const auto& row : rows)
    {
        for (const bool rawKeys : {false, true})
        {
            if (rawKeys && row.normalizedKeysOnly)
            {
                continue;
            }
            const auto toObject = compareAll(HelperKind::ToObject, toObjectArgs("v", rawKeys), row.text, row.name);
            EXPECT_TRUE(toObject.equal) << row.name;
            EXPECT_FALSE(toObject.success) << "array_to_object: " << row.name;
            EXPECT_EQ(toObject.trace, row.trace) << "array_to_object: " << row.name;

            const auto changes = compareAll(HelperKind::Changes, changesArgs("n", "o", rawKeys), row.text, row.name);
            EXPECT_TRUE(changes.equal) << row.name;
            EXPECT_FALSE(changes.success) << "array_to_object_changes: " << row.name;
            EXPECT_EQ(changes.trace, row.trace) << "array_to_object_changes: " << row.name;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A key that repeats keeps the position of its first insertion
// ---------------------------------------------------------------------------------------------------------------

TEST_F(ArrayToObjectDiff, RepeatedKeysKeepFirstPosition)
{
    constexpr std::size_t COUNT = 300;
    constexpr std::size_t SECOND = 199; // the 200th element
    constexpr std::size_t THIRD = 299;  // the 300th element
    constexpr std::string_view FIRST_MEMBER = R"({"key0":)";

    const auto keyOf = [](std::size_t i)
    {
        return (i == SECOND || i == THIRD) ? std::size_t {0} : i;
    };

    // array_to_object: the value of the 300th element wins
    {
        std::vector<std::string> elements;
        for (std::size_t i = 0; i < COUNT; ++i)
        {
            elements.push_back(fmt::format(R"({{"k":"key{}","v":{}}})", keyOf(i), i));
        }
        const auto out =
            compareAll(HelperKind::ToObject, toObjectArgs("v", false), eventText(elements), "array_to_object");
        ASSERT_TRUE(out.equal);
        ASSERT_TRUE(out.productive);
        EXPECT_EQ(out.doc.size(""), COUNT - 2);
        EXPECT_GT(out.doc.size(""), WIDE_THRESHOLD);
        const auto value = out.doc.getIntAsInt64("/key0");
        ASSERT_TRUE(value.has_value());
        EXPECT_EQ(*value, static_cast<std::int64_t>(THIRD));
        EXPECT_EQ(out.doc.str().compare(0, FIRST_MEMBER.size(), FIRST_MEMBER), 0) << out.doc.str().substr(0, 40);
    }

    // array_to_object_changes: the new value of the 300th element and the old value of the 200th (the 300th one
    // brings a blank old value)
    {
        std::vector<std::string> elements;
        for (std::size_t i = 0; i < COUNT; ++i)
        {
            std::string old = fmt::format(R"("o{}")", i);
            if (i == THIRD)
            {
                old = R"("  ")";
            }
            elements.push_back(fmt::format(R"({{"k":"key{}","n":{},"o":{}}})", keyOf(i), i, old));
        }
        const auto out = compareAll(
            HelperKind::Changes, changesArgs("n", "o", false), eventText(elements), "array_to_object_changes");
        ASSERT_TRUE(out.equal);
        ASSERT_TRUE(out.productive);
        EXPECT_EQ(out.doc.size(""), COUNT - 2);
        EXPECT_GT(out.doc.size(""), WIDE_THRESHOLD);
        const auto value = out.doc.getIntAsInt64("/key0/n");
        ASSERT_TRUE(value.has_value());
        EXPECT_EQ(*value, static_cast<std::int64_t>(THIRD));
        EXPECT_TRUE(out.doc.equalsString("/key0/o", fmt::format("o{}", SECOND)));
        EXPECT_EQ(out.doc.str().compare(0, FIRST_MEMBER.size(), FIRST_MEMBER), 0) << out.doc.str().substr(0, 40);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Copied elements wider than the writer threshold, with a member name repeated inside them
// ---------------------------------------------------------------------------------------------------------------

namespace
{
/// A JSON object text with 140 members named <prefix>0... followed by two members named x (the text keeps both)
std::string wideObjectWithRepeatedX(const std::string& prefix, const std::string& firstX, const std::string& secondX)
{
    std::string text = "{";
    for (std::size_t i = 0; i < 140; ++i)
    {
        text += fmt::format(R"("{}{}":{},)", prefix, i, i);
    }
    return text + R"("x":)" + firstX + R"(,"x":)" + secondX + "}";
}

/// Number of times @p needle occurs in @p text
std::size_t countOf(const std::string& text, const std::string& needle)
{
    std::size_t count = 0;
    for (auto pos = text.find(needle); pos != std::string::npos; pos = text.find(needle, pos + needle.size()))
    {
        ++count;
    }
    return count;
}

/// True when the serialized text has @p first before @p second
bool inOrder(const std::string& text, const std::string& first, const std::string& second)
{
    const auto a = text.find(first);
    const auto b = text.find(second);
    return a != std::string::npos && b != std::string::npos && a < b;
}
} // namespace

TEST_F(ArrayToObjectDiff, WideCopiedElements)
{
    // new = '.' (the whole element), old = 'x'. The element of key a is wide and has two members named x; key b
    // is another wide element; the last element repeats key a and overwrites the wide value with another one.
    {
        const auto elements = std::vector<std::string> {
            R"({"k":"a",)" + wideObjectWithRepeatedX("m", "7", R"("two")").substr(1),
            R"({"k":"b",)" + wideObjectWithRepeatedX("p", "5", R"("b2")").substr(1),
            R"({"k":"a",)" + wideObjectWithRepeatedX("q", "8", R"("three")").substr(1),
        };
        const auto out =
            compareAll(HelperKind::Changes, changesArgs(".", "x", false), eventText(elements), "new=. old=x");
        ASSERT_TRUE(out.equal);
        ASSERT_TRUE(out.productive);
        EXPECT_EQ(out.doc.size(""), 2u);
        EXPECT_GT(out.doc.size("/a"), WIDE_THRESHOLD);
        EXPECT_GT(out.doc.size("/b"), WIDE_THRESHOLD);
        const auto text = out.doc.str();
        // key a holds the last element: its first x is the written value (the old value read from the element),
        // the second x keeps its own; the overwritten element is gone
        EXPECT_TRUE(inOrder(text, R"("x":8)", R"("x":"three")")) << text.substr(0, 200);
        EXPECT_EQ(text.find(R"("x":"two")"), std::string::npos);
        EXPECT_TRUE(inOrder(text, R"("x":5)", R"("x":"b2")")) << text.substr(0, 200);
        EXPECT_EQ(countOf(text, R"("x":)"), 4u);
    }

    // new = 'v', old = 'v.x': v is the wide value with two members named x
    {
        const auto elements = std::vector<std::string> {
            R"({"k":"a","v":)" + wideObjectWithRepeatedX("m", "7", R"("two")") + "}",
            R"({"k":"b","v":)" + wideObjectWithRepeatedX("p", "5", R"("b2")") + "}",
            R"({"k":"a","v":)" + wideObjectWithRepeatedX("q", "8", R"("three")") + "}",
        };
        const auto out =
            compareAll(HelperKind::Changes, changesArgs("v", "v.x", false), eventText(elements), "new=v old=v.x");
        ASSERT_TRUE(out.equal);
        ASSERT_TRUE(out.productive);
        EXPECT_EQ(out.doc.size(""), 2u);
        EXPECT_GT(out.doc.size("/a/v"), WIDE_THRESHOLD);
        EXPECT_GT(out.doc.size("/b/v"), WIDE_THRESHOLD);
        const auto text = out.doc.str();
        EXPECT_TRUE(inOrder(text, R"("x":8)", R"("x":"three")")) << text.substr(0, 200);
        EXPECT_EQ(text.find(R"("x":"two")"), std::string::npos);
        EXPECT_TRUE(inOrder(text, R"("x":5)", R"("x":"b2")")) << text.substr(0, 200);
        EXPECT_EQ(countOf(text, R"("x":)"), 4u);
    }
}
