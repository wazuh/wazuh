// SPDX-License-Identifier: AGPL-3.0-or-later
#include "opBuilderHelperFilter.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <optional>
#include <type_traits>
#include <unordered_set>
#include <variant>

#include <re2/re2.h>

#include "syntax.hpp"
#include <base/baseTypes.hpp>
#include <base/utils/ipUtils.hpp>
#include <cmstore/categories.hpp>
#include <fastmetrics/registry.hpp>

namespace builder::builders::opfilter
{

//*************************************************
//*           Comparison filters                  *
//*************************************************

/**
 * @brief Operators supported by the comparison helpers.
 *
 */
enum class Operator
{
    EQ, ///< equal
    NE, ///< not equal
    GT, ///< greater than
    GE, ///< greater than equal
    LT, ///< less than
    LE, ///< less than equal
    ST, ///< start with
    CN  ///< contains
};

/**
 * @brief Type supported by the comparison helpers.
 *
 */
enum class Type
{
    STRING,
    NUMBER
};

/**
 * @brief Numeric operand of a comparison: an exact 64-bit integer (signed or unsigned) or a double.
 *
 * Integers that fit in int64_t are read as int64_t; only integers above INT64_MAX are read as uint64_t.
 */
using NumericValue = std::variant<int64_t, uint64_t, double>;

/**
 * @brief Reads the number at @p path of @p doc as a NumericValue.
 *
 * @param doc Document to read from
 * @param path JSON pointer path of the value, empty for the root
 * @return std::optional<NumericValue> The number, or std::nullopt if the value is missing or not a number
 */
std::optional<NumericValue> getNumericValue(const json::Json& doc, std::string_view path = "")
{
    if (const auto asInt = doc.getIntAsInt64(path); asInt.has_value())
    {
        return NumericValue {asInt.value()};
    }
    if (const auto asUint = doc.getUint64(path); asUint.has_value())
    {
        return NumericValue {asUint.value()};
    }
    if (const auto asDouble = doc.getNumberAsDouble(path); asDouble.has_value())
    {
        return NumericValue {asDouble.value()};
    }
    return std::nullopt;
}

/**
 * @brief Three-way comparison of two numeric operands.
 *
 * Two integers are compared exactly, whatever their width or sign; when either operand is a double both are
 * compared as doubles.
 *
 * @param l Left operand
 * @param r Right operand
 * @return std::optional<int> Negative when l < r, zero when l == r, positive when l > r; std::nullopt when the
 * operands are unordered (a NaN operand), which only `number_ne` accepts
 */
std::optional<int> compareNumericValues(const NumericValue& l, const NumericValue& r)
{
    return std::visit(
        [](const auto& lv, const auto& rv) -> std::optional<int>
        {
            using L = std::decay_t<decltype(lv)>;
            using R = std::decay_t<decltype(rv)>;
            if constexpr (std::is_floating_point_v<L> || std::is_floating_point_v<R>)
            {
                const auto ld = static_cast<double>(lv);
                const auto rd = static_cast<double>(rv);
                if (std::isnan(ld) || std::isnan(rd))
                {
                    return std::nullopt;
                }
                return (ld < rd) ? -1 : ((ld > rd) ? 1 : 0);
            }
            else if constexpr (std::is_same_v<L, int64_t> && std::is_same_v<R, uint64_t>)
            {
                if (lv < 0)
                {
                    return -1;
                }
                const auto lu = static_cast<uint64_t>(lv);
                return (lu < rv) ? -1 : ((lu > rv) ? 1 : 0);
            }
            else if constexpr (std::is_same_v<L, uint64_t> && std::is_same_v<R, int64_t>)
            {
                if (rv < 0)
                {
                    return 1;
                }
                const auto ru = static_cast<uint64_t>(rv);
                return (lv < ru) ? -1 : ((lv > ru) ? 1 : 0);
            }
            else
            {
                return (lv < rv) ? -1 : ((lv > rv) ? 1 : 0);
            }
        },
        l,
        r);
}

/**
 * @brief Get the Number Cmp Function object
 *
 * Two integers (signed or unsigned 64-bit) are compared exactly; when either operand is a floating-point number
 * both are compared as doubles.
 *
 * @param targetField Reference of the field to compare, obtained from the YAML key
 * @param op Operator to use
 * @param rightParameter Right parameter to compare, obtained from the YAML value
 * @param buildCtx Build context
 * @return FilterOp
 *
 * @throws std::runtime_error
 *   - if the right parameter is a value and not a number
 *   - if the right parameter is a reference to a schema field that is not a number
 */
FilterOp getNumberCmpFunction(const std::string& targetField,
                              Operator op,
                              const OpArg& rightParameter,
                              const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Depending on rValue type we store the reference or the numeric value
    std::variant<std::string, NumericValue> rValue {};

    if (rightParameter->isValue())
    {
        const auto value = std::static_pointer_cast<Value>(rightParameter)->value();
        const auto number = getNumericValue(value);
        if (!number.has_value())
        {
            throw std::runtime_error(fmt::format(R"(Expected a number but got '{}'.)", value.str()));
        }
        rValue = number.value();
    }
    else
    {
        auto ref = std::static_pointer_cast<Reference>(rightParameter);
        if (buildCtx->validator().hasField(ref->dotPath())
            && buildCtx->validator().getJsonType(ref->dotPath()) != json::Json::Type::Number)
        {
            throw std::runtime_error(
                fmt::format("Expected a reference of type '{}' but got reference '{}' of type '{}'",
                            json::Json::typeToStr(json::Json::Type::Number),
                            ref->dotPath(),
                            json::Json::typeToStr(buildCtx->validator().getJsonType(ref->dotPath()))));
        }
        rValue = std::static_pointer_cast<Reference>(rightParameter)->jsonPath();
    }

    // Depending on the operator we return the predicate over the three-way comparison result; unordered operands
    // (NaN) satisfy only the inequality, as in IEEE 754
    std::function<bool(std::optional<int> cmp)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](std::optional<int> cmp)
            {
                return cmp.has_value() && cmp.value() == 0;
            };
            break;
        case Operator::NE:
            cmpFunction = [](std::optional<int> cmp)
            {
                return !cmp.has_value() || cmp.value() != 0;
            };
            break;
        case Operator::GT:
            cmpFunction = [](std::optional<int> cmp)
            {
                return cmp.has_value() && cmp.value() > 0;
            };
            break;
        case Operator::GE:
            cmpFunction = [](std::optional<int> cmp)
            {
                return cmp.has_value() && cmp.value() >= 0;
            };
            break;
        case Operator::LT:
            cmpFunction = [](std::optional<int> cmp)
            {
                return cmp.has_value() && cmp.value() < 0;
            };
            break;
        case Operator::LE:
            cmpFunction = [](std::optional<int> cmp)
            {
                return cmp.has_value() && cmp.value() <= 0;
            };
            break;
        default: break;
    }

    // Tracing messages
    const auto name = buildCtx->context().opName;
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Comparison is false", name)};

    // Function that implements the helper
    return [=, isTestMode = buildCtx->isTestMode()](base::ConstEvent event) -> FilterResult
    {
        // The target must hold a number; a reference on the right side must resolve to a number too,
        // otherwise the value parsed at build time is used

        const auto lValue = getNumericValue(*event, targetField);
        if (!lValue.has_value())
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        NumericValue resolvedValue {};
        if (std::holds_alternative<std::string>(rValue))
        {
            const auto resolvedRValue = getNumericValue(*event, std::get<std::string>(rValue));
            if (!resolvedRValue.has_value())
            {
                RETURN_FAILURE(isTestMode, false, failureTrace2);
            }
            resolvedValue = resolvedRValue.value();
        }
        else
        {
            resolvedValue = std::get<NumericValue>(rValue);
        }

        if (cmpFunction(compareNumericValues(lValue.value(), resolvedValue)))
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(isTestMode, false, failureTrace3);
        }
    };
}

/**
 * @brief Get the String Cmp Function object
 *
 * @param targetField Reference of the field to compare, obtained from the YAML key
 * @param op Operator to use
 * @param rightParameter Right parameter to compare, obtained from the YAML value
 * @param name Formatted name of the helper
 * @return std::function<FilterResult(base::Event)>
 *
 * @throws std::runtime_error if helper::base::Parameter::Type is not supported
 */
FilterOp getStringCmpFunction(const std::string& targetField,
                              Operator op,
                              const OpArg& rightParameter,
                              const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Depending on the operator we return the correct function
    std::function<bool(std::string_view l, std::string_view r)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l == r;
            };
            break;
        case Operator::NE:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l != r;
            };
            break;
        case Operator::GT:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l > r;
            };
            break;
        case Operator::GE:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l >= r;
            };
            break;
        case Operator::LT:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l < r;
            };
            break;
        case Operator::LE:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l <= r;
            };
            break;
        case Operator::ST:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                return l.substr(0, r.length()) == r;
            };
            break;
        case Operator::CN:
            cmpFunction = [](std::string_view l, std::string_view r)
            {
                if (!r.empty())
                {
                    return l.find(r) != std::string_view::npos;
                }
                return false;
            };
            break;

        default: break;
    }

    const auto name = buildCtx->context().opName;
    // Pre-extract value string to avoid lazy json::Json creation per-event
    std::optional<std::string> preExtractedValueStr;
    if (rightParameter->isValue())
    {
        auto asValue = std::static_pointer_cast<const Value>(rightParameter);
        std::string_view sv;
        if (asValue->getString(sv) != json::RetGet::Success)
        {
            throw std::runtime_error(
                fmt::format(R"({} function: Expected a string but got {}.)", name, rightParameter->str()));
        }
        if ((op == Operator::ST || op == Operator::CN) && sv.empty())
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected a non-empty string but got an empty one", name));
        }
        preExtractedValueStr = std::string(sv);
    }
    else
    {
        auto ref = std::static_pointer_cast<Reference>(rightParameter);
        if (buildCtx->validator().hasField(ref->dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(ref->dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(
                    fmt::format("{} function: Expected a reference of type '{}' but got reference '{}' of type '{}'",
                                name,
                                json::Json::typeToStr(json::Json::Type::String),
                                ref->dotPath(),
                                json::Json::typeToStr(jType)));
            }
        }
    }

    // Tracing messages
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Comparison is false", name)};

    // Pre-build PointerPath objects to avoid re-parsing on every event
    const json::PointerPath targetFieldPP(targetField);
    const auto rightParamPP =
        rightParameter->isReference()
            ? std::make_optional<json::PointerPath>(std::static_pointer_cast<Reference>(rightParameter)->jsonPath())
            : std::nullopt;

    // Function that implements the helper
    return [=, isTestMode = buildCtx->isTestMode()](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        std::string_view lValue;
        if (event->getString(lValue, targetFieldPP) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        std::string_view rValue {};
        if (preExtractedValueStr.has_value())
        {
            rValue = *preExtractedValueStr;
        }
        else
        {
            if (event->getString(rValue, *rightParamPP) != json::RetGet::Success)
            {
                RETURN_FAILURE(isTestMode, false, failureTrace2);
            }
        }

        if (cmpFunction(lValue, rValue))
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(isTestMode, false, failureTrace3);
        }
    };
}

/**
 * @brief Builds the Expression for the comparison helper
 *
 * @param definition Helper definition
 * @param op Comparison operator
 * @param type Type of the comparison
 * @return base::Expression
 */
FilterOp opBuilderComparison(const std::string& targetField,
                             const std::vector<OpArg>& parameters,
                             Operator op,
                             Type t,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(parameters, 1);

    // Get the expression depending on the type
    switch (t)
    {
        case Type::STRING:
        {
            auto opFn = getStringCmpFunction(targetField, op, parameters[0], buildCtx);
            return opFn;
        }
        case Type::NUMBER:
        {
            auto opFn = getNumberCmpFunction(targetField, op, parameters[0], buildCtx);
            return opFn;
        }
        default:
            throw std::runtime_error(fmt::format("Comparison helper: Type '{}' not supported", static_cast<int>(t)));
    }
}

//*************************************************
//*              Number Cmp filters               *
//*************************************************

// field: +number_eq/number|$ref/
FilterOp opBuilderHelperNumberEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::EQ, Type::NUMBER, buildCtx);
    return op;
}

// field: +number_ne/number|$ref/
FilterOp opBuilderHelperNumberNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::NE, Type::NUMBER, buildCtx);
    return op;
}

// field: +number_lt/number|$ref/
FilterOp opBuilderHelperNumberLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LT, Type::NUMBER, buildCtx);
    return op;
}

// field: +number_lte/number|$ref/
FilterOp opBuilderHelperNumberLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LE, Type::NUMBER, buildCtx);
    return op;
}

// field: +number_gt/number|$ref/
FilterOp opBuilderHelperNumberGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GT, Type::NUMBER, buildCtx);
    return op;
}

// field: +number_gte/number|$ref/
FilterOp opBuilderHelperNumberGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GE, Type::NUMBER, buildCtx);
    return op;
}

//*************************************************
//*           String Cmp filters                  *
//*************************************************

// field: +string_eq/value|$ref
FilterOp opBuilderHelperStringEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::EQ, Type::STRING, buildCtx);
    return op;
}

// field: +string_ne/value|$ref
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::NE, Type::STRING, buildCtx);
    return op;
}

// field: +string_gt/value|$ref
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GT, Type::STRING, buildCtx);
    return op;
}

// field: +string_gte/value|$ref
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GE, Type::STRING, buildCtx);
    return op;
}

// field: +string_lt/value|$ref
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LT, Type::STRING, buildCtx);
    return op;
}

// field: +string_lte/value|$ref
FilterOp opBuilderHelperStringLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LE, Type::STRING, buildCtx);
    return op;
}

// field: +starts_with/value|$ref
FilterOp opBuilderHelperStringStarts(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::ST, Type::STRING, buildCtx);
    return op;
}

// field: +contains/value|$ref
FilterOp opBuilderHelperStringContains(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::CN, Type::STRING, buildCtx);
    return op;
}

// field: has_any_bit(mask)
FilterOp opBuilderHelperBinaryAnd(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    const auto& name = buildCtx->context().opName;

    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);
    // Parameter type check
    utils::assertValue(opArgs, 0);

    // Parse a hexadecimal string, with or without the '0x' prefix and in any case, into an unsigned 64-bit integer
    const auto parseHex = [](std::string_view str) -> std::optional<uint64_t>
    {
        if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        {
            str.remove_prefix(2);
        }

        // At most 16 hexadecimal digits fit in 64 bits
        if (str.empty() || str.size() > static_cast<size_t>(std::numeric_limits<uint64_t>::digits / 4))
        {
            return std::nullopt;
        }

        uint64_t result {0};
        const auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result, 16);
        if (ec != std::errc() || ptr != str.data() + str.size())
        {
            return std::nullopt;
        }

        return result;
    };

    // Mask: a hexadecimal string or a non-negative integer
    std::optional<uint64_t> maskOpt;
    {
        const auto maskValue = std::static_pointer_cast<Value>(opArgs[0])->value();
        std::string maskStr;
        if (maskValue.getString(maskStr) == json::RetGet::Success)
        {
            maskOpt = parseHex(maskStr);
        }
        else if (const auto maskInt = maskValue.getUint64(); maskInt.has_value())
        {
            maskOpt = maskInt.value();
        }
    }

    if (!maskOpt.has_value())
    {
        throw std::runtime_error(fmt::format(
            "{} function: Mask '{}' is not a valid hexadecimal string or non-negative integer (up to 64 bits)",
            name,
            opArgs[0]->str()));
    }

    const uint64_t mask = maskOpt.value();
    if (mask == 0)
    {
        throw std::runtime_error(fmt::format("{} function: Mask cannot be 0", name));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};
    const auto referenceNotFoundTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const auto referenceNotValidHexTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not a hexadecimal string or a non-negative integer",
                    name,
                    targetField.dotPath())};
    const auto failAndTrace {fmt::format("[{}] -> Failure: No bit of the mask is set", name)};

    // The filter
    return [parseHex,
            mask,
            successTrace,
            referenceNotFoundTrace,
            referenceNotValidHexTrace,
            failAndTrace,
            isTestMode = buildCtx->isTestMode(),
            targetPath = targetField.jsonPath(),
            targetPP = json::PointerPath(targetField.jsonPath())](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetPath))
        {
            RETURN_FAILURE(isTestMode, false, referenceNotFoundTrace);
        }

        std::optional<uint64_t> value;
        std::string_view str;
        if (event->getString(str, targetPP) == json::RetGet::Success)
        {
            value = parseHex(str);
        }
        else if (const auto number = event->getUint64(targetPath); number.has_value())
        {
            value = number.value();
        }

        if (!value.has_value())
        {
            RETURN_FAILURE(isTestMode, false, referenceNotValidHexTrace);
        }

        if (value.value() & mask)
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        RETURN_FAILURE(isTestMode, false, failAndTrace);
    };
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +regex_match/regexp
FilterOp opBuilderHelperRegexMatch(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);
    // Parameter type check
    utils::assertValue(opArgs, 0);

    const auto& name = buildCtx->context().opName;

    std::string value;
    if (std::static_pointer_cast<Value>(opArgs[0])->value().getString(value) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("{} function: Regex pattern expected a string but got {}", name, opArgs[0]->str()));
    }

    auto regex_ptr {std::make_shared<RE2>(value, RE2::Quiet)};
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("Invalid regex: \"{}\".", value));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Regex did not match", name)};

    // Return Op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = json::PointerPath(targetField.jsonPath())](
               base::ConstEvent event) -> FilterResult
    {
        std::string_view resolvedField;
        if (event->getString(resolvedField, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        if (RE2::PartialMatch(resolvedField, *regex_ptr))
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }
    };
}

// field: +regex_not_match/regexp
FilterOp opBuilderHelperRegexNotMatch(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // TODO: Regex parameter fails at operationBuilderSplit

    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);
    // Parameter type check
    utils::assertValue(opArgs, 0);
    // Format name for the tracer
    const auto name = buildCtx->context().opName;
    std::string value;
    if (std::static_pointer_cast<Value>(opArgs[0])->value().getString(value) != json::RetGet::Success)
    {
        throw std::runtime_error(
            fmt::format("{} function: Regex pattern expected a string but got {}", name, opArgs[0]->str()));
    }

    auto regex_ptr {std::make_shared<RE2>(value, RE2::Quiet)};
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("\"{}\" function: "
                                             "Invalid regex: \"{}\".",
                                             name,
                                             value));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Regex did match", name)};

    // Return Op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = json::PointerPath(targetField.jsonPath())](
               base::ConstEvent event) -> FilterResult
    {
        std::string_view resolvedField;
        if (event->getString(resolvedField, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        if (!RE2::PartialMatch(resolvedField, *regex_ptr))
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }
    };
}

// //*************************************************
// //*               IP filters                     *
// //*************************************************

// field: in_cidr('192.168.0.0/16', ...)
FilterOp opBuilderHelperIPCIDR(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters: one or more networks
    utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
    // Parameter type check
    utils::assertValue(opArgs);
    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Every network is a literal 'a.b.c.d/nn' or 'a.b.c.d/m.m.m.m', kept as its network address and mask (a mask need
    // not be contiguous)
    std::vector<std::pair<uint32_t, uint32_t>> networks;
    networks.reserve(opArgs.size());
    for (size_t i = 0; i < opArgs.size(); ++i)
    {
        std::string cidrStr;
        if (std::static_pointer_cast<Value>(opArgs[i])->value().getString(cidrStr) != json::RetGet::Success)
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected a CIDR string ('a.b.c.d/nn') as parameter {} but got {}",
                            name,
                            i + 1,
                            opArgs[i]->str()));
        }

        const auto slash = cidrStr.find('/');
        if (slash == std::string::npos || slash == 0 || slash + 1 == cidrStr.size())
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected a CIDR string ('a.b.c.d/nn') as parameter {} but got '{}'",
                            name,
                            i + 1,
                            cidrStr));
        }

        uint32_t network {};
        uint32_t mask {};
        try
        {
            network = ::utils::ip::IPv4ToUInt(cidrStr.substr(0, slash));
            mask = ::utils::ip::IPv4MaskUInt(cidrStr.substr(slash + 1));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("{} function: '{}' is not a valid IPv4 network: {}", name, cidrStr, e.what()));
        }

        networks.emplace_back(network & mask, mask);
    }

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: IPv4 address ", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: IP address is not in any of the networks", name)};

    // Return Op
    return [networks,
            successTrace,
            failureTrace1,
            failureTrace2,
            failureTrace3,
            isTestMode = buildCtx->isTestMode(),
            targetField = json::PointerPath(targetField.jsonPath())](base::ConstEvent event) -> FilterResult
    {
        std::string resolvedField;
        if (event->getString(resolvedField, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        uint32_t ip {};
        try
        {
            ip = ::utils::ip::IPv4ToUInt(resolvedField); // IPv4ToUInt requires std::string
        }
        catch (const std::exception& e)
        {
            RETURN_FAILURE(isTestMode,
                           false,
                           failureTrace2
                               + fmt::format("'{}' could not be converted to int: {}", resolvedField, e.what()));
        }

        for (const auto& [network, mask] : networks)
        {
            if ((ip & mask) == network)
            {
                RETURN_SUCCESS(isTestMode, true, successTrace);
            }
        }

        RETURN_FAILURE(isTestMode, false, failureTrace3);
    };
}

FilterOp opBuilderHelperPublicIP(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("{} -> Success", name)};
    const std::string failureTrace1 {
        fmt::format("{} -> Failure: Target field '{}' not found or not a string", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("{} -> Failure: IP address is not public", name)};
    const std::string failureTrace3 {fmt::format("{} -> Failure: Not a valid IP address", name)};

    auto checkFn = [](const std::string& ip) -> base::RespOrError<bool>
    {
        using namespace ::utils::ip;
        if (checkStrIsIPv4(ip))
        {
            return !isSpecialIPv4Address(ip);
        }

        if (checkStrIsIPv6(ip))
        {
            return !isSpecialIPv6Address(ip);
        }
        return base::Error {};
    };

    // Return Op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = json::PointerPath(targetField.jsonPath())](
               base::ConstEvent event) -> FilterResult
    {
        std::string resolvedField;
        if (event->getString(resolvedField, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        // checkFn requires std::string
        auto checkResult = checkFn(resolvedField);
        if (base::isError(checkResult))
        {
            RETURN_FAILURE(isTestMode, false, failureTrace3);
        }

        if (base::getResponse(checkResult))
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        RETURN_FAILURE(isTestMode, false, failureTrace2);
    };
}

//*************************************************
//*               Array filters                   *
//*************************************************
FilterOp opBuilderHelperArrayPresence(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      bool atleastOne,
                                      bool presenceCheck,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);

    auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not an array", name, targetField.dotPath())};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Target array '{}' {} of the parameters",
                    name,
                    targetField.dotPath(),
                    presenceCheck ? "does not contain at least one" : "contains at least one")};

    // Pre-resolve parameters at build time
    struct CmpParam
    {
        std::string refPath;                     ///< Set when the parameter is a reference.
        std::shared_ptr<const json::Json> value; ///< Set when the parameter is a literal value.
    };
    std::vector<CmpParam> cmpParams;
    cmpParams.reserve(opArgs.size());
    for (const auto& parameter : opArgs)
    {
        if (parameter->isReference())
        {
            cmpParams.push_back({std::static_pointer_cast<Reference>(parameter)->jsonPath(), nullptr});
        }
        else
        {
            cmpParams.push_back({{}, std::static_pointer_cast<Value>(parameter)->sharedValue()});
        }
    }

    // Return Op
    return [=,
            cmpParams = std::move(cmpParams),
            isTestMode = buildCtx->isTestMode(),
            targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        const auto resolvedArray {event->getArray(targetField)};
        if (!resolvedArray.has_value())
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }

        std::size_t matchCount {0};
        for (const auto& param : cmpParams)
        {
            // Comparison value: the shared literal, or a per-event snapshot of the reference.
            const json::Json* cmp = param.value.get();
            std::optional<json::Json> refValue;
            if (cmp == nullptr)
            {
                refValue = event->getJson(param.refPath);
                if (!refValue.has_value())
                {
                    continue;
                }
                cmp = &*refValue;
            }

            // Check if the array contains the value
            bool found = std::find_if(resolvedArray.value().begin(),
                                      resolvedArray.value().end(),
                                      [cmp](const json::Json& value) { return value == *cmp; })
                         != resolvedArray.value().end();

            if (presenceCheck == found)
            {
                if (atleastOne)
                {
                    RETURN_SUCCESS(isTestMode, true, successTrace);
                }

                matchCount++;
                if (matchCount == cmpParams.size())
                {
                    RETURN_SUCCESS(isTestMode, true, successTrace);
                }
            }
        }

        RETURN_FAILURE(isTestMode, false, failureTrace3);
    };
}

// field: +array_contains_all/value1/value2/...valueN
FilterOp opBuilderHelperContains(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, false, true, buildCtx);
}

FilterOp opBuilderHelperContainsAny(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, true, true, buildCtx);
}

// field: +array_contains_none/value1/value2/...valueN
FilterOp opBuilderHelperNotContainsAny(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, false, false, buildCtx);
}

//*************************************************
//*                Type filters                   *
//*************************************************

FilterOp typeMatcher(const Reference& targetField,
                     const std::vector<OpArg>& opArgs,
                     const std::shared_ptr<const IBuildCtx>& buildCtx,
                     json::Json::Type type,
                     bool negated = false)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace = negated ? fmt::format("[{}] -> Failure: Target field '{}' is a {}",
                                                    name,
                                                    targetField.dotPath(),
                                                    json::Json::typeToStr(type))
                                      : fmt::format("[{}] -> Failure: Target field '{}' is not a {}",
                                                    name,
                                                    targetField.dotPath(),
                                                    json::Json::typeToStr(type));
    const auto failureMissingValueTrace =
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath());

    // Return Op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if ((event->type(targetField) == type) != negated)
            {
                RETURN_SUCCESS(isTestMode, true, successTrace);
            }

            RETURN_FAILURE(isTestMode, false, failureTrace);
        }

        RETURN_FAILURE(isTestMode, false, failureMissingValueTrace);
    };
}

// field: +is_number
FilterOp opBuilderHelperIsNumber(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Number);
}

// field: +is_not_number
FilterOp opBuilderHelperIsNotNumber(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Number, true);
}

// field: +is_string
FilterOp opBuilderHelperIsString(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::String);
}

// field: +is_not_string
FilterOp opBuilderHelperIsNotString(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::String, true);
}

// field: +is_boolean
FilterOp opBuilderHelperIsBool(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Boolean);
}

// field: +is_not_boolean
FilterOp opBuilderHelperIsNotBool(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Boolean, true);
}

// field: +is_array
FilterOp opBuilderHelperIsArray(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Array);
}

// field: +is_not_array
FilterOp opBuilderHelperIsNotArray(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Array, true);
}

// field: +is_object
FilterOp opBuilderHelperIsObject(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Object);
}

// field: +is_not_object
FilterOp opBuilderHelperIsNotObject(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Object, true);
}

// field: +is_null
FilterOp opBuilderHelperIsNull(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Null);
}

// field: +is_not_null
FilterOp opBuilderHelperIsNotNull(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return typeMatcher(targetField, opArgs, buildCtx, json::Json::Type::Null, true);
}

//*************************************************
//*              Definition filters               *
//*************************************************

// <field>: +one_of/$<definition_array>|$<array_reference>
FilterOp opBuilderHelperMatchValue(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isArray())
        {
            throw std::runtime_error(fmt::format("Expected 'array' type for parameter 1, got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
        }
    }

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' has an invalid type", name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Reference is not an array", name)};
    const std::string failureTrace5 {fmt::format("[{}] -> Failure", name)};

    // Return op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = targetField.jsonPath(), parameter = opArgs[0]](
               base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        // Get value
        json::Json cmpValue {};
        {
            auto resolvedField {event->getJson(targetField)};
            if (resolvedField.has_value())
            {
                cmpValue = std::move(resolvedField.value());
            }
            else
            {
                RETURN_FAILURE(isTestMode, false, failureTrace2);
            }
        }

        bool isSuccess {false};
        // TODO Should be a function in json::Json for search in array
        auto searchCmpValue = [&cmpValue](const std::vector<json::Json>& def) -> bool
        {
            return std::find_if(
                       def.begin(), def.end(), [&cmpValue](const json::Json& value) { return value == cmpValue; })
                   != def.end();
        };

        // Get array
        if (parameter->isReference())
        {
            // TODO Should be 1 trace, if exist and is array, in all helers, no shearch for existance twice
            // Parameter is a reference
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            if (!event->exists(refPath))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace3);
            }

            if (!event->isArray(refPath))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace4);
            }

            isSuccess = searchCmpValue(event->getArray(refPath).value());
        }
        else
        {
            // Parameter is a value
            auto value = std::static_pointer_cast<Value>(parameter)->value().getArray().value();
            isSuccess = searchCmpValue(value);
        }

        // Check if the array contains the value
        if (isSuccess)
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }

        // Not found
        RETURN_FAILURE(isTestMode, false, failureTrace5);
    };
}

// <field>: is_key_of($<definition_object>|$<object_reference>)
FilterOp opBuilderHelperMatchKey(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isObject())
        {
            throw std::runtime_error(fmt::format("Expected 'object' type for parameter 1, got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
        }
    }
    else
    {
        auto ref = std::static_pointer_cast<Reference>(opArgs[0]);
        if (buildCtx->validator().hasField(ref->dotPath()))
        {
            if (buildCtx->validator().getType(ref->dotPath()) != schemf::Type::OBJECT)
            {
                throw std::runtime_error(
                    fmt::format("Expected a reference of an object but got reference '{}' which is of type '{}",
                                ref->dotPath(),
                                schemf::typeToStr(buildCtx->validator().getType(ref->dotPath()))));
            }
        }
    }

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not a string", name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: Reference has an invalid type", name)}; // TODO: ???
    const std::string failureTrace5 {fmt::format("[{}] -> Failure: Reference is not an object", name)};

    const std::string failureTrace6 {
        fmt::format("[{}] -> Failure: Object does not contain '{}'", name, targetField.dotPath())};

    // Share the Value's compact document once at build time instead of materializing a per event.
    const std::shared_ptr<const json::Json> defObject =
        opArgs[0]->isValue() ? std::static_pointer_cast<Value>(opArgs[0])->sharedValue() : nullptr;

    // Return op
    return [=,
            isTestMode = buildCtx->isTestMode(),
            targetField = targetField.jsonPath(),
            targetFieldPP = json::PointerPath(targetField.jsonPath()),
            parameter = opArgs[0]](base::ConstEvent event) -> FilterResult
    {
        std::string_view targetStr;
        if (auto ret = event->getString(targetStr, targetFieldPP); ret != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, ret == json::RetGet::WrongType ? failureTrace2 : failureTrace1);
        }

        // The key is matched literally: a dot in the value is part of the key, not a path separator
        auto pointerPath = json::Json::formatJsonPath(targetStr, true);
        bool exists {false};

        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            if (!event->exists(refPath))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace3);
            }

            if (!event->isObject(refPath))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace5);
            }

            exists = event->exists(refPath + pointerPath);
        }
        else
        {
            // Parameter is a definition
            exists = defObject->exists(pointerPath);
        }

        // Check if object contains the key
        if (!exists)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace6);
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
    };
}

// <field>: +end_with/$<definition_object>|$<object_reference>
FilterOp opBuilderHelperEndsWith(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    const auto name = buildCtx->context().opName;
    if (opArgs[0]->isValue())
    {
        std::string value;
        if (std::static_pointer_cast<Value>(opArgs[0])->value().getString(value) != json::RetGet::Success)
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected string value for parameter 1 but got '{}'", name, opArgs[0]->str()));
        }
        if (value.empty())
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected a non-empty string but got an empty one", name));
        }
    }
    else
    {
        auto ref = std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& validator = buildCtx->validator();
        if (validator.hasField(ref->dotPath()))
        {
            if (validator.getType(ref->dotPath()) != schemf::Type::KEYWORD
                && validator.getType(ref->dotPath()) != schemf::Type::TEXT)
            {
                throw std::runtime_error(fmt::format("Reference '{}' is of type '{}' but expected 'keyword' or 'text'",
                                                     ref->dotPath(),
                                                     schemf::typeToStr(validator.getType(ref->dotPath()))));
            }
        }
    }

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found or is not a string", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not a string", name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Reference not found or is not a string", name)};

    const std::string failureTrace4 {
        fmt::format("[{}] -> Failure: String does not end with '{}'", name, targetField.dotPath())};

    // Return op
    return [failureTrace1,
            failureTrace2,
            failureTrace3,
            failureTrace4,
            successTrace,
            isTestMode = buildCtx->isTestMode(),
            targetField = json::PointerPath(targetField.jsonPath()),
            parameter = opArgs[0]](base::ConstEvent event) -> FilterResult
    {
        std::string_view targetString;
        if (event->getString(targetString, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            std::string_view stringReference;
            if (event->getString(stringReference, refPath) != json::RetGet::Success)
            {
                RETURN_FAILURE(isTestMode, false, failureTrace1);
            }

            if (!base::utils::string::endsWith(targetString, stringReference))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace4);
            }

            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
        else
        {
            std::string_view valueString;
            if (std::static_pointer_cast<Value>(parameter)->getString(valueString) != json::RetGet::Success)
            {
                RETURN_FAILURE(isTestMode, false, failureTrace3);
            }
            if (!base::utils::string::endsWith(targetString, valueString))
            {
                RETURN_FAILURE(isTestMode, false, failureTrace4);
            }

            RETURN_SUCCESS(isTestMode, true, successTrace);
        }
    };
}

// <field>: +is_ipv4/
FilterOp opBuilderHelperIsIpv4(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found or is not a string", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("{} -> Failure: IP address is not IPv4", name)};

    // Return op
    return [failureTrace1,
            failureTrace2,
            successTrace,
            isTestMode = buildCtx->isTestMode(),
            targetField = json::PointerPath(targetField.jsonPath())](base::ConstEvent event) -> FilterResult
    {
        std::string targetString;
        if (event->getString(targetString, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        if (!::utils::ip::checkStrIsIPv4(targetString)) // checkStrIsIPv4 requires std::string
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
    };
}

// <field>: +is_ipv6/
FilterOp opBuilderHelperIsIpv6(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found or is not a string", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("{} -> Failure: IP address is not IPv6", name)};

    // Return op
    return [failureTrace1,
            failureTrace2,
            successTrace,
            isTestMode = buildCtx->isTestMode(),
            targetField = json::PointerPath(targetField.jsonPath())](base::ConstEvent event) -> FilterResult
    {
        std::string targetString;
        if (event->getString(targetString, targetField) != json::RetGet::Success)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        if (!::utils::ip::checkStrIsIPv6(targetString)) // checkStrIsIPv6 requires std::string
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
    };
}

// <field>: +has_only_keys/$<list_value>|$<list_reference>
FilterOp opBuilderHelperKeysExistInList(const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    utils::assertSize(opArgs, 1);
    const auto name = buildCtx->context().opName;

    std::unordered_set<std::string> expectedKeys {};
    if (opArgs[0]->isValue())
    {
        auto list = std::static_pointer_cast<Value>(opArgs[0])->value().getArray();
        if (!list.has_value())
        {
            throw std::runtime_error(fmt::format("Expected 'array' value but got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
        }

        for (const auto& element : list.value())
        {
            std::string elemStr;
            if (element.getString(elemStr) != json::RetGet::Success)
            {
                throw std::runtime_error(
                    fmt::format("{} function: expected a string array but found {}", name, element.str()));
            }

            expectedKeys.insert(std::move(elemStr));
        }
    }
    else
    {
        const auto arrayRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& validator = buildCtx->validator();

        if (validator.hasField(arrayRef.dotPath()))
        {
            auto jType = validator.getJsonType(arrayRef.dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(
                    fmt::format("Expected array of 'string' but got array of '{}'", json::Json::typeToStr(jType)));
            }
        }
    }

    const std::string successTrace = fmt::format("[{}] -> Success", name);
    const std::string failureTrace1 = fmt::format(
        "[{}] -> Failure: Target field '{}' not found or is not a json object", name, targetField.dotPath());
    const std::string failureTrace2 = fmt::format("[{}] -> Failure: Reference not found or is not an array", name);
    const std::string failureTrace3 = fmt::format("[{}] -> Failure: Element in array is not a string", name);
    const std::string failureTrace4 =
        fmt::format("[{}] -> Failure: There are keys in the target field that are missing from the list", name);

    return [failureTrace1,
            failureTrace2,
            failureTrace3,
            failureTrace4,
            successTrace,
            isTestMode = buildCtx->isTestMode(),
            targetField = targetField.jsonPath(),
            parameter = opArgs[0],
            expectedKeys](base::ConstEvent event) -> FilterResult
    {
        const auto objectFields = event->getFields(targetField);
        if (!objectFields.has_value())
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        std::unordered_set<std::string> localKeys = expectedKeys;
        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto list = event->getArray(refPath);
            if (!list.has_value())
            {
                RETURN_FAILURE(isTestMode, false, failureTrace2);
            }
            for (const auto& element : list.value())
            {
                std::string elemStr;
                if (element.getString(elemStr) != json::RetGet::Success)
                {
                    RETURN_FAILURE(isTestMode, false, failureTrace3);
                }

                localKeys.insert(std::move(elemStr));
            }
        }

        if (localKeys.size() < objectFields->size())
        {
            RETURN_FAILURE(isTestMode, false, failureTrace4);
        }

        for (const auto& key : objectFields.value())
        {
            if (localKeys.erase(key) == 0)
            {
                RETURN_FAILURE(isTestMode, false, failureTrace4);
            }
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
    };
}

// field: +array_length/expectedLength
FilterOp opBuilderHelperArrayLength(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);
    // Parameter type check
    utils::assertValue(opArgs, 0);

    auto name = buildCtx->context().opName;

    // Get expected length
    int64_t expectedLength {};
    try
    {
        expectedLength = std::static_pointer_cast<Value>(opArgs[0])->value().getInt64().value();
        if (expectedLength < 0)
        {
            throw std::runtime_error(
                fmt::format("{} function: Expected length '{}' cannot be negative", name, expectedLength));
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("{} function: Expected length parameter is not a valid integer: {}", name, e.what()));
    }

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success: Array has length {}", name, expectedLength)};
    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not an array", name, targetField.dotPath())};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Array length does not match expected length {}", name, expectedLength)};

    // Return Op
    return [=, isTestMode = buildCtx->isTestMode(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }

        const auto resolvedArray {event->getArray(targetField)};
        if (!resolvedArray.has_value())
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }

        if (static_cast<int64_t>(resolvedArray.value().size()) == expectedLength)
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }

        RETURN_FAILURE(isTestMode, false, failureTrace3);
    };
}

// field: +index_unclassified_events
FilterOp opBuilderHelperIndexUnclassifiedEvents(const Reference& targetField,
                                                const std::vector<OpArg>& opArgs,
                                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (targetField.jsonPath() != syntax::asset::CATEGORY_PATH)
    {
        throw std::runtime_error(
            fmt::format("index_unclassified_events: target field must be 'wazuh.integration.category', got '{}'",
                        targetField.dotPath()));
    }

    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);

    auto name = buildCtx->context().opName;
    const bool policyIndexUnclassified = buildCtx->context().indexUnclassifiedEvents;

    // Tracing
    const std::string successTrace {
        fmt::format("[{}] -> Success: Policy index_unclassified_events=true and category is 'unclassified'", name)};
    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not a string", name, targetField.dotPath())};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Policy index_unclassified_events=false or category is not 'unclassified'", name)};

    return [=, isTestMode = buildCtx->isTestMode(), targetFieldPP = json::PointerPath(targetField.jsonPath())](
               base::ConstEvent event) -> FilterResult
    {
        // Check if policy flag is enabled
        if (!policyIndexUnclassified)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace3);
        }

        std::string_view category;
        const auto ret = event->getString(category, targetFieldPP);
        if (ret == json::RetGet::NotFound)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace1);
        }
        if (ret == json::RetGet::WrongType)
        {
            RETURN_FAILURE(isTestMode, false, failureTrace2);
        }

        if (category == cm::store::categories::UNCLASSIFIED_CATEGORY)
        {
            RETURN_SUCCESS(isTestMode, true, successTrace);
        }

        RETURN_FAILURE(isTestMode, false, failureTrace3);
    };
}

} // namespace builder::builders::opfilter
