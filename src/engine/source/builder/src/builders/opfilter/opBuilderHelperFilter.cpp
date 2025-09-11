#include "opBuilderHelperFilter.hpp"

#include <algorithm>
#include <optional>
#include <unordered_set>
#include <variant>

#include <re2/re2.h>

#include "syntax.hpp"
#include <base/baseTypes.hpp>
#include <base/utils/ipUtils.hpp>

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
    NUMBER,
    INT
};

/**
 * @brief Get the Int Cmp Function object
 *
 * @param targetField Reference of the field to compare, obtained from the YAML key
 * @param op Operator to use
 * @param rightParameter Right parameter to compare, obtained from the YAML value
 * @return std::function<FilterResult(base::Event)>
 *
 * @throws std::runtime_error
 *   - if the right parameter is a value and not a valid integer
 *   - if helper::base::Parameter::Type is not supported
 */
FilterOp getIntCmpFunction(const std::string& targetField,
                           Operator op,
                           const OpArg& rightParameter,
                           const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Depending on rValue type we store the reference or the integer value
    std::variant<std::string, int64_t> rValue {};

    if (rightParameter->isValue())
    {
        try
        {
            rValue = std::static_pointer_cast<Value>(rightParameter)->value().getInt64().value();
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format(R"(Expected an integer but got '{}'.)",
                                                 std::static_pointer_cast<Value>(rightParameter)->value().str()));
        }
    }
    else
    {
        auto ref = std::static_pointer_cast<Reference>(rightParameter);
        if (buildCtx->validator().hasField(ref->dotPath())
            && buildCtx->validator().getType(ref->dotPath()) != schemf::Type::INTEGER)
        {
            throw std::runtime_error(
                fmt::format("Expected a reference of type '{}' but got reference '{}' of type '{}'",
                            schemf::typeToStr(schemf::Type::INTEGER),
                            ref->dotPath(),
                            schemf::typeToStr(buildCtx->validator().getType(ref->dotPath()))));
        }
        rValue = std::static_pointer_cast<Reference>(rightParameter)->jsonPath();
    }

    // Depending on the operator we return the correct function
    std::function<bool(int64_t l, int64_t r)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l == r;
            };
            break;
        case Operator::NE:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l != r;
            };
            break;
        case Operator::GT:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l > r;
            };
            break;
        case Operator::GE:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l >= r;
            };
            break;
        case Operator::LT:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l < r;
            };
            break;
        case Operator::LE:
            cmpFunction = [](int64_t l, int64_t r)
            {
                return l <= r;
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
    return [=, runState = buildCtx->runState()](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue = event->getIntAsInt64(targetField);
        if (!lValue.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        int64_t resolvedValue {0};
        if (std::holds_alternative<std::string>(rValue))
        {
            auto resolvedRValue = event->getIntAsInt64(std::get<std::string>(rValue));
            if (!resolvedRValue.has_value())
            {
                RETURN_FAILURE(runState, false, failureTrace2);
            }
            resolvedValue = resolvedRValue.value();
        }
        else
        {
            resolvedValue = std::get<int64_t>(rValue);
        }

        if (cmpFunction(lValue.value(), resolvedValue))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace3);
        }
    };
}

/**
 * @brief Get the Number Cmp Function object
 *
 * @param targetField Reference of the field to compare, obtained from the YAML key
 * @param op Operator to use
 * @param rightParameter Right parameter to compare, obtained from the YAML value
 * @return std::function<FilterResult(base::Event)>
 *
 * @throws std::runtime_error
 *   - if the right parameter is a value and not a valid integer
 *   - if helper::base::Parameter::Type is not supported
 */
FilterOp getNumberCmpFunction(const std::string& targetField,
                              Operator op,
                              const OpArg& rightParameter,
                              const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Depending on rValue type we store the reference or the integer value
    std::variant<std::string, double> rValue {};

    if (rightParameter->isValue())
    {
        try
        {
            rValue = std::static_pointer_cast<Value>(rightParameter)->value().getNumberAsDouble().value();
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format(R"(Expected an number but got '{}'.)",
                                                 std::static_pointer_cast<Value>(rightParameter)->value().str()));
        }
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

    // Depending on the operator we return the correct function
    std::function<bool(double l, double r)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](double l, double r)
            {
                return l == r;
            };
            break;
        case Operator::NE:
            cmpFunction = [](double l, double r)
            {
                return l != r;
            };
            break;
        case Operator::GT:
            cmpFunction = [](double l, double r)
            {
                return l > r;
            };
            break;
        case Operator::GE:
            cmpFunction = [](double l, double r)
            {
                return l >= r;
            };
            break;
        case Operator::LT:
            cmpFunction = [](double l, double r)
            {
                return l < r;
            };
            break;
        case Operator::LE:
            cmpFunction = [](double l, double r)
            {
                return l <= r;
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
    return [=, runState = buildCtx->runState()](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue = event->getNumberAsDouble(targetField);
        if (!lValue.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        double resolvedValue {0.0};
        if (std::holds_alternative<std::string>(rValue))
        {
            auto resolvedRValue = event->getNumberAsDouble(std::get<std::string>(rValue));
            if (!resolvedRValue.has_value())
            {
                RETURN_FAILURE(runState, false, failureTrace2);
            }
            resolvedValue = resolvedRValue.value();
        }
        else
        {
            resolvedValue = std::get<double>(rValue);
        }

        if (cmpFunction(lValue.value(), resolvedValue))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace3);
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
    std::function<bool(const std::string& l, const std::string& r)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l == r;
            };
            break;
        case Operator::NE:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l != r;
            };
            break;
        case Operator::GT:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l > r;
            };
            break;
        case Operator::GE:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l >= r;
            };
            break;
        case Operator::LT:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l < r;
            };
            break;
        case Operator::LE:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l <= r;
            };
            break;
        case Operator::ST:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                return l.substr(0, r.length()) == r;
            };
            break;
        case Operator::CN:
            cmpFunction = [](const std::string& l, const std::string& r)
            {
                if (!r.empty())
                {
                    return l.find(r) != std::string::npos;
                }
                return false;
            };
            break;

        default: break;
    }

    if (rightParameter->isValue())
    {
        if (!std::static_pointer_cast<Value>(rightParameter)->value().isString())
        {
            throw std::runtime_error(fmt::format(R"(Expected a string but got '{}'.)",
                                                 std::static_pointer_cast<Value>(rightParameter)->value().str()));
        }
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
                    fmt::format("Expected a reference of type '{}' but got reference '{}' of type '{}'",
                                json::Json::typeToStr(json::Json::Type::String),
                                ref->dotPath(),
                                json::Json::typeToStr(jType)));
            }
        }
    }

    // Tracing messages
    const auto name = buildCtx->context().opName;
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Comparison is false", name)};

    // Function that implements the helper
    return [=, runState = buildCtx->runState()](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        const auto lValue {event->getString(targetField)};
        if (!lValue.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        std::string rValue {};
        if (rightParameter->isValue())
        {
            rValue = std::static_pointer_cast<Value>(rightParameter)->value().getString().value();
        }
        else
        {
            const auto resolvedRValue {
                event->getString(std::static_pointer_cast<Reference>(rightParameter)->jsonPath())};
            if (!resolvedRValue.has_value())
            {
                RETURN_FAILURE(runState, false, failureTrace2);
            }

            rValue = resolvedRValue.value();
        }

        if (cmpFunction(lValue.value(), rValue))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace3);
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
        case Type::INT:
        {
            auto opFn = getIntCmpFunction(targetField, op, parameters[0], buildCtx);
            return opFn;
        }
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
//*               Int Cmp filters                 *
//*************************************************

// field: +int_equal/int|$ref/
FilterOp opBuilderHelperIntEqual(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::EQ, Type::INT, buildCtx);
    return op;
}

// field: +int_not_equal/int|$ref/
FilterOp opBuilderHelperIntNotEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::NE, Type::INT, buildCtx);
    return op;
}

// field: +int_less/int|$ref/
FilterOp opBuilderHelperIntLessThan(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LT, Type::INT, buildCtx);
    return op;
}

// field: +int_less_or_equal/int|$ref/
FilterOp opBuilderHelperIntLessThanEqual(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LE, Type::INT, buildCtx);
    return op;
}

// field: +int_greater/int|$ref/
FilterOp opBuilderHelperIntGreaterThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GT, Type::INT, buildCtx);
    return op;
}

// field: +int_greater_or_equal/int|$ref/
FilterOp opBuilderHelperIntGreaterThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GE, Type::INT, buildCtx);
    return op;
}

//*************************************************
//*               Double Cmp filters                 *
//*************************************************

// field: +double_equal/number|$ref/
FilterOp opBuilderHelperNumberEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::EQ, Type::NUMBER, buildCtx);
    return op;
}

// field: +double_not_equal/number|$ref/
FilterOp opBuilderHelperNumberNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::NE, Type::NUMBER, buildCtx);
    return op;
}

// field: +double_less/number|$ref/
FilterOp opBuilderHelperNumberLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LT, Type::NUMBER, buildCtx);
    return op;
}

// field: +double_less_or_equal/number|$ref/
FilterOp opBuilderHelperNumberLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LE, Type::NUMBER, buildCtx);
    return op;
}

// field: +double_greater/number|$ref/
FilterOp opBuilderHelperNumberGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GT, Type::NUMBER, buildCtx);
    return op;
}

// field: +double_greater_or_equal/number|$ref/
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

// field: +string_equal/value|$ref
FilterOp opBuilderHelperStringEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::EQ, Type::STRING, buildCtx);
    return op;
}

// field: +string_not_equal/value|$ref
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::NE, Type::STRING, buildCtx);
    return op;
}

// field: +string_greater/value|$ref
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GT, Type::STRING, buildCtx);
    return op;
}

// field: +string_greater_or_equal/value|$ref
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::GE, Type::STRING, buildCtx);
    return op;
}

// field: +string_less/value|$ref
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), opArgs, Operator::LT, Type::STRING, buildCtx);
    return op;
}

// field: +string_less_or_equal/value|$ref
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

// field: binary_and($ref, value)
FilterOp opBuilderHelperBinaryAnd(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    const auto& name = buildCtx->context().opName;
    const auto& schema = buildCtx->validator();

    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);
    // Parameter type check
    utils::assertValue(opArgs, 0);

    // Mask
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("{} function: Mask '{}' is not a string", name, opArgs[0]->str()));
    }
    auto strMask = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};
    const auto referenceNotFoundTrace {
        fmt::format("[{}] -> Failure: Reference '{}' not found or not a string", name, targetField.dotPath())};
    const auto referenceNotValidHexTrace {fmt::format("[{}] -> Failure: Reference '{}' is not a valid hexadecimal "
                                                      "number",
                                                      name,
                                                      targetField.dotPath())};

    const auto failAndTrace {fmt::format("[{}] -> Failure: Binary AND is false", name)};

    // Get the mask
    std::string prefix {"0x"};
    // 4 digits per byte + prefix
    std::size_t maxSize = (std::numeric_limits<uint64_t>::digits / 4) + prefix.size();
    uint64_t mask {};
    {
        if (strMask.substr(0, prefix.size()) != prefix)
        {
            throw std::runtime_error(
                fmt::format("{} function: Mask '{}' is not a valid hexadecimal number", name, strMask));
        }
        else if (strMask.size() > maxSize)
        {
            throw std::runtime_error(fmt::format("{} function: Mask '{}' is too big", name, strMask));
        }

        try
        {
            mask = std::stoull(strMask, nullptr, 16);
            if (mask == 0)
            {
                throw std::runtime_error(fmt::format("{} function: Mask cannot be 0", name));
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("{} function: Mask '{}' is not a valid hexadecimal number: {}", name, strMask, e.what()));
        }
    }

    // Fn to get the value from the event
    auto getValue = [targetField, referenceNotFoundTrace, referenceNotValidHexTrace](
                        base::ConstEvent event) -> base::RespOrError<uint64_t>
    {
        const auto value = event->getString(targetField.jsonPath());
        if (!value.has_value())
        {
            return base::Error {referenceNotFoundTrace};
        }

        if (value.value().substr(0, 2) != "0x")
        {
            return base::Error {referenceNotValidHexTrace};
        }

        uint64_t result {};
        try
        {
            result = std::stoull(value.value(), nullptr, 16);
        }
        catch (const std::exception& e)
        {
            return base::Error {referenceNotValidHexTrace};
        }

        return result;
    };

    // The filter
    return [getValue, mask, successTrace, failAndTrace](base::ConstEvent event) -> FilterResult
    {
        auto valueResult = getValue(event);
        if (base::isError(valueResult))
        {
            return base::result::makeFailure(false, base::getError(valueResult).message);
        }

        if (base::getResponse(valueResult) & mask)
        {
            return base::result::makeSuccess(true, successTrace);
        }
        return base::result::makeFailure(false, failAndTrace);
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

    auto value = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();

    auto regex_ptr {std::make_shared<RE2>(value, RE2::Quiet)};
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("Invalid regex: \"{}\".", value));
    }

    // Tracing
    const auto name = buildCtx->context().opName;
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Regex did not match", name)};

    // Return Op
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (RE2::PartialMatch(resolvedField.value(), *regex_ptr))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace2);
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
    const auto value = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();

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
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (!RE2::PartialMatch(resolvedField.value(), *regex_ptr))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace2);
        }
    };
}

// //*************************************************
// //*               IP filters                     *
// //*************************************************

// field: +ip_cidr_match/192.168.0.0/16
// field: +ip_cidr_match/192.168.0.0/255.255.0.0
FilterOp opBuilderHelperIPCIDR(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 2);
    // Parameter type check
    utils::assertValue(opArgs);
    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    uint32_t network {};
    try
    {
        network = ::utils::ip::IPv4ToUInt(std::static_pointer_cast<Value>(opArgs[0])->value().getString().value());
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(fmt::format("\"{}\" function: IPv4 address \"{}\" "
                                             "could not be converted to int: {}",
                                             name,
                                             network,
                                             e.what()));
    }

    uint32_t mask {};
    try
    {
        mask = ::utils::ip::IPv4MaskUInt(std::static_pointer_cast<Value>(opArgs[1])->value().getString().value());
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(fmt::format("\"{}\" function: IPv4 Mask \"{}\" "
                                             "could not be converted to int: {}",
                                             name,
                                             std::static_pointer_cast<Value>(opArgs[1])->value().getString().value(),
                                             e.what()));
    }

    uint32_t net_lower {network & mask};
    uint32_t net_upper {net_lower | (~mask)};

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: IPv4 address ", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: IP address is not in CIDR", name)};

    // Return Op
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        uint32_t ip {};
        try
        {
            ip = ::utils::ip::IPv4ToUInt(resolvedField.value());
        }
        catch (std::exception& e)
        {
            RETURN_FAILURE(
                runState,
                false,
                failureTrace2 + fmt::format("'{}' could not be converted to int: {}", resolvedField.value(), e.what()));
        }
        if (net_lower <= ip && ip <= net_upper)
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            RETURN_FAILURE(runState, false, failureTrace3);
        }
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
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        // Check for IPv4
        auto checkResult = checkFn(resolvedField.value());
        if (base::isError(checkResult))
        {
            RETURN_FAILURE(runState, false, failureTrace3);
        }

        if (base::getResponse(checkResult))
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        RETURN_FAILURE(runState, false, failureTrace2);
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

    // Return Op
    return [=, parameters = opArgs, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        const auto resolvedArray {event->getArray(targetField)};
        if (!resolvedArray.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace2);
        }

        json::Json cmpValue {};
        auto matchCount {0};
        for (const auto& parameter : parameters)
        {
            if (parameter->isReference())
            {
                auto resolvedParameter {event->getJson(std::static_pointer_cast<Reference>(parameter)->jsonPath())};
                if (resolvedParameter.has_value())
                {
                    cmpValue = std::move(resolvedParameter.value());
                }
                else
                {
                    continue;
                }
            }
            else
            {
                cmpValue = std::move(std::static_pointer_cast<Value>(parameter)->value().getJson().value());
            }

            // Check if the array contains the value
            bool found = std::find_if(resolvedArray.value().begin(),
                                      resolvedArray.value().end(),
                                      [&cmpValue](const json::Json& value) { return value == cmpValue; })
                         != resolvedArray.value().end();

            if (presenceCheck == found)
            {
                if (atleastOne)
                {
                    RETURN_SUCCESS(runState, true, successTrace);
                }

                matchCount++;
                if (matchCount == parameters.size())
                {
                    RETURN_SUCCESS(runState, true, successTrace);
                }
            }
        }

        RETURN_FAILURE(runState, false, failureTrace3);
    };
}

// field: +array_contains/value1/value2/...valueN
FilterOp opBuilderHelperContains(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, false, true, buildCtx);
}

// field: +array_not_contains/value1/value2/...valueN
FilterOp opBuilderHelperNotContains(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, true, false, buildCtx);
}

// field: +array_contains_any/value1/value2/...valueN
FilterOp opBuilderHelperContainsAny(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return opBuilderHelperArrayPresence(targetField, opArgs, true, true, buildCtx);
}

// field: +array_not_contains_any/value1/value2/...valueN
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
    const auto failureTrace =
        negated ? fmt::format(
            "[{}] -> Failure: Target field '{}' is a {}", name, targetField.dotPath(), json::Json::typeToStr(type))
                : fmt::format("[{}] -> Failure: Target field '{}' is not a {}",
                              name,
                              targetField.dotPath(),
                              json::Json::typeToStr(type));
    const auto failureMissingValueTrace =
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath());

    // Return Op
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](
               base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if ((event->type(targetField) == type) != negated)
            {
                RETURN_SUCCESS(runState, true, successTrace);
            }

            RETURN_FAILURE(runState, false, failureTrace);
        }

        RETURN_FAILURE(runState, false, failureMissingValueTrace);
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

// <field>: +match_value/$<definition_array>|$<array_reference>
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
    else
    {
        auto ref = std::static_pointer_cast<Reference>(opArgs[0]);
        if (buildCtx->validator().hasField(ref->dotPath()))
        {
            if (!buildCtx->validator().isArray(ref->dotPath()))
            {
                throw std::runtime_error(fmt::format(
                    "Expected a reference of an array but got reference '{}' which is not an array", ref->dotPath()));
            }
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
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath(), parameter = opArgs[0]](
               base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, failureTrace1);
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
                RETURN_FAILURE(runState, false, failureTrace2);
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
                RETURN_FAILURE(runState, false, failureTrace3);
            }

            if (!event->isArray(refPath))
            {
                RETURN_FAILURE(runState, false, failureTrace4);
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
            RETURN_SUCCESS(runState, true, successTrace);
        }

        // Not found
        RETURN_FAILURE(runState, false, failureTrace5);
    };
}

// <field>: +exists_key_in/$<definition_object>|$<object_reference>
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

    // Return op
    return [=, runState = buildCtx->runState(), targetField = targetField.jsonPath(), parameter = opArgs[0]](
               base::ConstEvent event) -> FilterResult
    {
        // Get key
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (!event->isString(targetField))
        {
            RETURN_FAILURE(runState, false, failureTrace2);
        }

        auto pointerPath = json::Json::formatJsonPath(event->getString(targetField).value());
        bool exists {false};

        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            if (!event->exists(refPath))
            {
                RETURN_FAILURE(runState, false, failureTrace3);
            }

            if (!event->isObject(refPath))
            {
                RETURN_FAILURE(runState, false, failureTrace5);
            }

            exists = event->exists(refPath + pointerPath);
        }
        else
        {
            // Parameter is a definition
            exists = std::static_pointer_cast<Value>(parameter)->value().exists(pointerPath);
        }

        // Check if object contains the key
        if (!exists)
        {
            RETURN_FAILURE(runState, false, failureTrace6);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}

// <field>: +end_with/$<definition_object>|$<object_reference>
FilterOp opBuilderHelperEndsWith(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
        {
            throw std::runtime_error(fmt::format("Expected 'string' value but got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
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

    const auto name = buildCtx->context().opName;

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
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            parameter = opArgs[0]](base::ConstEvent event) -> FilterResult
    {
        const auto targetString = event->getString(targetField);
        if (!targetString.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto stringReference = event->getString(refPath);
            if (!stringReference.has_value())
            {
                RETURN_FAILURE(runState, false, failureTrace1);
            }

            if (!base::utils::string::endsWith(targetString.value(), stringReference.value()))
            {
                RETURN_FAILURE(runState, false, failureTrace4);
            }

            RETURN_SUCCESS(runState, true, successTrace);
        }
        else
        {
            auto valueString = std::static_pointer_cast<Value>(parameter)->value().getString().value();
            if (!base::utils::string::endsWith(targetString.value(), valueString))
            {
                RETURN_FAILURE(runState, false, failureTrace4);
            }

            RETURN_SUCCESS(runState, true, successTrace);
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
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        const auto targetString = event->getString(targetField);
        if (!targetString.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (!::utils::ip::checkStrIsIPv4(targetString.value()))
        {
            RETURN_FAILURE(runState, false, failureTrace2);
        }

        RETURN_SUCCESS(runState, true, successTrace);
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
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        const auto targetString = event->getString(targetField);
        if (!targetString.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        if (!::utils::ip::checkStrIsIPv6(targetString.value()))
        {
            RETURN_FAILURE(runState, false, failureTrace2);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}

// <field>: +is_test_session
FilterOp opBuilderHelperIsTestSession(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);

    const auto name = buildCtx->context().opName;
    const auto runState = buildCtx->runState();

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {
        fmt::format("[{}] -> Failure: The evaluated environment is a production environment", name)};

    // Return op
    return [failureTrace, successTrace, runState](base::ConstEvent event) -> FilterResult
    {
        if (runState->sandbox)
        {
            RETURN_SUCCESS(runState, true, successTrace);
        }
        RETURN_FAILURE(runState, false, failureTrace);
    };
}

// <field>: +keys_exist_in_list/$<list_value>|$<list_reference>
FilterOp opBuilderHelperKeysExistInList(const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    utils::assertSize(opArgs, 1);

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
            if (!element.isString())
            {
                throw std::runtime_error(fmt::format("Expecting a 'string' array but found '{}'", element.typeName()));
            }
            expectedKeys.insert(element.getString().value());
        }
    }
    else
    {
        const auto arrayRef = *std::static_pointer_cast<Reference>(opArgs[0]);
        const auto& validator = buildCtx->validator();

        if (validator.hasField(arrayRef.dotPath()))
        {
            if (!validator.isArray(arrayRef.dotPath()))
            {
                throw std::runtime_error(fmt::format(
                    "Expected 'array' reference but got reference '{}' wich is not an array", arrayRef.dotPath()));
            }

            auto jType = validator.getJsonType(arrayRef.dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(
                    fmt::format("Expected array of 'string' but got array of '{}'", json::Json::typeToStr(jType)));
            }
        }
    }

    const auto name = buildCtx->context().opName;
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
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            parameter = opArgs[0],
            expectedKeys](base::ConstEvent event) -> FilterResult
    {
        const auto objectTarget = event->getObject(targetField);
        if (!objectTarget.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace1);
        }

        std::unordered_set<std::string> localKeys = expectedKeys;
        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            const auto list = event->getArray(refPath);
            if (!list.has_value())
            {
                RETURN_FAILURE(runState, false, failureTrace2);
            }
            for (const auto& element : list.value())
            {
                if (!element.isString())
                {
                    RETURN_FAILURE(runState, false, failureTrace3);
                }
                localKeys.insert(element.getString().value());
            }
        }

        if (localKeys.size() < objectTarget.value().size())
        {
            RETURN_FAILURE(runState, false, failureTrace4);
        }

        for (const auto& [key, value] : objectTarget.value())
        {
            if (localKeys.erase(key) == 0)
            {
                RETURN_FAILURE(runState, false, failureTrace4);
            }
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}

} // namespace builder::builders::opfilter
