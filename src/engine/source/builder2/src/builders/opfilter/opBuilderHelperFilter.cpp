#include "opBuilderHelperFilter.hpp"

#include <algorithm>
#include <optional>
#include <variant>

#include <re2/re2.h>

#include "baseTypes.hpp"
#include "syntax.hpp"
#include <utils/ipUtils.hpp>

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
    INT
};

/**
 * @brief Get the Int Cmp Function object
 *
 * @param targetField Reference of the field to compare, obtained from the YAML key
 * @param op Operator to use
 * @param rightParameter Right parameter to compare, obtained from the YAML value
 * @param name Formatted name of the helper
 * @return std::function<FilterResult(base::Event)>
 *
 * @throws std::runtime_error
 *   - if the right parameter is a value and not a valid integer
 *   - if helper::base::Parameter::Type is not supported
 */
FilterOp
getIntCmpFunction(const std::string& targetField, Operator op, const OpArg& rightParameter, const std::string& name)
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
            throw std::runtime_error(
                fmt::format(R"('{}' function: Parameter '{}' could not be converted to int64_t: '{}'.)",
                            name,
                            std::static_pointer_cast<Value>(rightParameter)->value().str(),
                            e.what()));
        }
    }
    else
    {
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
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Comparison is false", name)};

    // Function that implements the helper
    return [=](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue = event->getIntAsInt64(targetField);
        if (!lValue.has_value())
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        int64_t resolvedValue {0};
        if (std::holds_alternative<std::string>(rValue))
        {
            auto resolvedRValue = event->getIntAsInt64(std::get<std::string>(rValue));
            if (!resolvedRValue.has_value())
            {
                return base::result::makeFailure(false, failureTrace2);
            }
            resolvedValue = resolvedRValue.value();
        }
        else
        {
            resolvedValue = std::get<int64_t>(rValue);
        }

        if (cmpFunction(lValue.value(), resolvedValue))
        {
            return base::result::makeSuccess(true, successTrace);
        }
        else
        {
            return base::result::makeFailure(false, failureTrace3);
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
FilterOp
getStringCmpFunction(const std::string& targetField, Operator op, const OpArg& rightParameter, const std::string& name)
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

    if (rightParameter->isValue() && !std::static_pointer_cast<Value>(rightParameter)->value().isString()) 
    {
        throw std::runtime_error(fmt::format(R"( "{}" function: Parameter "{}" is not a string.)",
                                             name,
                                             std::static_pointer_cast<Value>(rightParameter)->value().str()));
    }

    // Tracing messages
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Comparison is false", name)};

    // Function that implements the helper
    return [=](base::ConstEvent event) -> FilterResult
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        const auto lValue {event->getString(targetField)};
        if (!lValue.has_value())
        {
            return base::result::makeFailure(false, failureTrace1);
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
                return base::result::makeFailure(false, failureTrace2);
            }

            rValue = resolvedRValue.value();
        }

        if (cmpFunction(lValue.value(), rValue))
        {
            return base::result::makeSuccess(true, successTrace);
        }
        else
        {
            return base::result::makeFailure(false, failureTrace3);
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
FilterOp opBuilderComparison(
    const std::string& targetField, const std::string& name, const std::vector<OpArg>& parameters, Operator op, Type t)
{
    // Assert expected number of parameters
    utils::assertSize(parameters, 1);

    // Get the expression depending on the type
    switch (t)
    {
        case Type::INT:
        {
            auto opFn = getIntCmpFunction(targetField, op, parameters[0], name);
            return opFn;
        }
        case Type::STRING:
        {
            auto opFn = getStringCmpFunction(targetField, op, parameters[0], name);
            return opFn;
        }
        default:
            throw std::runtime_error(
                fmt::format("{} function: Unsupported comparison type ({}).", name, static_cast<int>(t)));
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
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::EQ, Type::INT);
    return op;
}

// field: +int_not_equal/int|$ref/
FilterOp opBuilderHelperIntNotEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::NE, Type::INT);
    return op;
}

// field: +int_less/int|$ref/
FilterOp opBuilderHelperIntLessThan(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::LT, Type::INT);
    return op;
}

// field: +int_less_or_equal/int|$ref/
FilterOp opBuilderHelperIntLessThanEqual(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::LE, Type::INT);
    return op;
}

// field: +int_greater/int|$ref/
FilterOp opBuilderHelperIntGreaterThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::GT, Type::INT);
    return op;
}

// field: +int_greater_or_equal/int|$ref/
FilterOp opBuilderHelperIntGreaterThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op = opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::GE, Type::INT);
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
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::EQ, Type::STRING);
    return op;
}

// field: +string_not_equal/value|$ref
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::NE, Type::STRING);
    return op;
}

// field: +string_greater/value|$ref
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::GT, Type::STRING);
    return op;
}

// field: +string_greater_or_equal/value|$ref
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::GE, Type::STRING);
    return op;
}

// field: +string_less/value|$ref
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::LT, Type::STRING);
    return op;
}

// field: +string_less_or_equal/value|$ref
FilterOp opBuilderHelperStringLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::LE, Type::STRING);
    return op;
}

// field: +starts_with/value|$ref
FilterOp opBuilderHelperStringStarts(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::ST, Type::STRING);
    return op;
}

// field: +contains/value|$ref
FilterOp opBuilderHelperStringContains(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto op =
        opBuilderComparison(targetField.jsonPath(), buildCtx->context().opName, opArgs, Operator::CN, Type::STRING);
    return op;
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

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    auto value = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();

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
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Regex did not match", name)};

    // Return Op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        if (RE2::PartialMatch(resolvedField.value(), *regex_ptr))
        {
            return base::result::makeSuccess(true, successTrace);
        }
        else
        {
            return base::result::makeFailure(false, failureTrace2);
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
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        if (!RE2::PartialMatch(resolvedField.value(), *regex_ptr))
        {
            return base::result::makeSuccess(true, successTrace);
        }
        else
        {
            return base::result::makeFailure(false, failureTrace2);
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
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        const auto resolvedField {event->getString(targetField)};
        if (!resolvedField.has_value())
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        uint32_t ip {};
        try
        {
            ip = ::utils::ip::IPv4ToUInt(resolvedField.value());
        }
        catch (std::exception& e)
        {
            return base::result::makeFailure(
                false,
                failureTrace2 + fmt::format("'{}' could not be converted to int: {}", resolvedField.value(), e.what()));
        }
        if (net_lower <= ip && ip <= net_upper)
        {
            return base::result::makeSuccess(true, successTrace);
        }
        else
        {
            return base::result::makeFailure(false, failureTrace3);
        }
    };
}

//*************************************************
//*               Array filters                   *
//*************************************************
// TODO: update to handle any json type
FilterOp opBuilderHelperArrayPresence(const Reference& targetField,
                                      const std::string& name,
                                      const std::vector<OpArg>& parameters,
                                      bool checkPresence)
{
    // Assert expected number of parameters
    utils::assertSize(parameters, 1, utils::MAX_OP_ARGS);

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: Target field '{}' is not an array", name, targetField.dotPath())};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: Target array '{}' {} of the parameters",
                                                 name,
                                                 targetField.dotPath(),
                                                 checkPresence ? "does not contain any" : "contain at least one")};

    // Return Op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        const auto resolvedArray {event->getArray(targetField)};
        if (!resolvedArray.has_value())
        {
            return base::result::makeFailure(false, failureTrace2);
        }

        json::Json cmpValue {};
        auto result = base::result::makeSuccess(true, successTrace);
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
                // TODO: throws if not a string
                cmpValue.setString(std::static_pointer_cast<Value>(parameter)->value().getString().value());
            }

            // Check if the array contains the value, if so finish
            if (std::find_if(resolvedArray.value().begin(),
                             resolvedArray.value().end(),
                             [&cmpValue](const json::Json& value) { return value == cmpValue; })
                != resolvedArray.value().end())
            {
                if (!checkPresence)
                {
                    result = base::result::makeFailure(false, failureTrace3);
                }
                return result;
            }
        }

        if (checkPresence)
        {
            result = base::result::makeFailure(false, failureTrace3);
        }
        return result;
    };
}

// field: +array_contains/value1/value2/...valueN
FilterOp opBuilderHelperContainsString(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    for (const auto& arg : opArgs)
    {
        if (arg->isValue())
        {
            auto value = std::static_pointer_cast<Value>(arg)->value();
            if (!value.isString())
            {
                throw std::runtime_error(fmt::format("\"{}\" function: "
                                                     "Parameter \"{}\" is not a string.",
                                                     buildCtx->context().opName,
                                                     value.str()));
            }
        }
    }
    auto op = opBuilderHelperArrayPresence(targetField, buildCtx->context().opName, opArgs, true);
    return op;
}

// field: +array_not_contains/value1/value2/...valueN
FilterOp opBuilderHelperNotContainsString(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    for (const auto& arg : opArgs)
    {
        if (arg->isValue())
        {
            auto value = std::static_pointer_cast<Value>(arg)->value();
            if (!value.isString())
            {
                throw std::runtime_error(fmt::format("\"{}\" function: "
                                                     "Parameter \"{}\" is not a string.",
                                                     buildCtx->context().opName,
                                                     value.str()));
            }
        }
    }
    auto op = opBuilderHelperArrayPresence(targetField, buildCtx->context().opName, opArgs, false);
    return op;
}

//*************************************************
//*                Type filters                   *
//*************************************************

// field: +is_number
FilterOp opBuilderHelperIsNumber(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not a number", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return Op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isNumber(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_not_number
FilterOp opBuilderHelperIsNotNumber(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is a number", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (!event->isNumber(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_string
FilterOp opBuilderHelperIsString(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not a string", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isString(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_not_string
FilterOp opBuilderHelperIsNotString(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is a string", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (!event->isString(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_boolean
FilterOp opBuilderHelperIsBool(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not a boolean", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isBool(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_not_boolean
FilterOp opBuilderHelperIsNotBool(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is a boolean", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (!event->isBool(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_array
FilterOp opBuilderHelperIsArray(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not an array", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isArray(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_not_array
FilterOp opBuilderHelperIsNotArray(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is an array", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (!event->isArray(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_object
FilterOp opBuilderHelperIsObject(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not an object", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isObject(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }

        return result;
    };
}

// field: +is_not_object
FilterOp opBuilderHelperIsNotObject(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is an object", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (!event->isObject(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }
        return result;
    };
}

// field: +is_null
FilterOp opBuilderHelperIsNull(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is not null", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};

    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;

        if (event->exists(targetField))
        {
            if (event->isNull(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }
        return result;
    };
}

// field: +is_not_null
FilterOp opBuilderHelperIsNotNull(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;
    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is null", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;
        if (event->exists(targetField))
        {
            if (!event->isNull(targetField))
            {
                result = base::result::makeSuccess(true, successTrace);
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }
        return result;
    };
}

// field: +is_true
FilterOp opBuilderHelperIsTrue(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;
    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is false", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;
        if (event->exists(targetField))
        {
            if (event->isBool(targetField))
            {
                if (event->getBool(targetField).value())
                {
                    result = base::result::makeSuccess(true, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(false, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }
        return result;
    };
}

// field: +is_false
FilterOp opBuilderHelperIsFalse(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 0);
    const auto name = buildCtx->context().opName;
    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' is true", name, targetField.dotPath())};
    const std::string failureMissingValueTrace {
        fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField.dotPath())};
    // Return op
    return [=, targetField = targetField.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        FilterResult result;
        if (event->exists(targetField))
        {
            if (event->isBool(targetField))
            {
                if (!event->getBool(targetField).value())
                {
                    result = base::result::makeSuccess(true, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(false, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(false, failureTrace);
            }
        }
        else
        {
            result = base::result::makeFailure(false, failureMissingValueTrace);
        }
        return result;
    };
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

    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isArray())
    {
        throw std::runtime_error(fmt::format("Expected 'array' type for parameter 1, got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
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
    return [=, targetField = targetField.jsonPath(), parameter = opArgs[0]](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            return base::result::makeFailure(false, failureTrace1);
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
                return base::result::makeFailure(false, failureTrace2);
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
                return base::result::makeFailure(false, failureTrace3);
            }

            if (!event->isArray(refPath))
            {
                return base::result::makeFailure(false, failureTrace4);
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
            return base::result::makeSuccess(true, successTrace);
        }

        // Not found
        return base::result::makeFailure(false, failureTrace5);
    };
}

// <field>: +match_key/$<definition_object>|$<object_reference>
FilterOp opBuilderHelperMatchKey(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isObject())
    {
        throw std::runtime_error(fmt::format("Expected 'object' type for parameter 1, got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
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
    return [=, targetField = targetField.jsonPath(), parameter = opArgs[0]](base::ConstEvent event) -> FilterResult
    {
        // Get key
        if (!event->exists(targetField))
        {
            return base::result::makeFailure(false, failureTrace1);
        }

        if (!event->isString(targetField))
        {
            return base::result::makeFailure(false, failureTrace2);
        }

        auto pointerPath = json::Json::formatJsonPath(event->getString(targetField).value());
        bool exists {false};

        if (parameter->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(parameter)->jsonPath();
            if (!event->exists(refPath))
            {
                return base::result::makeFailure(false, failureTrace3);
            }

            if (!event->isObject(refPath))
            {
                return base::result::makeFailure(false, failureTrace5);
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
            return base::result::makeFailure(false, failureTrace6);
        }

        return base::result::makeSuccess(true, successTrace);
    };
}

} // namespace builder::builders::opfilter
