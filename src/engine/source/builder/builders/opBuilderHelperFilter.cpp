#include "opBuilderHelperFilter.hpp"

#include <algorithm>
#include <optional>
#include <variant>

#include <re2/re2.h>

#include "baseTypes.hpp"
#include "syntax.hpp"
#include <baseHelper.hpp>
#include <utils/ipUtils.hpp>

namespace builder::internals::builders
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
    ST  ///< start with
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
 * @return std::function<base::result::Result<base::Event>(base::Event)>
 *
 * @throws std::runtime_error
 *   - if the right parameter is a value and not a valid integer
 *   - if helper::base::Parameter::Type is not supported
 */
std::function<base::result::Result<base::Event>(base::Event)>
getIntCmpFunction(const std::string& targetField,
                  Operator op,
                  const helper::base::Parameter& rightParameter,
                  const std::string& name)
{
    // Depending on rValue type we store the reference or the integer value
    std::variant<std::string, int> rValue {};
    auto rValueType {rightParameter.m_type};
    switch (rightParameter.m_type)
    {
        case helper::base::Parameter::Type::VALUE:
            try
            {
                rValue = std::stoi(rightParameter.m_value);
            }
            catch (const std::exception& e)
            {
                std::throw_with_nested(std::runtime_error(fmt::format(
                    "[builders::getIntCmpFunction()] could not convert {} to int",
                    rightParameter.m_value)));
            }

            break;

        case helper::base::Parameter::Type::REFERENCE:
            rValue = rightParameter.m_value;
            break;

        default:
            throw std::runtime_error(fmt::format(
                "[builders::getIntCmpFunction()] invalid parameter type for {}",
                rightParameter.m_value));
    }

    // Depending on the operator we return the correct function
    std::function<bool(int l, int r)> cmpFunction;
    switch (op)
    {
        case Operator::EQ:
            cmpFunction = [](int l, int r)
            {
                return l == r;
            };
            break;
        case Operator::NE:
            cmpFunction = [](int l, int r)
            {
                return l != r;
            };
            break;
        case Operator::GT:
            cmpFunction = [](int l, int r)
            {
                return l > r;
            };
            break;
        case Operator::GE:
            cmpFunction = [](int l, int r)
            {
                return l >= r;
            };
            break;
        case Operator::LT:
            cmpFunction = [](int l, int r)
            {
                return l < r;
            };
            break;
        case Operator::LE:
            cmpFunction = [](int l, int r)
            {
                return l <= r;
            };
            break;
        default: break;
    }

    // Tracing messages
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {
        fmt::format("[{}] -> Failure: [{}] not found", name, rightParameter.m_value)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure", name)};

    // Function that implements the helper
    return [=](base::Event event) -> base::result::Result<base::Event>
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue {event->getInt(targetField)};
        if (!lValue.has_value())
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (helper::base::Parameter::Type::REFERENCE == rValueType)
        {
            auto resolvedRValue {event->getInt(std::get<std::string>(rValue))};
            if (!resolvedRValue.has_value())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            if (cmpFunction(lValue.value(), resolvedRValue.value()))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace3);
            }
        }
        else
        {
            if (cmpFunction(lValue.value(), std::get<int>(rValue)))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace3);
            }
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
 * @return std::function<base::result::Result<base::Event>(base::Event)>
 *
 * @throws std::runtime_error if helper::base::Parameter::Type is not supported
 */
std::function<base::result::Result<base::Event>(base::Event)>
getStringCmpFunction(const std::string& targetField,
                     Operator op,
                     const helper::base::Parameter& rightParameter,
                     const std::string& name)
{
    // Depending on rValue type we store the reference or the string value, string in both
    // cases
    std::string rValue {};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

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

        default: break;
    }

    // Tracing messages
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {
        fmt::format("[{}] -> Failure: [{}] not found", name, rightParameter.m_value)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure", name)};

    // Function that implements the helper
    return [=](base::Event event) -> base::result::Result<base::Event>
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        const auto lValue {event->getString(targetField)};
        if (!lValue.has_value())
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (helper::base::Parameter::Type::REFERENCE == rValueType)
        {
            const auto resolvedRValue {event->getString(rValue)};
            if (!resolvedRValue.has_value())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            if (cmpFunction(lValue.value(), resolvedRValue.value()))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace3);
            }
        }
        else
        {
            if (cmpFunction(lValue.value(), rValue))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace3);
            }
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
base::Expression opBuilderComparison(const std::any& definition, Operator op, Type t)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);
    // Get the expression depending on the type
    switch (t)
    {
        case Type::INT:
        {
            auto opFn {getIntCmpFunction(targetField, op, parameters[0], name)};
            return base::Term<base::EngineOp>::create(name, opFn);
        }
        case Type::STRING:
        {
            auto opFn {getStringCmpFunction(targetField, op, parameters[0], name)};
            return base::Term<base::EngineOp>::create(name, opFn);
        }
        default:
            throw std::runtime_error(fmt::format("[builders::opBuilderComparison] "
                                                 "Unsupported type: {}",
                                                 static_cast<int>(t)));
    }
}

//*************************************************
//*               Int Cmp filters                 *
//*************************************************

// field: +i_eq/int|$ref/
base::Expression opBuilderHelperIntEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::EQ, Type::INT)};
    return expression;
}

// field: +i_ne/int|$ref/
base::Expression opBuilderHelperIntNotEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::NE, Type::INT)};
    return expression;
}

// field: +i_lt/int|$ref/
base::Expression opBuilderHelperIntLessThan(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::LT, Type::INT)};
    return expression;
}

// field: +i_le/int|$ref/
base::Expression opBuilderHelperIntLessThanEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::LE, Type::INT)};
    return expression;
}

// field: +i_gt/int|$ref/
base::Expression opBuilderHelperIntGreaterThan(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::GT, Type::INT)};
    return expression;
}

// field: +i_ge/int|$ref/
base::Expression opBuilderHelperIntGreaterThanEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::GE, Type::INT)};
    return expression;
}

//*************************************************
//*           String Cmp filters                  *
//*************************************************

// field: +s_eq/value|$ref
base::Expression opBuilderHelperStringEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::EQ, Type::STRING)};
    return expression;
}

// field: +s_ne/value|$ref
base::Expression opBuilderHelperStringNotEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::NE, Type::STRING)};
    return expression;
}

// field: +s_gt/value|$ref
base::Expression opBuilderHelperStringGreaterThan(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::GT, Type::STRING)};
    return expression;
}

// field: +s_ge/value|$ref
base::Expression opBuilderHelperStringGreaterThanEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::GE, Type::STRING)};
    return expression;
}

// field: +s_lt/value|$ref
base::Expression opBuilderHelperStringLessThan(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::LT, Type::STRING)};
    return expression;
}

// field: +s_le/value|$ref
base::Expression opBuilderHelperStringLessThanEqual(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::LE, Type::STRING)};
    return expression;
}

// field: +s_starts/value|$ref
base::Expression opBuilderHelperStringStarts(const std::any& definition)
{
    auto expression {opBuilderComparison(definition, Operator::ST, Type::STRING)};
    return expression;
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +r_match/regexp
base::Expression opBuilderHelperRegexMatch(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Parameter type check
    helper::base::checkParameterType(parameters[0], helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    auto regex_ptr {std::make_shared<RE2>(parameters[0].m_value, RE2::Quiet)};
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("[builders::opBuilderHelperRegexMatch] "
                                             "Invalid regex: {}",
                                             parameters[0].m_value));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            const auto resolvedField {event->getString(targetField)};
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            if (RE2::PartialMatch(resolvedField.value(), *regex_ptr))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace2);
            }
        });
}

// field: +r_not_match/regexp
base::Expression opBuilderHelperRegexNotMatch(const std::any& definition)
{
    // TODO: Regex parameter fails at operationBuilderSplit
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Parameter type check
    helper::base::checkParameterType(parameters[0], helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    auto regex_ptr {std::make_shared<RE2>(parameters[0].m_value, RE2::Quiet)};
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("[builders::opBuilderHelperRegexNotMatch] "
                                             "Invalid regex: {}",
                                             parameters[0].m_value));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            const auto resolvedField {event->getString(targetField)};
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            if (!RE2::PartialMatch(resolvedField.value(), *regex_ptr))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace2);
            }
        });
}

// //*************************************************
// //*               IP filters                     *
// //*************************************************

// field: +ip_cidr/192.168.0.0/16
// field: +ip_cidr/192.168.0.0/255.255.0.0
base::Expression opBuilderHelperIPCIDR(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    // Parameter type check
    for (const auto& parameter : parameters)
    {
        helper::base::checkParameterType(parameter, helper::base::Parameter::Type::VALUE);
    }
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    uint32_t network {};
    try
    {
        network = utils::ip::IPv4ToUInt(parameters[0].m_value);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error("Invalid IPv4 address: " + network);
    }

    uint32_t mask {};
    try
    {
        mask = utils::ip::IPv4MaskUInt(parameters[1].m_value);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error("Invalid IPv4 mask: " + mask);
    }

    uint32_t net_lower {network & mask};
    uint32_t net_upper {net_lower | (~mask)};

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure: invalid target ip", name)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            const auto resolvedField {event->getString(targetField)};
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            uint32_t ip {};
            try
            {
                ip = utils::ip::IPv4ToUInt(resolvedField.value());
            }
            catch (std::exception& ex)
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            if (ip >= net_lower && ip <= net_upper)
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace3);
            }
        });
}

//*************************************************
//*               Existance filters               *
//*************************************************

// field: +exists
base::Expression opBuilderHelperExists(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            if (event->exists(targetField))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace);
            }
        });
}

// field: +not_exists
base::Expression opBuilderHelperNotExists(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            if (!event->exists(targetField))
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace);
            }
        });
}

//*************************************************
//*               Array filters                   *
//*************************************************

// field: +s_contains/value1/value2/...valueN
// TODO: Add test for this helper
base::Expression opBuilderHelperContainsString(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    if (parameters.empty())
    {
        throw std::runtime_error(
            fmt::format("[opBuilderHelperContains] parameters can not be empty"));
    }
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure: invalid target array", name)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure", name)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // TODO FIx this, unused resolvedField
            const auto resolvedField {event->getString(targetField)};
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            const auto resolvedArray {event->getArray(targetField)};
            if (!resolvedArray.has_value())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            json::Json cmpValue {};
            for (const auto& parameter : parameters)
            {
                switch (parameter.m_type)
                {
                    case helper::base::Parameter::Type::REFERENCE:
                    {
                        const auto resolvedParameter {
                            event->getString(parameter.m_value)};
                        if (!resolvedParameter.has_value())
                        {
                            return base::result::makeFailure(event, failureTrace3);
                        }

                        cmpValue.setString(resolvedParameter.value());
                    }
                    case helper::base::Parameter::Type::VALUE:
                    {
                        cmpValue.setString(parameter.m_value);
                    }
                    default:
                        throw std::runtime_error(fmt::format(
                            "[opBuilderHelperContains] invalid parameter type"));
                }

                if (std::find(resolvedArray.value().begin(),
                              resolvedArray.value().end(),
                              cmpValue)
                    == resolvedArray.value().end())
                {
                    return base::result::makeFailure(event, failureTrace3);
                }
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

//*************************************************
//*                Type filters                   *
//*************************************************

// field: +is_number
base::Expression opBuilderHelperIsNumber(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isNumber(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_number
base::Expression opBuilderHelperIsNotNumber(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isNumber(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_string
base::Expression opBuilderHelperIsString(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isString(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_string
base::Expression opBuilderHelperIsNotString(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isString(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_bool
base::Expression opBuilderHelperIsBool(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isBool(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_bool
base::Expression opBuilderHelperIsNotBool(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isBool(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_array
base::Expression opBuilderHelperIsArray(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isArray(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_array
base::Expression opBuilderHelperIsNotArray(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isArray(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_object
base::Expression opBuilderHelperIsObject(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isObject(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_object
base::Expression opBuilderHelperIsNotObject(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isObject(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_null
base::Expression opBuilderHelperIsNull(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (event->isNull(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_not_null
base::Expression opBuilderHelperIsNotNull(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->exists(targetField))
            {
                if (!event->isNull(targetField))
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_true
base::Expression opBuilderHelperIsTrue(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->getBool(targetField).has_value())
            {
                if (event->getBool(targetField).value())
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

// field: +is_false
base::Expression opBuilderHelperIsFalse(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters {helper::base::processParameters(rawParameters)};
    helper::base::checkParametersSize(parameters, 0);
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};

    const auto failureMissingValueTrace {
        fmt::format("[{}] -> Failure, \"{}\" field not found", name, targetField)};

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            base::result::Result<base::Event> result;

            if (event->getBool(targetField).has_value())
            {
                if (!event->getBool(targetField).value())
                {
                    result = base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    result = base::result::makeFailure(event, failureTrace);
                }
            }
            else
            {
                result = base::result::makeFailure(event, failureMissingValueTrace);
            }

            return result;
        });
}

} // namespace builder::internals::builders
