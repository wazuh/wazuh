#include "opBuilderHelperFilter.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <variant>

#include <fmt/format.h>
#include <re2/re2.h>

#include "baseTypes.hpp"
#include "syntax.hpp"
#include <utils/ipUtils.hpp>

namespace builder::internals::builders
{

/**
 * @brief Struct to handle that parameters may be a value or a reference.
 *
 */
struct Parameter
{
    enum class Type
    {
        REFERENCE,
        VALUE
    };

    Type m_type;
    std::string m_value;

    friend std::ostream& operator<<(std::ostream& os, const Parameter& parameter)
    {
        os << parameter.m_value;
        return os;
    }
};

/**
 * @brief Extract expected parameters from std::any.
 *  <string helperName> <string targetField> <array of string parameters>
 * targetField must be a valid JSON pointer path.
 * References inside parameters must be preceded by ANCHOR_REFERENCE.
 * /envent/original: name ["param1", ... ]
 *
 * @param definition
 * @return std::tuple<std::string, std::string, std::vector<std::string>>
 *
 * @throws std::runtime_error if definition is not a tuple with the expected structure.
 */
std::tuple<std::string, std::string, std::vector<std::string>>
extractDefinition(const std::any& definition)
{
    std::tuple<std::string, std::string, std::vector<std::string>> extracted;
    try
    {
        extracted =
            std::any_cast<std::tuple<std::string, std::string, std::vector<std::string>>>(
                definition);
    }
    catch (const std::bad_any_cast& e)
    {
        std::throw_with_nested(std::runtime_error(
            "[builders::processDefinition(definition)] "
            "Can not process definition, expected tuple with name and parameters"));
    }

    return extracted;
}

/**
 * @brief Transforms a vector of strings into a vector of Parameters.
 * If the string is a reference, it will be transformed into a Parameter with
 * Type::REFERENCE and the reference will be transformed into a JSON pointer path.
 *
 * If the string is a value, it will be transformed into a Parameter with Type::VALUE.
 *
 * @param parameters vector of strings
 * @return std::vector<Parameter>
 *
 * @throws std::runtime_error if a reference parameter can not be transformed into a JSON
 * pointer path.
 */
std::vector<Parameter> processParameters(const std::vector<std::string>& parameters)
{
    std::vector<Parameter> newParameters;
    std::transform(parameters.begin(),
                   parameters.end(),
                   std::back_inserter(newParameters),
                   [](const std::string& parameter) -> Parameter
                   {
                       if (parameter[0] == syntax::REFERENCE_ANCHOR)
                       {
                           std::string pointerPath;
                           try
                           {
                               pointerPath =
                                   json::Json::formatJsonPath(parameter.substr(1));
                           }
                           catch (const std::exception& e)
                           {
                               std::throw_with_nested(std::runtime_error(fmt::format(
                                   "[builders::processParameters(parameters)] "
                                   "Can not format to Json pointer path parameter: {}",
                                   parameter)));
                           }
                           return {Parameter::Type::REFERENCE, pointerPath};
                       }
                       else
                       {
                           return {Parameter::Type::VALUE, parameter};
                       }
                   });

    return newParameters;
}

/**
 * @brief Check that the number of parameters is correct and throw otherwise.
 *
 * @param parameters
 * @param size
 *
 * @throws std::runtime_error if the number of parameters is not correct.
 */
void assertParametersSize(const std::vector<Parameter>& parameters, size_t size)
{
    if (parameters.size() != size)
    {
        throw std::runtime_error(fmt::format("[builders::assertParametersSize] "
                                             "Expected [{}] parameters, got [{}]",
                                             size,
                                             parameters.size()));
    }
}

/**
 * @brief Check that the paremeter is of Parameter::Type and throw otherwise.
 *
 * @param parameter
 * @param type
 *
 * @throws std::runtime_error if the parameter is not of the expected type.
 */
void assertParameterType(const Parameter& parameter, Parameter::Type type)
{
    if (parameter.m_type != type)
    {
        throw std::runtime_error(fmt::format(
            "[builders::assertParameterType] "
            "Expected parameter of type [{}], got parameter [{}] with type [{}]",
            static_cast<int>(type),
            parameter.m_value,
            static_cast<int>(parameter.m_type)));
    }
}

/**
 * @brief Format the name to be used in Tracers.
 * Format: "helper.<name>[<targetField>/<parameters>]"
 *
 * @param name
 * @param targetField
 * @param parameters
 * @return std::string
 */
std::string formatHelperFilterName(const std::string& name,
                                   const std::string& targetField,
                                   const std::vector<Parameter>& parameters)
{
    std::stringstream formattedName;
    formattedName << fmt::format("helper.{}[{}", name, targetField);
    if (parameters.size() > 0)
    {
        formattedName << fmt::format(", {}", parameters.begin()->m_value);
        for (auto it = parameters.begin() + 1; it != parameters.end(); ++it)
        {
            formattedName << fmt::format(", {}", it->m_value);
        }
    }
    formattedName << "]";

    return formattedName.str();
}

//*************************************************
//*           Comparison filters                  *
//*************************************************

/**
 * @brief Operators supported by the comparison helpers.
 *
 */
enum class Operator
{
    EQ,
    NE,
    GT,
    GE,
    LT,
    LE
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
 *   - if Parameter::Type is not supported
 */
std::function<base::result::Result<base::Event>(base::Event)>
getIntCmpFunction(const std::string& targetField,
                  Operator op,
                  const Parameter& rightParameter,
                  const std::string& name)
{
    // Depending on rValue type we store the reference or the integer value
    std::variant<std::string, int> rValue {};
    auto rValueType = rightParameter.m_type;
    switch (rightParameter.m_type)
    {
        case Parameter::Type::VALUE:
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

        case Parameter::Type::REFERENCE: rValue = rightParameter.m_value; break;

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
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 =
        fmt::format("[{}] -> Failure: [{}] not found", name, rightParameter.m_value);
    const auto failureTrace3 = fmt::format("[{}] -> Failure", name);

    // Function that implements the helper
    return [=](base::Event event) -> base::result::Result<base::Event>
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue = event->getValueInt(targetField);
        if (!lValue.has_value())
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (rValueType == Parameter::Type::REFERENCE)
        {
            auto resolvedRValue = event->getValueInt(std::get<std::string>(rValue));
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
 * @throws std::runtime_error if Parameter::Type is not supported
 */
std::function<base::result::Result<base::Event>(base::Event)>
getStringCmpFunction(const std::string& targetField,
                     Operator op,
                     const Parameter& rightParameter,
                     const std::string& name)
{
    // Depending on rValue type we store the reference or the string value, string in both
    // cases
    std::string rValue {};
    auto rValueType = rightParameter.m_type;
    switch (rightParameter.m_type)
    {
        case Parameter::Type::VALUE: rValue = rightParameter.m_value; break;
        case Parameter::Type::REFERENCE: rValue = rightParameter.m_value; break;
        default:
            throw std::runtime_error(fmt::format(
                "[builders::getIntCmpFunction()] invalid parameter type [{}] for [{}]",
                static_cast<int>(rightParameter.m_type),
                rightParameter.m_value));
    }

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
        default: break;
    }

    // Tracing messages
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 =
        fmt::format("[{}] -> Failure: [{}] not found", name, rightParameter.m_value);
    const auto failureTrace3 = fmt::format("[{}] -> Failure", name);

    // Function that implements the helper
    return [=](base::Event event) -> base::result::Result<base::Event>
    {
        // We assert that references exists, checking if the optional from Json getter is
        // empty ot not. Then if is a reference we get the value from the event, otherwise
        // we get the value from the parameter

        auto lValue = event->getValueString(targetField);
        if (!lValue.has_value())
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        if (rValueType == Parameter::Type::REFERENCE)
        {
            auto resolvedRValue = event->getValueString(rValue);
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
    auto [name, targetField, raw_parameters] = extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters = processParameters(raw_parameters);
    // Assert expected number of parameters
    assertParametersSize(parameters, 1);
    // Format name for the tracer
    name = formatHelperFilterName(name, targetField, parameters);
    // Get the expression depending on the type
    switch (t)
    {
        case Type::INT:
        {
            auto opFn = getIntCmpFunction(targetField, op, parameters[0], name);
            return base::Term<base::EngineOp>::create(name, opFn);
        }
        case Type::STRING:
        {
            auto opFn = getStringCmpFunction(targetField, op, parameters[0], name);
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
    auto expression = opBuilderComparison(definition, Operator::EQ, Type::INT);
    return expression;
}

// field: +i_ne/int|$ref/
base::Expression opBuilderHelperIntNotEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::NE, Type::INT);
    return expression;
}

// field: +i_lt/int|$ref/
base::Expression opBuilderHelperIntLessThan(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::LT, Type::INT);
    return expression;
}

// field: +i_le/int|$ref/
base::Expression opBuilderHelperIntLessThanEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::LE, Type::INT);
    return expression;
}

// field: +i_gt/int|$ref/
base::Expression opBuilderHelperIntGreaterThan(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::GT, Type::INT);
    return expression;
}

// field: +i_ge/int|$ref/
base::Expression opBuilderHelperIntGreaterThanEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::GE, Type::INT);
    return expression;
}

//*************************************************
//*           String Cmp filters                  *
//*************************************************

// <field>: +s_eq/<value>
base::Expression opBuilderHelperStringEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::EQ, Type::STRING);
    return expression;
}

// <field>: +s_ne/<value>
base::Expression opBuilderHelperStringNotEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::NE, Type::STRING);
    return expression;
}

// <field>: +s_gt/<value>|$<ref>
base::Expression opBuilderHelperStringGreaterThan(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::GT, Type::STRING);
    return expression;
}

// <field>: +s_ge/<value>|$<ref>
base::Expression opBuilderHelperStringGreaterThanEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::GE, Type::STRING);
    return expression;
}

// <field>: +s_lt/<value>|$<ref>
base::Expression opBuilderHelperStringLessThan(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::LT, Type::STRING);
    return expression;
}

// <field>: +s_le/<value>|$<ref>
base::Expression opBuilderHelperStringLessThanEqual(const std::any& definition)
{
    auto expression = opBuilderComparison(definition, Operator::LE, Type::STRING);
    return expression;
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +r_match/regexp
base::Expression opBuilderHelperRegexMatch(const std::any& definition)
{
    auto [name, targetField, raw_parameters] = extractDefinition(definition);
    auto parameters = processParameters(raw_parameters);
    assertParametersSize(parameters, 1);
    assertParameterType(parameters[0], Parameter::Type::VALUE);
    name = formatHelperFilterName(name, targetField, parameters);

    auto regex_ptr = std::make_shared<RE2>(parameters[0].m_value, RE2::Quiet);
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("[builders::opBuilderHelperRegexMatch] "
                                             "Invalid regex: {}",
                                             parameters[0].m_value));
    }

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 = fmt::format("[{}] -> Failure", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            auto resolvedField = event->getValueString(targetField);
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
    auto [name, targetField, raw_parameters] = extractDefinition(definition);
    auto parameters = processParameters(raw_parameters);
    assertParametersSize(parameters, 1);
    assertParameterType(parameters[0], Parameter::Type::VALUE);
    name = formatHelperFilterName(name, targetField, parameters);

    auto regex_ptr = std::make_shared<RE2>(parameters[0].m_value, RE2::Quiet);
    if (!regex_ptr->ok())
    {
        throw std::runtime_error(fmt::format("[builders::opBuilderHelperRegexNotMatch] "
                                             "Invalid regex: {}",
                                             parameters[0].m_value));
    }

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 = fmt::format("[{}] -> Failure", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            auto resolvedField = event->getValueString(targetField);
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

// path_to_ip: +ip_cidr/192.168.0.0/16
// path_to_ip: +ip_cidr/192.168.0.0/255.255.0.0
base::Expression opBuilderHelperIPCIDR(const std::any& definition)
{
    auto [name, targetField, raw_parameters] = extractDefinition(definition);
    auto parameters = processParameters(raw_parameters);
    assertParametersSize(parameters, 2);
    for (const auto& parameter : parameters)
    {
        assertParameterType(parameter, Parameter::Type::VALUE);
    }

    name = formatHelperFilterName(name, targetField, parameters);

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
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 = fmt::format("[{}] -> Failure: invalid target ip", name);
    const auto failureTrace3 = fmt::format("[{}] -> Failure", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            auto resolvedField = event->getValueString(targetField);
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

// <field>: exists
base::Expression opBuilderHelperExists(const std::any& definition)
{
    auto [name, targetField, rawParameters] = extractDefinition(definition);
    auto parameters = processParameters(rawParameters);
    assertParametersSize(parameters, 0);
    name = formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace = fmt::format("[{}] -> Failure", name);

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

// <field>: not_exists
base::Expression opBuilderHelperNotExists(const std::any& definition)
{
    auto [name, targetField, rawParameters] = extractDefinition(definition);
    auto parameters = processParameters(rawParameters);
    assertParametersSize(parameters, 0);
    name = formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace = fmt::format("[{}] -> Failure", name);

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

//<field>: s_contains/value1/value2/...valueN
base::Expression opBuilderHelperContainsString(const std::any& definition)
{
    auto [name, targetField, rawParameters] = extractDefinition(definition);
    auto parameters = processParameters(rawParameters);
    if (parameters.empty())
    {
        throw std::runtime_error(
            fmt::format("[opBuilderHelperContains] parameters can not be empty"));
    }
    name = formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 = fmt::format("[{}] -> Failure: invalid target array", name);
    const auto failureTrace3 = fmt::format("[{}] -> Failure", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            auto resolvedField = event->getValueString(targetField);
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            auto resolvedArray = event->getValueArrayString(targetField);
            if (!resolvedArray.has_value())
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            for (const auto& parameter : parameters)
            {
                switch (parameter.m_type)
                {
                    case Parameter::Type::REFERENCE:
                    {
                        auto resolvedParameter = event->getValueString(parameter.m_value);
                        if (!resolvedParameter.has_value())
                        {
                            return base::result::makeFailure(event, failureTrace3);
                        }
                        if (std::find(resolvedArray.value().begin(),
                                      resolvedArray.value().end(),
                                      resolvedParameter.value())
                            == resolvedArray.value().end())
                        {
                            return base::result::makeFailure(event, failureTrace3);
                        }
                    }
                    case Parameter::Type::VALUE:
                        if (std::find(resolvedArray.value().begin(),
                                      resolvedArray.value().end(),
                                      parameter.m_value)
                            == resolvedArray.value().end())
                        {
                            return base::result::makeFailure(event, failureTrace3);
                        }
                    default:
                        throw std::runtime_error(fmt::format(
                            "[opBuilderHelperContains] invalid parameter type"));
                }
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace builder::internals::builders
