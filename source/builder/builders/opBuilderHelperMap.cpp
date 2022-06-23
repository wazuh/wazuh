/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderHelperMap.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <variant>

#include <re2/re2.h>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/stringUtils.hpp>

namespace
{

/**
 * @brief Operators supported by the string helpers.
 *
 */
enum class StringOperator
{
    UP,
    LO,
    TR
};

/**
 * @brief Operators supported by the int helpers.
 *
 */
enum class IntOperator
{
    SUM,
    SUB,
    MUL,
    DIV
};

IntOperator strToOp(const helper::base::Parameter& op)
{
    if ("sum" == op.m_value)
    {
        return IntOperator::SUM;
    }
    else if ("sub" == op.m_value)
    {
        return IntOperator::SUB;
    }
    else if ("mul" == op.m_value)
    {
        return IntOperator::MUL;
    }
    else if ("div" == op.m_value)
    {
        return IntOperator::DIV;
    }
    throw std::runtime_error(fmt::format("[builders::strToOp()] operation not support"));
}

/**
 * @brief Tranform the string in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param definition The transformation definition. i.e : field: +s_[up|lo]/value|$ref
 * @param op The operator to use:
 * - `UP`: Upper case
 * - `LO`: Lower case
 * @return base::Expression
 */
base::Expression opBuilderHelperStringTransformation(const std::any& definition,
                                                     StringOperator op)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters = helper::base::processParameters(raw_parameters);
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Depending on rValue type we store the reference or the string value, string in both
    // cases
    std::string rValue {};
    const helper::base::Parameter rightParameter = parameters[0];
    auto rValueType = rightParameter.m_type;
    rValue = rightParameter.m_value;

    // Depending on the operator we return the correct function
    std::function<std::string(const std::string& value)> transformFunction;
    switch (op)
    {
        case StringOperator::UP:
            transformFunction = [](const std::string& value)
            {
                std::string result;
                std::transform(
                    value.begin(), value.end(), std::back_inserter(result), ::toupper);
                return result;
            };
            break;
        case StringOperator::LO:
            transformFunction = [](const std::string& value)
            {
                std::string result;
                std::transform(
                    value.begin(), value.end(), std::back_inserter(result), ::tolower);
                return result;
            };
            break;
        default: break;
    }

    // Tracing messages
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, rightParameter.m_value);
    const auto failureTrace2 = fmt::format("[{}] -> Failure", name);

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // We assert that references exists, checking if the optional from Json getter
            // is empty ot not. Then if is a reference we get the value from the event,
            // otherwise we get the value from the parameter

            // REF

            if (helper::base::Parameter::Type::REFERENCE == rValueType)
            {
                auto resolvedRValue = event->getString(rValue);
                if (!resolvedRValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }

                else
                {
                    auto res = transformFunction(resolvedRValue.value());
                    event->setString(res, targetField);
                    return base::result::makeSuccess(event, successTrace);
                }
            }
            else
            {
                auto res = transformFunction(rValue);
                event->setString(res, targetField);
                return base::result::makeSuccess(event, successTrace);
            }
        });
}

/**
 * @brief Tranform the int in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param definition The transformation definition. i.e : +i_calc/[+|-|*|/]/val|$ref/
 * @param op The operator to use:
 * - `SUM`: Sum
 * - `SUB`: Subtract
 * - `MUL`: Multiply
 * - `DIV`: Divide
 * @return base::Expression
 */
base::Expression
opBuilderHelperIntTransformation(const std::string& targetField,
                                 IntOperator op,
                                 const helper::base::Parameter& rightParameter,
                                 const std::string& name)
{
    // Depending on rValue type we store the reference or the integer value
    std::variant<std::string, int> rValue {};
    auto rValueType = rightParameter.m_type;
    switch (rightParameter.m_type)
    {
        case helper::base::Parameter::Type::VALUE:
            try
            {
                rValue = std::stoi(rightParameter.m_value);
            }
            catch (const std::exception& e)
            {
                std::throw_with_nested(std::runtime_error(
                    fmt::format("[builders::opBuilderHelperIntTransformation()] could "
                                "not convert {} to int",
                                rightParameter.m_value)));
            }
            if (IntOperator::DIV == op && std::get<int>(rValue) == 0)
            {
                throw std::runtime_error(fmt::format(
                    "[builders::opBuilderHelperIntTransformation()] division by zero"));
            }

            break;

        case helper::base::Parameter::Type::REFERENCE:
            rValue = rightParameter.m_value;
            break;

        default:
            throw std::runtime_error(
                fmt::format("[builders::opBuilderHelperIntTransformation()] invalid "
                            "parameter type for {}",
                            rightParameter.m_value));
    }

    // Depending on the operator we return the correct function
    std::function<int(int l, int r)> transformFunction;
    switch (op)
    {
        case IntOperator::SUM:
            transformFunction = [](int l, int r)
            {
                return l + r;
            };
            break;
        case IntOperator::SUB:
            transformFunction = [](int l, int r)
            {
                return l - r;
            };
            break;
        case IntOperator::MUL:
            transformFunction = [](int l, int r)
            {
                return l * r;
            };
            break;
        case IntOperator::DIV:
            transformFunction = [](int l, int r)
            {
                if (0 == r)
                {
                    throw std::runtime_error(
                        fmt::format("[builders::opBuilderHelperIntTransformation()] "
                                    "division by zero"));
                }

                return l / r;
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

    const auto failureTrace4 = fmt::format(
        "[{}] -> Failure: [{}] division by zero", name, rightParameter.m_value);

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // We assert that references exists, checking if the optional from Json getter
            // is empty ot not. Then if is a reference we get the value from the event,
            // otherwise we get the value from the parameter

            auto lValue = event->getInt(targetField);
            if (!lValue.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            if (helper::base::Parameter::Type::REFERENCE == rValueType)
            {
                auto resolvedRValue = event->getInt(std::get<std::string>(rValue));
                if (!resolvedRValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace2);
                }
                else
                {
                    if (IntOperator::DIV == op && resolvedRValue == 0)
                    {
                        return base::result::makeFailure(event, failureTrace4);
                    }
                    auto res = transformFunction(lValue.value(), resolvedRValue.value());
                    event->setInt(res, targetField);
                    return base::result::makeSuccess(event, successTrace);
                }
            }
            else
            {
                auto res = transformFunction(lValue.value(), std::get<int>(rValue));
                event->setInt(res, targetField);
                return base::result::makeSuccess(event, successTrace);
            }
        });
}

} // namespace

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
//*************************************************
//*           String tranform                     *
//*************************************************

// field: +s_up/value|$ref
base::Expression opBuilderHelperStringUP(const std::any& definition)
{
    auto expression = opBuilderHelperStringTransformation(definition, StringOperator::UP);
    return expression;
}

// field: +s_lo/value|$ref
base::Expression opBuilderHelperStringLO(const std::any& definition)
{
    auto expression = opBuilderHelperStringTransformation(definition, StringOperator::LO);
    return expression;
}

// field: +s_trim/[begin | end | both]/char
base::Expression opBuilderHelperStringTrim(const std::any& definition)
{

    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters = helper::base::processParameters(raw_parameters);
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    // Parameter type check
    helper::base::checkParameterType(parameters[0], helper::base::Parameter::Type::VALUE);
    helper::base::checkParameterType(parameters[1], helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Get trim type
    char trimType = parameters[0].m_value == "begin"  ? 's'
                    : parameters[0].m_value == "end"  ? 'e'
                    : parameters[0].m_value == "both" ? 'b'
                                                      : '\0';
    if ('\0' == trimType)
    {
        throw std::runtime_error("Invalid trim type for s_trim operator");
    }

    // get trim char
    std::string trimChar {parameters[1].m_value};
    if (trimChar.size() != 1)
    {
        throw std::runtime_error("Invalid trim char for s_trim operator");
    }

    // Tracing messages
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] not found", name, targetField);
    const auto failureTrace2 =
        fmt::format("[{}] -> Failure: [{}] not found", name, parameters[1].m_value);
    const auto failureTrace3 = fmt::format("[{}] -> Failure", name);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Get field value
            auto resolvedField = event->getString(targetField);

            // Check if field is a string
            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Get string
            std::string strToTrim {resolvedField.value()};

            // Trim
            switch (trimType)
            {
                case 's':
                    // Trim begin
                    strToTrim.erase(0, strToTrim.find_first_not_of(trimChar));
                    break;
                case 'e':
                    // Trim end
                    strToTrim.erase(strToTrim.find_last_not_of(trimChar) + 1);
                    break;
                case 'b':
                    // Trim both
                    strToTrim.erase(0, strToTrim.find_first_not_of(trimChar));
                    strToTrim.erase(strToTrim.find_last_not_of(trimChar) + 1);
                    break;
                default:
                    // if raise here, then the source code is wrong
                    throw std::logic_error("Invalid trim type for s_trim operator");
                    break;
            }

            event->setString(strToTrim, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// <field>: +s_concat/<string1>|$<ref1>/<string2>|$<ref2>
base::Lifter opBuilderHelperStringConcat(const base::DocumentValue& def,
                                         types::TracerFn tr)
{

    // Get field path to concat
    std::string field {json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        // Logical error
        throw std::runtime_error(
            "Invalid parameter type for s_concat operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(parm, '/')};
    if (parametersArr.size() < 3)
    {
        throw std::runtime_error("Invalid number of parameters for s_concat operator");
    }

    // removing first element (helper function name)
    parametersArr.erase(parametersArr.begin());

    // check if parameters aren't empty
    for (auto param : parametersArr)
    {
        if (param.empty())
        {
            throw std::runtime_error("one parameter is an empty string");
        }
    }

    base::Document doc {def};
    std::string successTrace = fmt::format("{} s_concat Success", doc.str());
    std::string failureTrace = fmt::format("{} s_concat Failure", doc.str());

    // Return Lifter
    return [=, parametersArr = std::move(parametersArr), tr = std::move(tr)](
               base::Observable o) {
        // Append rxcpp operation
        return o.map([=, parametersArr = std::move(parametersArr), tr = std::move(tr)](
                         base::Event e) {
            std::string result {};

            for (auto parameter : parametersArr)
            {
                if (parameter.at(0) == REFERENCE_ANCHOR)
                {
                    auto param = json::formatJsonPath(parameter.substr(1));
                    try
                    {
                        auto value = &e->getEventValue(param);
                        if (value && value->IsString())
                        {
                            result.append(value->GetString());
                        }
                        else
                        {
                            tr(failureTrace);
                            return e;
                        }
                    }
                    catch (std::exception& ex)
                    {
                        tr(failureTrace);
                        return e;
                    }
                }
                else
                {
                    result.append(parameter);
                }
            }

            try
            {
                tr(successTrace);
                e->getEvent()->set(
                    field,
                    rapidjson::Value(result.c_str(), e->getEventDocAllocator()).Move());
                return e;
            }
            catch (std::exception& ex)
            {
                return e;
            }
        });
    };
}

//*************************************************
//*           Int tranform                        *
//*************************************************

// field: +i_calc/[+|-|*|/]/val|$ref/
base::Expression opBuilderHelperIntCalc(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters = helper::base::processParameters(raw_parameters);
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);
    auto op = strToOp(parameters[0]);

    auto expression =
        opBuilderHelperIntTransformation(targetField, op, parameters[1], name);
    return expression;
}

//*************************************************
//*           Regex tranform                      *
//*************************************************

// field: +r_ext/_field/regexp/
base::Expression opBuilderHelperRegexExtract(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters = helper::base::processParameters(raw_parameters);
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    // Parameter type check
    helper::base::checkParameterType(parameters[0],
                                     helper::base::Parameter::Type::REFERENCE);
    helper::base::checkParameterType(parameters[1], helper::base::Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    std::string map_field {parameters[0].m_value};

    auto regex_ptr {std::make_shared<RE2>(parameters[1].m_value)};
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[1].m_value + "'. "
                                + regex_ptr->error();
        throw std::runtime_error(err);
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
            // TODO Remove try catch
            auto resolvedField = event->getString(map_field);

            if (!resolvedField.has_value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            std::string match;
            if (RE2::PartialMatch(resolvedField.value(), *regex_ptr, &match))
            {
                event->setString(match, targetField);

                return base::result::makeSuccess(event, successTrace);
            }
            return base::result::makeFailure(event, failureTrace2);
        });
}

base::Expression opBuilderHelperAppendString(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(rawParameters);
    if (parameters.empty())
    {
        throw std::runtime_error(
            fmt::format("[opBuilderHelperAppend] parameters can not be empty"));
    }
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);

    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: parameter reference not found", name);

    // Return result
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event>
        {
            for (const auto& parameter : parameters)
            {
                switch (parameter.m_type)
                {
                    case helper::base::Parameter::Type::REFERENCE:
                    {
                        auto value = event->getString(parameter.m_value);
                        if (!value)
                        {
                            return base::result::makeFailure(event, failureTrace1);
                        }

                        event->appendString(value.value(), targetField);
                    }
                    break;
                    case helper::base::Parameter::Type::VALUE:
                    {
                        event->appendString(parameter.m_value, targetField);
                    }
                    break;
                    default:
                        throw std::runtime_error(
                            fmt::format("{}: unexpected parameter type [{}]",
                                        name,
                                        parameter.m_value));
                }
            }
            return base::result::makeSuccess(event, successTrace);
        });
}

//*************************************************
//*             JSON tranform                     *
//*************************************************

// <key>: +json_delete_fields/<string1>|<$reference1>/<string2>|<$reference2>
base::Lifter opBuilderHelperJsonDeleteFields(const base::DocumentValue& def,
                                             types::TracerFn tr)
{
    // Get field key where to store the quantity of deleted fieldS
    std::string key {json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        // Logical error
        throw std::runtime_error(
            "Invalid parameter type for delete_field operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(parm, '/')};
    if (parametersArr.size() < 2)
    {
        throw std::runtime_error(
            "Invalid number of parameters for delete_field operator");
    }

    // removing first element (helper function name)
    parametersArr.erase(parametersArr.begin());

    // check if parameters aren't empty
    for (auto param : parametersArr)
    {
        if (param.empty())
        {
            throw std::runtime_error("one parameter is an empty string");
        }
    }

    base::Document doc {def};
    std::string successTrace = fmt::format("{} json_delete_fields Success", doc.str());
    std::string failureTrace = fmt::format("{} json_delete_fields Failure", doc.str());

    // Return Lifter
    return [=, parametersArr = std::move(parametersArr), tr = std::move(tr)](
               base::Observable o) {
        // Append rxcpp operation
        return o.map([=, parametersArr = std::move(parametersArr), tr = std::move(tr)](
                         base::Event e) {
            int deletedFields = 0;
            for (auto parameter : parametersArr)
            {
                std::string field = "";
                if (parameter.at(0) == REFERENCE_ANCHOR)
                {
                    try
                    {
                        auto value = &e->getEventValue(json::formatJsonPath(parameter.substr(1)));
                        if (value && value->IsString())
                        {
                            field = value->GetString();
                        }
                        else
                        {
                            tr(failureTrace);
                            continue;
                        }
                    }
                    catch (std::exception& ex)
                    {
                        tr(failureTrace + ": " + ex.what());
                    }
                }
                else
                {
                    field = json::formatJsonPath(parameter);
                }

                if (e->getEvent()->m_doc.EraseMember(field.c_str()))
                    ++deletedFields;
            }

            // Create and add integer to base::Event
            try
            {
                e->setEventValue(key, rapidjson::Value(deletedFields).Move());
                tr(successTrace);
            }
            catch (std::exception& ex)
            {
                tr(failureTrace + ": " + ex.what());
            }

            return e;
        });
    };
}

} // namespace builder::internals::builders
