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

#include <re2/re2.h>

#include "syntax.hpp"
#include <utils/stringUtils.hpp>

namespace
{

/**
 * @brief Tranform the string in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param field The field path to transform
 * @param op The operator to use:
 * - `u`: Upper case
 * - `l`: Lower case
 * @param e The base::Event that contains the field to transform
 * @param refValue The reference to the value user as source of the
 * transformation
 * @param value The value to use as source of the transformation
 * @return base::result::Result<base::Event> The base::result::Result<base::Event>
 * with the field transformed
 * @throw std::logic_error if the `op` is not valid
 */
base::result::Result<base::Event> opBuilderHelperStringTransformation(const std::string field,
                                          char op,
                                          base::Event e,
                                          std::optional<std::string> refValue,
                                          std::optional<std::string> value)
{

    const auto helperName = fmt::format("{}: +s_up", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Get src field
    if (refValue.has_value())
    {
        // Get reference to json base::Event
        // TODO Remove try catch or if nullptr after fix get method of document
        // class
        // TODO Update to use proper reference
        std::optional<std::string> refValueToCheck {};
        try
        {
            refValueToCheck = e->getString(refValue.value());
        }
        catch (std::exception& ex)
        {
            // TODO Check exception type
            return base::result::makeFailure(e, failureTrace);
        }

        if (!refValueToCheck.has_value())
        {
            return base::result::makeFailure(e, failureTrace);
        }
        // If reache here, the refValueToCheck is a string
        value = std::optional<std::string> {refValueToCheck};
    }

    // Operation
    switch (op)
    {
        case 'u':
            // Upper case
            std::transform(value.value().begin(),
                           value.value().end(),
                           value.value().begin(),
                           ::toupper);
            break;
        case 'l':
            // Lower case
            std::transform(value.value().begin(),
                           value.value().end(),
                           value.value().begin(),
                           ::tolower);
            break;
        default:
            // if raise here, then the source code is wrong
            throw std::logic_error("Invalid string transformation operator");
            break;
    }

    json::Json jsonValue;
    jsonValue.setString(value.value());

    // Create and add string to base::Event
    try
    {
        e->set(field, jsonValue);
    }
    catch (std::exception& ex)
    {
        // TODO Check exception type
        return base::result::makeFailure(e, failureTrace);
    }

    return base::result::makeSuccess(e, successTrace);
}

/**
 * @brief Tranform the int in `field` path in the base::Event `e` according to the
 * `op` definition and the `value` or the `refValue`
 *
 * @param field The field path to transform
 * @param op The operator to use:
 * - `sum`: Sum
 * - `sub`: Subtract
 * - `mul`: Multiply
 * - `div`: Divide
 * @param e The base::Event that contains the field to transform
 * @param refValue The reference to the value user as source of the
 * transformation
 * @param value The value to use as source of the transformation
 * @return base::result::Result<base::Event> The base::result::Result<base::Event>
 * with the field transformed
 * @throw std::logic_error if the `op` is not valid
 */
base::result::Result<base::Event> opBuilderHelperIntTransformation(const std::string field,
                                       std::string op,
                                       base::Event e,
                                       std::optional<std::string> refValue,
                                       std::optional<int> value)
{

    const auto helperName = fmt::format("{}: +s_up", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // TODO Remove try catch or if nullptr after fix get method of document
    // class Get value to compare
    std::optional<int> fieldValue {};
    try
    {
        fieldValue = e->getInt(field);
    }
    catch (std::exception& ex)
    {
        // TODO Check exception type
        return base::result::makeFailure(e, failureTrace);
    }

    if (!fieldValue.has_value())
    {
        return base::result::makeFailure(e, failureTrace);
    }

    if (refValue.has_value())
    {
        // Get reference to json base::Event
        // TODO Remove try catch or if nullptr after fix get method of document
        // class
        std::optional<int> refValueToCheck {};
        try
        {
            refValueToCheck = e->getInt(refValue.value());
        }
        catch (std::exception& ex)
        {
            // TODO Check exception type
            return base::result::makeFailure(e, failureTrace);
        }

        if (!refValueToCheck.has_value())
        {
            return base::result::makeFailure(e, failureTrace);
        }
        value = std::optional<int> {refValueToCheck};
    }

    // Operation
    // TODO: change to switch for performance
    if (op == "sum")
    {
        value = fieldValue.value() + value.value();
    }
    else if (op == "sub")
    {
        value = fieldValue.value() - value.value();
    }
    else if (op == "mul")
    {
        value = fieldValue.value() * value.value();
    }
    else if (op == "div")
    {
        if (value.value() == 0)
        {
            return base::result::makeFailure(e, failureTrace);
        }
        value = fieldValue.value() / value.value();
    }
    else
    {
        return base::result::makeFailure(e, failureTrace);
    }

    json::Json jsonValue;
    jsonValue.setInt(value.value());

    // Create and add string to base::Event
    try
    {
        e->set(field, jsonValue);
    }
    catch (std::exception& ex)
    {
        // TODO Check exception type
        return base::result::makeFailure(e, failureTrace);
    }
    return base::result::makeSuccess(e, successTrace);
}

} // namespace

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
//*************************************************
//*           String tranform                     *
//*************************************************

// <field>: +s_up/<str>|$<ref>
base::Expression opBuilderHelperStringUP(std::any definition)
{
    // Get Field path and arguments of the helper function
    std::string field;
    std::vector<std::string> parameters;

    try
    {
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get field path
        field = std::get<0>(helperTuple);

        // Get parameters of the helper function
        parameters = std::get<1>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    if (parameters.size() != 2)
    {
        throw std::runtime_error(
            "Invalid number of parameters for s_up operator");
    }

    std::optional<std::string> refExpStr {};
    std::optional<std::string> expectedStr {};

    // Check if is a reference to json base::Event
    if (parameters[1][0] == REFERENCE_ANCHOR)
    {
        refExpStr = json::Json::formatJsonPath(parameters[1].substr(1));
    }
    else
    {
        expectedStr = parameters[1];
    }

    const auto helperName = fmt::format("{}: +s_up", field);

    // Return Term
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                return opBuilderHelperStringTransformation(field, 'u', e, refExpStr, expectedStr);
            });

}

// <field>: +s_lo/<str>|$<ref>
base::Expression opBuilderHelperStringLO(std::any definition)
{
    // Get Field path and arguments of the helper function
    std::string field;
    std::vector<std::string> parameters;

    try
    {
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get field path
        field = std::get<0>(helperTuple);

        // Get parameters of the helper function
        parameters = std::get<1>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    if (parameters.size() != 2)
    {
        throw std::runtime_error(
            "Invalid number of parameters for s_lo operator");
    }

    std::optional<std::string> refExpStr {};
    std::optional<std::string> expectedStr {};

    // Check if is a reference to json base::Event
    if (parameters[1][0] == REFERENCE_ANCHOR)
    {
        refExpStr = json::Json::formatJsonPath(parameters[1].substr(1));
    }
    else
    {
        expectedStr = parameters[1];
    }

    const auto helperName = fmt::format("{}: +s_lo", field);

    // Return Term
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                return opBuilderHelperStringTransformation(field, 'l', e, refExpStr, expectedStr);
            });

}

// <field>: +s_trim/[begin | end | both]/char
base::Expression opBuilderHelperStringTrim(std::any definition)
{
    // Get Field path and arguments of the helper function
    std::string field;
    std::vector<std::string> parameters;

    try
    {
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get field path
        field = std::get<0>(helperTuple);

        // Get parameters of the helper function
        parameters = std::get<1>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    if (parameters.size() != 3)
    {
        throw std::runtime_error(
            "Invalid number of parameters for s_trim operator");
    }

    // Get trim type
    char trimType = parameters[1] == "begin"  ? 's'
                    : parameters[1] == "end"  ? 'e'
                    : parameters[1] == "both" ? 'b'
                                                 : '\0';
    if (trimType == '\0')
    {
        throw std::runtime_error("Invalid trim type for s_trim operator");
    }

    // get trim char
    std::string trimChar {parameters[2]};
    if (trimChar.size() != 1)
    {
        throw std::runtime_error("Invalid trim char for s_trim operator");
    }

    const auto helperName = fmt::format("{}: +s_trim", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return Term
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                // Shoulbe short after refact, witout try catch
                // Get field value
                std::optional<std::string> fieldValue {};
                try
                {
                    fieldValue = e->getString(field);
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                    return  base::result::makeFailure(e, failureTrace);
                }

                // Check if field is a string
                if (!fieldValue.has_value())
                {
                    return  base::result::makeFailure(e, failureTrace);
                }

                // Get string
                std::string strToTrim {fieldValue.value()};

                // Trim
                switch (trimType)
                {
                    case 's':
                        // Trim begin
                        strToTrim.erase(0,
                                        strToTrim.find_first_not_of(trimChar));
                        break;
                    case 'e':
                        // Trim end
                        strToTrim.erase(strToTrim.find_last_not_of(trimChar) +
                                        1);
                        break;
                    case 'b':
                        // Trim both
                        strToTrim.erase(0,
                                        strToTrim.find_first_not_of(trimChar));
                        strToTrim.erase(strToTrim.find_last_not_of(trimChar) +
                                        1);
                        break;
                    default:
                        // if raise here, then the source code is wrong
                        throw std::logic_error(
                            "Invalid trim type for s_trim operator");
                        break;
                }

                json::Json jsonValue;
                jsonValue.setString(strToTrim);

                // Update base::Event
                try
                {
                    e->set(field, jsonValue);
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                    return  base::result::makeFailure(e, failureTrace);
                }

                return base::result::makeSuccess(e, successTrace);
            });

}

//*************************************************
//*           Int tranform                        *
//*************************************************

// field: +i_calc/[+|-|*|/]/val|$ref/
base::Expression opBuilderHelperIntCalc(std::any definition)
{
    // Get Field path and arguments of the helper function
    std::string field;
    std::vector<std::string> parameters;

    try
    {
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get field path
        field = std::get<0>(helperTuple);

        // Get parameters of the helper function
        parameters = std::get<1>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    if (parameters.size() != 3)
    {
        throw std::runtime_error("Invalid parameters");
    }

    std::optional<std::string> refValue {};
    std::optional<int> value {};
    std::string op {parameters[1]};

    // TODO Parametrize this
    if (op != "sum" && op != "sub" && op != "mul" && op != "div")
    {
        throw std::runtime_error("Invalid operator");
    }

    if (op == "div")
    {
        if (parameters[2] == "0")
        {
            throw std::runtime_error("Division by zero");
        }
    }

    if (parameters[2][0] == REFERENCE_ANCHOR)
    {
        // Check case `+i_calc/op/$`
        refValue =
            json::Json::formatJsonPath(parameters[2].substr(1, std::string::npos));
    }
    else
    {
        value = std::stoi(parameters[2]);
    }

    const auto helperName = fmt::format("{}: +i_calc", field);

    // Return Term
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                return opBuilderHelperIntTransformation(field, op, e, refValue, value);
            });

}

//*************************************************
//*           Regex tranform                      *
//*************************************************

// field: +r_ext/_field/regexp/
base::Expression opBuilderHelperRegexExtract(std::any definition)
{
    // Get Field path and arguments of the helper function
    std::string field;
    std::vector<std::string> parameters;

    try
    {
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get field path
        field = std::get<0>(helperTuple);

        // Get parameters of the helper function
        parameters = std::get<1>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    if (parameters.size() != 3)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    std::string map_field {json::Json::formatJsonPath(parameters[1])};

    auto regex_ptr {std::make_shared<RE2>(parameters[2])};
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[2] +
                                "'. " + regex_ptr->error();
        throw std::runtime_error(err);
    }

    const auto helperName = fmt::format("{}: +r_ext", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return Term
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                // TODO Remove try catch
                    std::optional<std::string> field_str {};
                    try
                    {
                        field_str = e->getString(field);
                    }
                    catch (std::exception& ex)
                    {
                        // TODO Check exception type
                        return base::result::makeFailure(e, failureTrace);
                    }
                    if (field_str.has_value())
                    {
                        std::string match;
                        if (RE2::PartialMatch(
                                field_str.value(), *regex_ptr, &match))
                        {
                            json::Json jsonValue;
                            jsonValue.setString(match);

                            // Create and add string to base::Event
                            try
                            {
                                e->set(map_field, jsonValue);
                            }
                            catch (std::exception& ex)
                            {
                                // TODO Check exception type
                                return base::result::makeFailure(e, failureTrace);
                            }

                            return base::result::makeSuccess(e, successTrace);
                        }
                    }
                    return base::result::makeFailure(e, failureTrace);
            });

}

} // namespace builder::internals::builders
