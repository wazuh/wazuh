/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderHelperFilter.hpp"

#include <optional>
#include <string>
#include <tuple>

#include <fmt/format.h>
#include <re2/re2.h>

#include "syntax.hpp"
#include <utils/ipUtils.hpp>
#include <utils/stringUtils.hpp>

namespace
{

using opString = std::optional<std::string>;
using builder::internals::syntax::REFERENCE_ANCHOR;

/**
 * @brief Get the Comparator operator, and the value to compare
 * or the reference to value to compare
 *
 * @param definition The JSON definition of the operator
 * @return std::tuple<std::string, opString, opString> the operator,
 * the value to compare and the reference to value to compare (if exists)
 * @throw std::runtime_error if the number of parameters is not valid
 * @throw std::logic_error if the json node is not valid definition for the
 * helper function
 */
std::tuple<std::string, opString, opString>
getCompOpParameter(std::any definition)
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

    // Parse parameters
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    std::optional<std::string> refValue {};
    std::optional<std::string> value {};

    if (parameters[1][0] == REFERENCE_ANCHOR)
    {
        refValue = json::Json::formatJsonPath(parameters[1].substr(1));
    }
    else
    {
        value = parameters[1];
    }

    return {field, refValue, value};
}
} // namespace

namespace builder::internals::builders
{

// <field>: exists
base::Expression opBuilderHelperExists(std::any definition)
{

    std::string field;
    try
    {
        // Get Field path and arguments of the helper function
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get Field path
        field = std::get<0>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    const auto helperName = fmt::format("{}: +exists", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (e->exists(field))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: not_exists
base::Expression opBuilderHelperNotExists(std::any definition)
{
    std::string field;
    try
    {
        // Get Field path and arguments of the helper function
        const auto helperTuple =
        std::any_cast<std::tuple<std::string, std::vector<std::string>>>(
            definition);

        // Get Field path
        field = std::get<0>(helperTuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(
            std::runtime_error("[builders::helperFilterBuilder(definition)] "
                               "Received unexpected arguments."));
    }

    const auto helperName = fmt::format("{}: +exists", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (!e->exists(field))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

//*************************************************
//*           String filters                      *
//*************************************************

bool opBuilderHelperStringComparison(const std::string & key,
                                     char op,
                                     base::Event e,
                                     std::optional<std::string> refValue,
                                     std::optional<std::string> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document
    // class
    // TODO Update to use proper references
    // TODO Following the philosofy of doing as much as possible in the build
    // phase this function should
    //      return another function used by the filter, instead of deciding the
    //      operator on runtime
    // TODO string and int could be merged if they used the same comparators
    // Get value to compare
    std::optional<std::string> fieldToCompare {};
    try
    {
        fieldToCompare = e->getValueString(key);
    }
    catch (std::exception& ex)
    {
        // TODO Check exception type
        return false;
    }

    if (!fieldToCompare.has_value())
    {
        return false;
    }

    // get str to compare
    if (refValue.has_value())
    {
        // Get reference to json event
        // TODO Remove try catch or if nullptr after fix get method of document
        // class
        // TODO Update to use proper references
        std::optional<std::string> refValueToCheck {};
        try
        {
            refValueToCheck = e->getValueString(refValue.value());
        }
        catch (std::exception& ex)
        {
            // TODO Check exception type
            return false;
        }

        if (!refValueToCheck.has_value())
        {
            return false;
        }
        value = std::optional<std::string> {refValueToCheck};
    }

    // String operation
    switch (op)
    {
        case '=':
            return fieldToCompare.value() == value.value();
        case '!':
            return fieldToCompare.value() != value.value();
        case '>':
            return fieldToCompare.value() > value.value();
        // case '>=':
        case 'g':
            return fieldToCompare.value() >= value.value();
        case '<':
            return fieldToCompare.value() < value.value();
        // case '<=':
        case 'l':
            return fieldToCompare.value() <= value.value();
        default:
            // if raise here, then the logic is wrong
            throw std::invalid_argument("Invalid operator: '" +
                                        std::string {op} + "' ");
    }

    return false;
}

// <field>: +s_eq/<value>
base::Expression opBuilderHelperStringEQ(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_eq", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, '=', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: +s_ne/<value>
base::Expression opBuilderHelperStringNE(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_ne", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, '!', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: +s_gt/<value>|$<ref>
base::Expression opBuilderHelperStringGT(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_gt", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, '>', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: +s_ge/<value>|$<ref>
base::Expression opBuilderHelperStringGE(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_ge", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, 'g', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: +s_lt/<value>|$<ref>
base::Expression opBuilderHelperStringLT(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_lt", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, '<', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// <field>: +s_le/<value>|$<ref>
base::Expression opBuilderHelperStringLE(std::any definition)
{
    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +s_le", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperStringComparison(field, 'l', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

//*************************************************
//*               Int filters                     *
//*************************************************

bool opBuilderHelperIntComparison(const std::string & field,
                                  char op,
                                  base::Event e,
                                  std::optional<std::string> refValue,
                                  std::optional<int> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document
    // class
    // TODO Update to use proper references
    // TODO Same as opBuilderHelperStringComparison
    // Get value to compare
    std::optional<int> fieldValue {};
    try
    {
        fieldValue = e->getValueInt(field);
    }
    catch (std::exception& ex)
    {
        // TODO Check exception type
        return false;
    }

    if (!fieldValue.has_value())
    {
        return false;
    }

    // get str to compare
    if (refValue.has_value())
    {
        // Get reference to json event
        // TODO Remove try catch or if nullptr after fix get method of document
        // class
        // TODO update to use proper references
        std::optional<int>  refValueToCheck {};
        try
        {
            refValueToCheck = e->getValueInt(refValue.value());
        }
        catch (std::exception& ex)
        {
            // TODO Check exception type
            return false;
        }

        if (!refValueToCheck.has_value())
        {
            return false;
        }
        value = std::optional<int> {refValueToCheck};
    }

    // Int operation
    switch (op)
    {
        // case '==':
        case '=': return fieldValue.value() == value.value();
        // case '!=':
        case '!': return fieldValue.value() != value.value();
        case '>': return fieldValue.value() > value.value();
        // case '>=':
        case 'g': return fieldValue.value() >= value.value();
        case '<': return fieldValue.value() < value.value();
        // case '<=':
        case 'l': return fieldValue.value() <= value.value();

        default:
            // if raise here, then the source code is wrong
            throw std::invalid_argument("Invalid operator: '" +
                                        std::string {op} + "' ");
    }

    return false;
}

// field: +i_eq/int|$ref/
base::Expression opBuilderHelperIntEqual(std::any definition)
{
    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_eq", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, '=', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// field: +i_ne/int|$ref/
base::Expression opBuilderHelperIntNotEqual(std::any definition)
{

    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_ne", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, '!', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// field: +i_lt/int|$ref/
base::Expression opBuilderHelperIntLessThan(std::any definition)
{

    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_lt", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, '<', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// field: +i_le/int|$ref/
base::Expression opBuilderHelperIntLessThanEqual(std::any definition)
{

    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_le", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, 'l', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// field: +i_gt/int|$ref/
base::Expression opBuilderHelperIntGreaterThan(std::any definition)
{

    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_gt", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, '>', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

// field: +i_ge/int|$ref/
base::Expression opBuilderHelperIntGreaterThanEqual(std::any definition)
{

    auto [field, refValue, valuestr] {getCompOpParameter(definition)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    const auto helperName = fmt::format("{}: +i_ge", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                if (opBuilderHelperIntComparison(field, 'g', e, refValue, value))
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            });
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +r_match/regexp
base::Expression opBuilderHelperRegexMatch(std::any definition)
{

    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +r_match", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    auto regex_ptr = std::make_shared<RE2>(value.value(), RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + value.value() +
                                "'. " + regex_ptr->error();
        throw std::runtime_error(err);
    }

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                // TODO Remove try catch
                // TODO Update to use proper reference
                std::optional<std::string> field_str {};
                try
                {
                    field_str = e->getValueString(field);
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                    return  base::result::makeFailure(e, failureTrace);
                }

                if (field_str.has_value())
                {
                    if (RE2::PartialMatch(field_str.value(), *regex_ptr))
                    {
                        return base::result::makeSuccess(e, successTrace);
                    }
                    else
                    {
                        return  base::result::makeFailure(e, failureTrace);
                    }
                }
                return  base::result::makeFailure(e, failureTrace);
            });

}

// field: +r_not_match/regexp
base::Expression opBuilderHelperRegexNotMatch(std::any definition)
{

    auto [field, refValue, value] {getCompOpParameter(definition)};

    const auto helperName = fmt::format("{}: +r_not_match", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    auto regex_ptr = std::make_shared<RE2>(value.value(), RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + value.value() +
                                "'. " + regex_ptr->error();
        throw std::runtime_error(err);
    }

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
                // TODO Remove try catch
                // TODO Update to use proper reference
                std::optional<std::string> field_str {};
                try
                {
                    field_str = e->getValueString(field);
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                    return  base::result::makeFailure(e, failureTrace);
                }

                if (field_str.has_value())
                {
                    if (!RE2::PartialMatch(field_str.value(), *regex_ptr))
                    {
                        return base::result::makeSuccess(e, successTrace);
                    }
                    else
                    {
                        return  base::result::makeFailure(e, failureTrace);
                    }
                }
                return  base::result::makeFailure(e, failureTrace);
            });
}

//*************************************************
//*               IP filters                     *
//*************************************************

// path_to_ip: +ip_cidr/192.168.0.0/16
// path_to_ip: +ip_cidr/192.168.0.0/255.255.0.0
base::Expression opBuilderHelperIPCIDR(std::any definition)
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

    //Checks number of parameters
    if (parameters.size() != 3)
    {
        throw std::runtime_error("Invalid number of parameters");
    }
    else if (parameters[2].empty())
    {
        throw std::runtime_error("The network can't be empty");
    }
    else if (parameters[1].empty())
    {
        throw std::runtime_error("The cidr can't be empty");
    }

    uint32_t network {};
    try
    {
        network = utils::ip::IPv4ToUInt(parameters[1]);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error("Invalid IPv4 address: " + network);
    }

    uint32_t mask {};
    try
    {
        mask = utils::ip::IPv4MaskUInt(parameters[2]);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error("Invalid IPv4 mask: " + mask);
    }

    uint32_t net_lower {network & mask};
    uint32_t net_upper {net_lower | (~mask)};

    const auto helperName = fmt::format("{}: +ip_cidr", field);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", helperName);
    const auto failureTrace = fmt::format("[{}] -> Failure", helperName);

    // Return result
    return base::Term<base::EngineOp>::create(helperName,
            [=](base::Event e)->base::result::Result<base::Event>
            {
            // TODO Remove try catch
            // TODO Update to use proper reference
            std::optional<std::string> field_str {};
            try
            {
                field_str = e->getValueString(field);
            }
            catch (std::exception& ex)
            {
                return  base::result::makeFailure(e, failureTrace);
            }
            if (field_str.has_value())
            {
                uint32_t ip {};
                try
                {
                    ip = utils::ip::IPv4ToUInt(field_str.value());
                }
                catch (std::exception& ex)
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
                if (ip >= net_lower && ip <= net_upper)
                {
                    return base::result::makeSuccess(e, successTrace);
                }
                else
                {
                    return  base::result::makeFailure(e, failureTrace);
                }
            }
            return  base::result::makeFailure(e, failureTrace);
        });
}

} // namespace builder::internals::builders
