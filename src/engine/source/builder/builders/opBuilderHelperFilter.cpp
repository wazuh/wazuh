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
using builder::internals::types::DocumentValue;

/**
 * @brief Get the Comparator operator, and the value to compare
 * or the reference to value to compare
 *
 * @param def The JSON definition of the operator
 * @return std::tuple<std::string, opString, opString> the operator,
 * the value to compare and the reference to value to compare (if exists)
 * @throw std::runtime_error if the number of parameters is not valid
 * @throw std::logic_error if the json node is not valid definition for the
 * helper function
 */
std::tuple<std::string, opString, opString>
getCompOpParameter(const DocumentValue &def)
{
    // Get destination path
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    // Get function helper
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::logic_error("Invalid operator definition");
    }
    std::string rawValue {def.MemberBegin()->value.GetString()};

    // Parse parameters
    std::vector<std::string> parameters {utils::string::split(rawValue, '/')};
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    std::optional<std::string> refValue {};
    std::optional<std::string> value {};

    if (parameters[1][0] == REFERENCE_ANCHOR)
    {
        refValue = json::formatJsonPath(parameters[1].substr(1));
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
types::Lifter opBuilderHelperExists(const types::DocumentValue &def,
                                    types::TracerFn tr)
{
    // Get Field path to check
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Check parameters
    std::vector<std::string> parameters {
        utils::string::split(def.MemberBegin()->value.GetString(), '/')};
    if (parameters.size() != 1)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    // Tracing
    std::string successTrace = fmt::format("{{{}: +exists}} Condition Success",
                                           def.MemberBegin()->name.GetString());
    std::string failureTrace = fmt::format("{{{}: +exists}} Condition Failure",
                                           def.MemberBegin()->name.GetString());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (e->exists(field))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: not_exists
types::Lifter opBuilderHelperNotExists(const types::DocumentValue &def,
                                       types::TracerFn tr)
{
    // Get Field path to check
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    std::vector<std::string> parameters =
        utils::string::split(def.MemberBegin()->value.GetString(), '/');
    if (parameters.size() != 1)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    // Tracing
    std::string successTrace =
        fmt::format("{{{}: +not_exists}} Condition Success",
                    def.MemberBegin()->name.GetString());
    std::string failureTrace =
        fmt::format("{{{}: +not_exists}} Condition Failure",
                    def.MemberBegin()->name.GetString());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (!e->exists(field))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

//*************************************************
//*           String filters                      *
//*************************************************

bool opBuilderHelperStringComparison(const std::string key,
                                     char op,
                                     types::Event &e,
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
    const rapidjson::Value *fieldToCompare {};
    try
    {
        fieldToCompare = &e->get(key);
    }
    catch (std::exception &ex)
    {
        // TODO Check exception type
        return false;
    }

    if (fieldToCompare == nullptr || !fieldToCompare->IsString())
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
        const rapidjson::Value *refValueToCheck {};
        try
        {
            refValueToCheck = &e->get(refValue.value());
        }
        catch (std::exception &ex)
        {
            // TODO Check exception type
            return false;
        }

        if (refValueToCheck == nullptr || !refValueToCheck->IsString())
        {
            return false;
        }
        value = std::string {refValueToCheck->GetString()};
    }

    // String operation
    switch (op)
    {
        case '=':
            return std::string {fieldToCompare->GetString()} == value.value();
        case '!':
            return std::string {fieldToCompare->GetString()} != value.value();
        case '>':
            return std::string {fieldToCompare->GetString()} > value.value();
        // case '>=':
        case 'g':
            return std::string {fieldToCompare->GetString()} >= value.value();
        case '<':
            return std::string {fieldToCompare->GetString()} < value.value();
        // case '<=':
        case 'l':
            return std::string {fieldToCompare->GetString()} <= value.value();
        default:
            // if raise here, then the logic is wrong
            throw std::invalid_argument("Invalid operator: '" +
                                        std::string {op} + "' ");
    }

    return false;
}

// <field>: s_eq/<value>
types::Lifter opBuilderHelperStringEQ(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catch, return false
                if (opBuilderHelperStringComparison(
                        key, '=', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: s_ne/<value>
types::Lifter opBuilderHelperStringNE(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperStringComparison(
                        key, '!', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: s_gt/<value>|$<ref>
types::Lifter opBuilderHelperStringGT(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperStringComparison(
                        key, '>', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: s_ge/<value>|$<ref>
types::Lifter opBuilderHelperStringGE(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperStringComparison(
                        key, 'g', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: s_lt/<value>|$<ref>
types::Lifter opBuilderHelperStringLT(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperStringComparison(
                        key, '<', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// <field>: s_le/<value>|$<ref>
types::Lifter opBuilderHelperStringLE(const types::DocumentValue &def,
                                      types::TracerFn tr)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperStringComparison(
                        key, 'l', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

//*************************************************
//*               Int filters                     *
//*************************************************

bool opBuilderHelperIntComparison(const std::string field,
                                  char op,
                                  types::Event &e,
                                  std::optional<std::string> refValue,
                                  std::optional<int> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document
    // class
    // TODO Update to use proper references
    // TODO Same as opBuilderHelperStringComparison
    // Get value to compare
    const rapidjson::Value *fieldValue {};
    try
    {
        fieldValue = &e->get(field);
    }
    catch (std::exception &ex)
    {
        // TODO Check exception type
        return false;
    }

    if (fieldValue == nullptr || !fieldValue->IsInt())
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
        const rapidjson::Value *refValueToCheck {};
        try
        {
            refValueToCheck = &e->get(refValue.value());
        }
        catch (std::exception &ex)
        {
            // TODO Check exception type
            return false;
        }

        if (refValueToCheck == nullptr || !refValueToCheck->IsInt())
        {
            return false;
        }
        value = refValueToCheck->GetInt();
    }

    // Int operation
    switch (op)
    {
        // case '==':
        case '=': return fieldValue->GetInt() == value.value();
        // case '!=':
        case '!': return fieldValue->GetInt() != value.value();
        case '>': return fieldValue->GetInt() > value.value();
        // case '>=':
        case 'g': return fieldValue->GetInt() >= value.value();
        case '<': return fieldValue->GetInt() < value.value();
        // case '<=':
        case 'l': return fieldValue->GetInt() <= value.value();

        default:
            // if raise here, then the source code is wrong
            throw std::invalid_argument("Invalid operator: '" +
                                        std::string {op} + "' ");
    }

    return false;
}

// field: +i_eq/int|$ref/
types::Lifter opBuilderHelperIntEqual(const types::DocumentValue &def,
                                      types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (opBuilderHelperIntComparison(
                        field, '=', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// field: +i_ne/int|$ref/
types::Lifter opBuilderHelperIntNotEqual(const types::DocumentValue &def,
                                         types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                if (opBuilderHelperIntComparison(
                        field, '!', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// field: +i_lt/int|$ref/
types::Lifter opBuilderHelperIntLessThan(const types::DocumentValue &def,
                                         types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                if (opBuilderHelperIntComparison(
                        field, '<', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// field: +i_le/int|$ref/
types::Lifter opBuilderHelperIntLessThanEqual(const types::DocumentValue &def,
                                              types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                if (opBuilderHelperIntComparison(
                        field, 'l', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// field: +i_gt/int|$ref/
types::Lifter opBuilderHelperIntGreaterThan(const types::DocumentValue &def,
                                            types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                if (opBuilderHelperIntComparison(
                        field, '>', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

// field: +i_ge/int|$ref/
types::Lifter
opBuilderHelperIntGreaterThanEqual(const types::DocumentValue &def,
                                   types::TracerFn tr)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value =
        valuestr.has_value() ? std::optional<int> {std::stoi(valuestr.value())}
                             : std::nullopt;

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                if (opBuilderHelperIntComparison(
                        field, 'g', e, refValue, value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +r_match/regexp
types::Lifter opBuilderHelperRegexMatch(const types::DocumentValue &def,
                                        types::TracerFn tr)
{
    // Get field
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    std::string value {def.MemberBegin()->value.GetString()};

    std::vector<std::string> parameters {utils::string::split(value, '/')};
    if (parameters.size() != 2)
    {
        throw std::invalid_argument("Wrong number of arguments passed");
    }

    auto regex_ptr = std::make_shared<RE2>(parameters[1], RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[1] +
                                "'. " + regex_ptr->error();
        throw std::runtime_error(err);
    }

    // Return Lifter
    return [field, regex_ptr](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                // TODO Update to use proper reference
                const rapidjson::Value *field_str {};
                try
                {
                    field_str = &e->get(field);
                }
                catch (std::exception &ex)
                {
                    // TODO Check exception type
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    return (
                        RE2::PartialMatch(field_str->GetString(), *regex_ptr));
                }
                return false;
            });
    };
}

// field: +r_not_match/regexp
types::Lifter opBuilderHelperRegexNotMatch(const types::DocumentValue &def,
                                           types::TracerFn tr)
{
    // Get field
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    std::string value = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(value, '/');
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    auto regex_ptr = std::make_shared<RE2>(parameters[1], RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[1] +
                                "'. " + regex_ptr->error();
        throw std::runtime_error(err);
    }

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                // TODO Update to use proper reference
                const rapidjson::Value *field_str {};
                try
                {
                    field_str = &e->get(field);
                }
                catch (std::exception &ex)
                {
                    // TODO Check exception type
                    tr(failureTrace);
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    if (!RE2::PartialMatch(field_str->GetString(), *regex_ptr))
                    {
                        tr(successTrace);
                        return true;
                    }
                    else
                    {
                        tr(failureTrace);
                        return false;
                    }
                }
                tr(failureTrace);
                return false;
            });
    };
}

//*************************************************
//*               IP filters                     *
//*************************************************

// path_to_ip: +ip_cidr/192.168.0.0/16
// path_to_ip: +ip_cidr/192.168.0.0/255.255.0.0
types::Lifter opBuilderHelperIPCIDR(const types::DocumentValue &def,
                                    types::TracerFn tr)
{
    // Get Field path to check
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    // Get function helper
    std::string rawValue = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(rawValue, '/');
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
    catch (std::exception &e)
    {
        throw std::runtime_error("Invalid IPv4 address: " + network);
    }

    uint32_t mask {};
    try
    {
        mask = utils::ip::IPv4MaskUInt(parameters[2]);
    }
    catch (std::exception &e)
    {
        throw std::runtime_error("Invalid IPv4 mask: " + mask);
    }

    uint32_t net_lower {network & mask};
    uint32_t net_upper {net_lower | (~mask)};

    // Tracing
    types::Document defTmp {def};
    std::string successTrace =
        fmt::format("{} Condition Success", defTmp.str());
    std::string failureTrace =
        fmt::format("{} Condition Failure", defTmp.str());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                // TODO Update to use proper reference
                const rapidjson::Value *field_str {};
                try
                {
                    field_str = &e->get(field);
                }
                catch (std::exception &ex)
                {
                    tr(failureTrace);
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    uint32_t ip {};
                    try
                    {
                        ip = utils::ip::IPv4ToUInt(field_str->GetString());
                    }
                    catch (std::exception &ex)
                    {
                        tr(failureTrace);
                        return false;
                    }
                    if (ip >= net_lower && ip <= net_upper)
                    {
                        tr(successTrace);
                        return true;
                    }
                    else
                    {
                        tr(failureTrace);
                        return false;
                    }
                }
                tr(failureTrace);
                return false;
            });
    };
}

} // namespace builder::internals::builders