/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <optional>
#include <string>
#include <tuple>
#include <re2/re2.h>

#include "opBuilderHelperFilter.hpp"
#include "stringUtils.hpp"
#include "ipUtils.hpp"
#include "syntax.hpp"

using DocumentValue = builder::internals::types::DocumentValue;
namespace
{

using opString = std::optional<std::string>;
using builder::internals::syntax::REFERENCE_ANCHOR;
/**
 * @brief Get the Comparator operator, and the value to compare
 * or the reference to value to compare
 *
 * @param def The JSON definition of the operator
 * @return std::tuple<std::string, opString, opString> the operator,
 * the value to compare and the reference to value to compare (if exists)
 * @throw std::runtime_error if the number of parameters is not valid
 * @throw std::logic_error if the json node is not valid definition for the helper
 * function
 */
std::tuple<std::string, opString, opString> getCompOpParameter(const DocumentValue & def)
{
    // Get destination path
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};
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
        refValue = json::Document::preparePath(parameters[1].substr(1));
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
types::Lifter opBuilderHelperExists(const DocumentValue & def)
{
    // Get Field path to check
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};

    //Check parameters
    std::vector<std::string> parameters {
        utils::string::split(def.MemberBegin()->value.GetString(), '/')};
    if (parameters.size() != 1)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    // Return Lifter
    return [field](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return e->exists(field); });
    };
}

// <field>: not_exists
types::Lifter opBuilderHelperNotExists(const DocumentValue & def)
{
    // Get Field path to check
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};

    std::vector<std::string> parameters =
        utils::string::split(def.MemberBegin()->value.GetString(), '/');
    if (parameters.size() != 1)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    // Return Lifter
    return [field](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return !e->exists(field); });
    };
}

//*************************************************
//*           String filters                      *
//*************************************************

bool opBuilderHelperStringComparison(const std::string key, char op, types::Event & e,
                                     std::optional<std::string> refValue,
                                     std::optional<std::string> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document class
    // Get value to compare
    const rapidjson::Value * fieldToCompare {};
    try
    {
        fieldToCompare = e->get(key);
    }
    catch (std::exception & ex)
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
        // TODO Remove try catch or if nullptr after fix get method of document class
        const rapidjson::Value * refValueToCheck {};
        try
        {
            refValueToCheck = e->get(refValue.value());
        }
        catch (std::exception & ex)
        {
            // TODO Check exception type
            return false;
        }

        if (refValueToCheck == nullptr || !refValueToCheck->IsString())
        {
            return false;
        }
        value = std::string{refValueToCheck->GetString()};
    }

    // String operation
    switch (op)
    {
        case '=':
            return std::string{fieldToCompare->GetString()} == value.value();
        case '!':
            return std::string{fieldToCompare->GetString()} != value.value();
        case '>':
            return std::string{fieldToCompare->GetString()} > value.value();
        // case '>=':
        case 'g':
            return std::string{fieldToCompare->GetString()} >= value.value();
        case '<':
            return std::string{fieldToCompare->GetString()} < value.value();
        // case '<=':
        case 'l':
            return std::string{fieldToCompare->GetString()} <= value.value();
        default:
            // if raise here, then the logic is wrong
            throw std::invalid_argument("Invalid operator: '" + std::string{op} + "' ");
    }

    return false;
}

// <field>: s_eq/<value>
types::Lifter opBuilderHelperStringEQ(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperStringComparison(key, '=', e, refValue, value);
            });
    };
}

// <field>: s_ne/<value>
types::Lifter opBuilderHelperStringNE(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            { return opBuilderHelperStringComparison(key, '!', e, refValue, value); });
    };
}

// <field>: s_gt/<value>|$<ref>
types::Lifter opBuilderHelperStringGT(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            { return opBuilderHelperStringComparison(key, '>', e, refValue, value); });
    };
}

// <field>: s_ge/<value>|$<ref>
types::Lifter opBuilderHelperStringGE(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            { return opBuilderHelperStringComparison(key, 'g', e, refValue, value); });
    };
}

// <field>: s_lt/<value>|$<ref>
types::Lifter opBuilderHelperStringLT(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            { return opBuilderHelperStringComparison(key, '<', e, refValue, value); });
    };
}

// <field>: s_le/<value>|$<ref>
types::Lifter opBuilderHelperStringLE(const DocumentValue & def)
{
    auto [key, refValue, value] {getCompOpParameter(def)};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [key, refValue, value](types::Event e)
            { return opBuilderHelperStringComparison(key, 'l', e, refValue, value); });
    };
}

//*************************************************
//*               Int filters                     *
//*************************************************

bool opBuilderHelperIntComparison(const std::string field, char op, types::Event & e,
                                  std::optional<std::string> refValue,
                                  std::optional<int> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document class
    // Get value to compare
    const rapidjson::Value * fieldValue {};
    try
    {
        fieldValue = e->get(field);
    }
    catch (std::exception & ex)
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
        // TODO Remove try catch or if nullptr after fix get method of document class
        const rapidjson::Value * refValueToCheck {};
        try
        {
            refValueToCheck = e->get(refValue.value());
        }
        catch (std::exception & ex)
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
        case '=':
            return fieldValue->GetInt() == value.value();
        // case '!=':
        case '!':
            return fieldValue->GetInt() != value.value();
        case '>':
            return fieldValue->GetInt() > value.value();
        // case '>=':
        case 'g':
            return fieldValue->GetInt() >= value.value();
        case '<':
            return fieldValue->GetInt() < value.value();
        // case '<=':
        case 'l':
            return fieldValue->GetInt() <= value.value();

        default:
            // if raise here, then the source code is wrong
            throw std::invalid_argument("Invalid operator: '" + std::string{op} + "' ");
    }

    return false;
}

// field: +i_eq/int|$ref/
types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int> {std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            { return opBuilderHelperIntComparison(field, '=', e, refValue, value); });
    };
}

// field: +i_ne/int|$ref/
types::Lifter opBuilderHelperIntNotEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '!', e, refValue, value);
            });
    };
}

// field: +i_lt/int|$ref/
types::Lifter opBuilderHelperIntLessThan(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '<', e, refValue, value);
            });
    };
}

// field: +i_le/int|$ref/
types::Lifter opBuilderHelperIntLessThanEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, 'l', e, refValue, value);
            });
    };
}

// field: +i_gt/int|$ref/
types::Lifter opBuilderHelperIntGreaterThan(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '>', e, refValue, value);
            });
    };
}

// field: +i_ge/int|$ref/
types::Lifter opBuilderHelperIntGreaterThanEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] {getCompOpParameter(def)};

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, 'g', e, refValue, value);
            });
    };
}

//*************************************************
//*               Regex filters                   *
//*************************************************

// field: +r_match/regexp
types::Lifter opBuilderHelperRegexMatch(const types::DocumentValue & def)
{
    // Get field
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};
    std::string value {def.MemberBegin()->value.GetString()};

    std::vector<std::string> parameters {utils::string::split(value, '/')};
    if (parameters.size() != 2)
    {
        throw std::invalid_argument("Wrong number of arguments passed");
    }

    auto regex_ptr = std::make_shared<RE2>(parameters[1], RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[1] + "'. "
                          + regex_ptr->error();
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
                const rapidjson::Value * field_str {};
                try
                {
                    field_str = e->get(field);
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    return (RE2::PartialMatch(field_str->GetString(), *regex_ptr));
                }
                return false;
            });
    };
}

// field: +r_not_match/regexp
types::Lifter opBuilderHelperRegexNotMatch(const types::DocumentValue & def)
{
    // Get field
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};
    std::string value = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(value, '/');
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid number of parameters");
    }

    auto regex_ptr = std::make_shared<RE2>(parameters[1], RE2::Quiet);
    if (!regex_ptr->ok())
    {
        const std::string err = "Error compiling regex '" + parameters[1] + "'. "
                          + regex_ptr->error();
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
                const rapidjson::Value * field_str {};
                try
                {
                    field_str = e->get(field);
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    return (!RE2::PartialMatch(field_str->GetString(), *regex_ptr));
                }
                return false;
            });
    };
}


//*************************************************
//*               IP filters                     *
//*************************************************


// path_to_ip: +ip_cidr/192.168.0.0/16
// path_to_ip: +ip_cidr/192.168.0.0/255.255.0.0
types::Lifter opBuilderHelperIPCIDR(const types::DocumentValue & def)
{
    // Get Field path to check
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};
    // Get function helper
    std::string rawValue = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(rawValue, '/');
    if (parameters.size() != 3)
    {
        throw std::runtime_error("Invalid number of parameters");
    } else if (parameters[2].empty())
    {
        throw std::runtime_error("The network can't be empty");
    }
    else if (parameters[1].empty())
    {
        throw std::runtime_error("The cidr can't be empty");
    }

    uint32_t network {};
    try {
        network = utils::ip::IPv4ToUInt(parameters[1]);
    } catch (std::exception & e)
    {
        throw std::runtime_error("Invalid IPv4 address: " + network);
    }

    uint32_t mask {};
    try {
        mask = utils::ip::IPv4MaskUInt(parameters[2]);
    } catch (std::exception & e)
    {
       throw std::runtime_error("Invalid IPv4 mask: " + mask);
    }

    uint32_t net_lower {network & mask};
    uint32_t net_upper {net_lower | (~mask)};

    // Return Lifter
    return [field, net_lower, net_upper](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                const rapidjson::Value * field_str{};
                try
                {
                    field_str = e->get(field);
                }
                catch (std::exception & ex)
                {
                    return false;
                }
                if (field_str != nullptr && field_str->IsString())
                {
                    uint32_t ip {};
                    try
                    {
                        ip = utils::ip::IPv4ToUInt(field_str->GetString());
                    }
                    catch (std::exception & ex)
                    {
                        return false;
                    }
                    return (ip >= net_lower && ip <= net_upper);
                }
                return false;
            });
    };
}

} // namespace builder::internals::builders
