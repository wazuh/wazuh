/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <tuple>
#include <string>
#include "OpBuilderHelperFilter.hpp"

using DocumentValue = builder::internals::types::DocumentValue;
namespace {

using opString = std::optional<std::string>;
std::tuple<std::string, opString, opString>  getCompOpParameter(const DocumentValue & def)
{
    // Get destination path
    std::string field = def.MemberBegin()->name.GetString();
    // Get function helper
    std::string rawValue = def.MemberBegin()->value.GetString();

    // Parse parameters
    std::vector<std::string> parameters = utils::string::split(rawValue, '/');
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid parameters");
    }

    std::optional<std::string> refValue;
    std::optional<std::string> value;

    if (parameters[1][0] == '$')
    {
        refValue = parameters[1].substr(1);
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

types::Lifter opBuilderHelperExists(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return e.exists("/" + field); });
    };
}

types::Lifter opBuilderHelperNotExists(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return !e.exists("/" + field); });
    };
}

bool opBuilderHelperStringComparison(const std::string key, char op, types::Event & e,
                                                 std::optional<std::string> refExpStr,
                                                 std::optional<std::string> expectedStr) {

    // TODO Remove try catch or if nullptr after fix get method of document class
    // Get value to compare
    const rapidjson::Value * value{};
    try {
        value = e.get("/" + key);
    } catch (std::exception & e) {
        // TODO Check exception type
        return false;
    }

    if (value == nullptr || !value->IsString()) {
        return false;
    }

    // get str to compare
    if (refExpStr.has_value()) {
        // Get reference to json event
        auto refValueToCheck = e.getObject().FindMember(refExpStr.value().c_str());
        // if is a string value then compare
        if (refValueToCheck->value.IsString()) {
            expectedStr = std::string{refValueToCheck->value.GetString()};
            //return std::string{value->GetString()} == std::string{refValueToCheck->value.GetString()};
        } else {
            return false;
        }
    }

    // String operation
    switch (op) {
        case '=':
            return std::string{value->GetString()} == expectedStr.value();
        // This is not a typo, The '=' operand must be negated, since it must return true
        // if the reference is not found or they are of different type the event will be emitted again.
        //case '!':
        //    return std::string{value->GetString()} != expectedStr.value();
        case '>':
            return std::string{value->GetString()} > expectedStr.value();
        case '<':
            return std::string{value->GetString()} < expectedStr.value();
        //case '>=':
        case 'm':
            return std::string{value->GetString()} >= expectedStr.value();
        //case '<=':
        case 'n':
            return std::string{value->GetString()} <= expectedStr.value();
        default:
            throw std::invalid_argument("Invalid operator: '" + std::string{op} + "' ");
    }

    return false;
}

// <field>: s_eq/<value>
types::Lifter opBuilderHelperString_eq(const types::DocumentValue & def)
{
    // Get field key to check
    std::string key {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString()) {
        throw std::runtime_error("Invalid parameter type for s_eq operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr = utils::string::split(parm, '/');
    if (parametersArr.size() != 2) {
        throw std::runtime_error("Invalid number of parameters for s_eq operator");
    }

    std::optional<std::string> refExpStr {};
    std::optional<std::string> expectedStr {};

    // Check if is a reference to json event
    if (parametersArr[1][0] == '$') {
        refExpStr = parametersArr[1].substr(1);
    } else {
        expectedStr = parametersArr[1];
    }

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([key, expectedStr, refExpStr](types::Event e) {
            // try and catche, return false
            return opBuilderHelperStringComparison(key, '=', e, refExpStr, expectedStr);
        });
    };
}

// <field>: s_ne/<value>
types::Lifter opBuilderHelperString_ne(const types::DocumentValue & def)
{
    // Get field key to check
    std::string key {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString()) {
        throw std::runtime_error("Invalid parameter type for s_ne operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr = utils::string::split(parm, '/');
    if (parametersArr.size() != 2) {
        throw std::runtime_error("Invalid number of parameters for s_ne operator");
    }

    std::optional<std::string> refExpStr {};
    std::optional<std::string> expectedStr {};

    // Check if is a reference to json event
    if (parametersArr[1][0] == '$') {
        refExpStr = parametersArr[1].substr(1);
    } else {
        expectedStr = parametersArr[1];
    }

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([key, expectedStr, refExpStr](types::Event e) {
            // Not use a `!` operator, since it must return false if the reference
            // is not found or they are of different type
            // try and catche, return false
            return !opBuilderHelperStringComparison(key, '=', e, refExpStr, expectedStr);
        });
    };
}


// TODO <field>: s_gt/<value>|$<ref>
// TODO <field>: s_lt/<value>|$<ref>
// TODO <field>: s_gte/<value>|$<ref>
// TODO <field>: s_lte/<value>|$<ref>

} // namespace builder::internals::builders
