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

// TODO field: +s_eq/str|$ref/

types::Lifter opBuilderHelperS_eq(const types::DocumentValue & def)
{
    // Get field key to check
    std::string key = def.MemberBegin()->name.GetString();

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

    std::string expectedStr = parametersArr[1];
    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([expectedStr, key](types::Event e) {
            try {
                    if(auto f2c = e.get("/" + key); f2c) {
                        return f2c->IsString() && std::string{f2c->GetString()} == expectedStr;
                    }
                    return false;
            } catch (std::exception & e) {
                // TODO Check exception type
                return false;
            }
        });
    };
}

// TODO field: +s_gt/str|$ref/
// TODO field: +s_lt/str|$ref/
} // namespace builder::internals::builders
