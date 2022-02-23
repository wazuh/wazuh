/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string>
#include <algorithm>

#include "OpBuilderHelperMap.hpp"
#include "stringUtils.hpp"


namespace builder::internals::builders
{

//*************************************************
//*           String tranform                     *
//*************************************************

types::Event opBuilderHelperStringTransformation(const std::string key, char op, types::Event & e,
                                                 std::optional<std::string> refExpStr,
                                                 std::optional<std::string> expectedStr) {


    // TODO Remove try catch or if nullptr after fix get method of document class

    // Check if dst field exists
    // TODO Ignore? or change te field name?
    if (e.exists("/" + key)) {
        return e;
    }

    // Get src field
    if (refExpStr.has_value()) {
        // Get reference to json event
        // TODO Remove try catch or if nullptr after fix get method of document class
        const rapidjson::Value * refValueToCheck{};
        try
        {
            refValueToCheck = e.get("/" + refExpStr.value());
        }
        catch (std::exception & ex)
        {
            // TODO Check exception type
            return e;
        }

        if (refValueToCheck == nullptr || !refValueToCheck->IsString())
        {
            return e;
        }
        // If reache here, the refValueToCheck is a string
        expectedStr = std::string{refValueToCheck->GetString()};
    }

    switch (op) {
        case 'u':
            // Upper case
            std::transform(expectedStr.value().begin(), expectedStr.value().end(),
                          expectedStr.value().begin(), ::toupper);
            break;
        case 'l':
            // Lower case
            std::transform(expectedStr.value().begin(), expectedStr.value().end(),
                          expectedStr.value().begin(), ::tolower);
            break;
        case 't':
            break;
        default:
            // if raise here, then the source code is wrong
            throw std::logic_error("Invalid string transformation operator");
            break;
    }
    

    // TODO Check if necesary create all json path
    // Create and add string to event

    e.m_doc.AddMember(
        rapidjson::Value(key.c_str() , e.m_doc.GetAllocator()).Move(),
        rapidjson::Value(expectedStr.value().c_str(), e.m_doc.GetAllocator()).Move(),
        e.m_doc.GetAllocator());

    return e;
}

// <field>: +s_up/<str>|$<ref>
types::Lifter opBuilderHelperString_up(const types::DocumentValue & def){

     // Get field key to check
    std::string key {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString()) {
        throw std::runtime_error("Invalid parameter type for s_up operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr = utils::string::split(parm, '/');
    if (parametersArr.size() != 2) {
        throw std::runtime_error("Invalid number of parameters for s_up operator");
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
        return o.map([key, expectedStr, refExpStr](types::Event e) {
            return opBuilderHelperStringTransformation(key, 'u', e, refExpStr, expectedStr);
        });
    };
}


// <field>: +s_lo/<str>|$<ref>
types::Lifter opBuilderHelperString_lo(const types::DocumentValue & def){

     // Get field key to check
    std::string key {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString()) {
        throw std::runtime_error("Invalid parameter type for s_lo operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr = utils::string::split(parm, '/');
    if (parametersArr.size() != 2) {
        throw std::runtime_error("Invalid number of parameters for s_lo operator");
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
        return o.map([key, expectedStr, refExpStr](types::Event e) {
            return opBuilderHelperStringTransformation(key, 'l', e, refExpStr, expectedStr);
        });
    };
}

} // namespace builder::internals::builders

