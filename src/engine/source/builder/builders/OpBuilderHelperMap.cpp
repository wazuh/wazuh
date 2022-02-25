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
// TODO Rename function, remove `_`
types::Event opBuilderHelperStringTransformation(const std::string key, char op, types::Event & e,
                                                 std::optional<std::string> refExpStr,
                                                 std::optional<std::string> expectedStr) {


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
        default:
            // if raise here, then the source code is wrong
            throw std::logic_error("Invalid string transformation operator");
            break;
    }


    // TODO Check if necesary create all json path
    // Create and add string to event
    try {
        e.set("/" + key, rapidjson::Value(expectedStr.value().c_str(), e.m_doc.GetAllocator()).Move());
    } catch (std::exception & ex) {
        // TODO Check exception type
        return e;
    }

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

// <field>: +s_trim/[begin | end | both]/char
types::Lifter opBuilderHelperStringTrim(const types::DocumentValue & def) {

   // Get field path to trim
    std::string field {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString()) {
        // Logical error
        throw std::runtime_error("Invalid parameter type for s_trim operator (str expected)");
    }

    // Parse parameters
    std::string parm {def.MemberBegin()->value.GetString()};
    auto parametersArr = utils::string::split(parm, '/');
    if (parametersArr.size() != 3) {
        throw std::runtime_error("Invalid number of parameters for s_trim operator");
    }

    // Get trim type
    char trimType = parametersArr[1] == "begin" ? 's' :
                    parametersArr[1] == "end" ? 'e' :
                    parametersArr[1] == "both" ? 'b' :
                    '\0';
    if (trimType == '\0') {
        throw std::runtime_error("Invalid trim type for s_trim operator");
    }

    // get trim char
    std::string trimChar {parametersArr[2]};
    if (trimChar.size() != 1) {
        throw std::runtime_error("Invalid trim char for s_trim operator");
    }

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.map([field, trimType, trimChar](types::Event e) {

            // Get field value
            const rapidjson::Value * fieldValue;
            try {
                fieldValue = e.get("/"+field);
            } catch (std::exception & ex) {
                // TODO Check exception type
                return e;
            }

            // Check if field is a string
            if (fieldValue== nullptr || !fieldValue->IsString()) {
                return e;
            }

            // Get string
            std::string strToTrim {fieldValue->GetString()};

                // Trim
                switch (trimType) {
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

            // Update event
            try {
                e.set("/" + field, rapidjson::Value(strToTrim.c_str(), e.m_doc.GetAllocator()).Move());
            } catch (std::exception & ex) {
                // TODO Check exception type
                return e;
            }

            return e;
        });
    };


}

} // namespace builder::internals::builders

