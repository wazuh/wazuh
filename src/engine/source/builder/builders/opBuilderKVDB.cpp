/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <optional>
#include <string>
#include <re2/re2.h>

#include "opBuilderKVDB.hpp"
#include "syntax.hpp"
#include "stringUtils.hpp"

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;

// <field>: +kvdb_extract/<DB>/<ref_key>
types::Lifter opBuilderKVDBExtract(const types::DocumentValue & def)
{
    // Get target of the extraction
    std::string target {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error(
            "Invalid parameter type for kvdb extracting operator (str expected)");
    }

    // Parse parameters
    std::string params {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(params, '/')};
    if (parametersArr.size() < 2 || parametersArr.size() > 3)
    {
        throw std::runtime_error("Invalid number of parameters for kvdb extracting operator");
    }
    std::string db = std::move(parametersArr[1]);
    std::string key = std::move(parametersArr[2]);
    bool is_reference = false;
    if (key[0] == REFERENCE_ANCHOR) {
        key = key.substr(1); //TODO We can define a type "reference" with a tuple or a struct with this two values.
        is_reference = true;
    }

    // Return Lifter
    return [target, db, key, is_reference](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                std::string_view db_key;
                if (is_reference){
                    auto value = e.get(key);//TODO: Is this handling multilevel json?? I don´t think so...
                    if (value && value->IsString()){
                        db_key = value->GetString();
                    }
                    else {
                        //TODO error
                        return e;
                    }
                }
                else {
                    db_key = key;
                }
                std::string DUMMY = db+key;
                auto v = rapidjson::Value(DUMMY.c_str(), e.m_doc.GetAllocator());
                e.set(target, v);
                return e;
            });
    };
}

types::Lifter opBuilderKVDBExistanceCheck(const types::DocumentValue & def, bool check_exist)
{
    // Get key of the match
    std::string key {def.MemberBegin()->name.GetString()};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error(
            "Invalid parameter type for kvdb matching operator (str expected)");
    }

    // Parse parameters
    std::string params {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(params, '/')};
    if (parametersArr.size() != 2)
    {
        throw std::runtime_error("Invalid number of parameters for kvdb matching operator");
    }
    std::string db = std::move(parametersArr[1]);

    // Return Lifter
    return [db, key, check_exist](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                auto value = e.get("/" + key);
                bool found;
                if (value && value->IsString()) {
                    // Call KVDB
                    found = true;
                }
                else {
                    //TODO error
                    found = false;
                }
                return check_exist ? found : !found;
            });
    };
}

// <field>: +kvdb_match/<DB>
types::Lifter opBuilderKVDBMatch(const types::DocumentValue & def) {
    return opBuilderKVDBExistanceCheck(def, true);
}

// <field>: +kvdb_not_match/<DB>
types::Lifter opBuilderKVDBNotMatch(const types::DocumentValue & def) {
    return opBuilderKVDBExistanceCheck(def, false);
}


} // namespace builder::internals::builders
