/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderKVDB.hpp"

#include <string>

#include <fmt/format.h>
#include <utils/stringUtils.hpp>
#include <kvdb/kvdbManager.hpp>

#include "syntax.hpp"


namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;

// <field>: +kvdb_extract/<DB>/<ref_key>
types::Lifter opBuilderKVDBExtract(const types::DocumentValue & def, types::TracerFn tr)
{
    // Get target of the extraction
    std::string target {json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error(
            "Invalid parameter type for kvdb extracting operator (str expected)");
    }

    // Parse parameters
    std::string params {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(params, '/')};
    if (parametersArr.size() != 3) //TODO: We are using default column only now
    {
        throw std::runtime_error("Invalid number of parameters for kvdb extracting operator");
    }

    // Get DB
    auto kvdb = KVDBManager::get().getDB(parametersArr[1]);
    if (!kvdb)
    {
        auto msg = fmt::format("[{}] DB isn't available for usage", parametersArr[1]);
        throw std::runtime_error(std::move(msg));
    }

    // Get reference key
    std::string& key = parametersArr[2];
    bool isReference = false;
    if (key[0] == REFERENCE_ANCHOR) {
        key = json::formatJsonPath(key.substr(1));
        isReference = true;
    }

    // Return Lifter
    return [target, kvdb, key, isReference](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                // Get DB key
                std::string dbKey;
                if (isReference){
                    try
                    {
                        auto value = &e->get(key);
                        if (value && value->IsString()){
                            dbKey = value->GetString();
                        }
                        else {
                            return e;
                        }
                    }
                    catch (std::exception & ex)
                    {
                        // TODO Check exception type
                        return e;
                    }
                }
                else {
                    dbKey = std::move(key);
                }

                // Get value from the DB
                std::string dbValue = kvdb->read(dbKey);
                if (dbValue.empty()) {
                    return e;
                }

                // Create and add string to event
                try
                {
                    e->set(target,
                        rapidjson::Value(dbValue.c_str(), e->m_doc.GetAllocator()).Move());
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return e;
                }

                return e;
            });
    };
}

types::Lifter opBuilderKVDBExistanceCheck(const types::DocumentValue & def, bool checkExist)
{
    // Get key of the match
    std::string key {json::formatJsonPath(def.MemberBegin()->name.GetString())};

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

    auto kvdb = KVDBManager::get().getDB(parametersArr[1]);
    if (!kvdb)
    {
        auto msg = fmt::format("[{}] DB isn't available for usage", parametersArr[1]);
        throw std::runtime_error(std::move(msg));
    }

    // Return Lifter
    return [kvdb, key, checkExist](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                bool found = false;
                try // TODO We are only using try for JSON::get. Is correct to wrap everything?
                {
                    auto value = &e->get(key);
                    if (value && value->IsString()) {
                        if (kvdb->hasKey(value->GetString())) {
                            found = true;
                        }
                    }
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                }
                return checkExist ? found : !found;
            });
    };
}

// <field>: +kvdb_match/<DB>
types::Lifter opBuilderKVDBMatch(const types::DocumentValue & def, types::TracerFn tr) {
    return opBuilderKVDBExistanceCheck(def, true);
}

// <field>: +kvdb_not_match/<DB>
types::Lifter opBuilderKVDBNotMatch(const types::DocumentValue & def, types::TracerFn tr) {
    return opBuilderKVDBExistanceCheck(def, false);
}

} // namespace builder::internals::builders
