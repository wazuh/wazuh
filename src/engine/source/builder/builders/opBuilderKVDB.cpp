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

#include "syntax.hpp"
#include <kvdb/kvdbManager.hpp>
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;

// <field>: +kvdb_extract/<DB>/<ref_key>
types::Lifter opBuilderKVDBExtract(const types::DocumentValue& def,
                                   types::TracerFn tr)
{
    // Get target of the extraction
    std::string target {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Invalid parameter type for kvdb extracting "
                                 "operator (str expected)");
    }

    // Parse parameters
    std::string params {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(params, '/')};
    if (parametersArr.size() != 3) // TODO: We are using default column only now
    {
        throw std::runtime_error(
            "Invalid number of parameters for kvdb extracting operator");
    }

    // Get DB
    auto kvdb = KVDBManager::get().getDB(parametersArr[1]);
    if (!kvdb)
    {
        auto msg =
            fmt::format("[{}] DB isn't available for usage", parametersArr[1]);
        throw std::runtime_error(std::move(msg));
    }

    // Get reference key
    std::string& key = parametersArr[2];
    bool isReference = false;
    if (key[0] == REFERENCE_ANCHOR)
    {
        key = json::formatJsonPath(key.substr(1));
        isReference = true;
    }

    // TODO this is not great
    // Make deep copy of value
    types::Document doc {def};
    std::string successTrace = fmt::format("{} KVDBExtract Success", doc.str());
    std::string failureTrace = fmt::format("{} KVDBExtract Failure", doc.str());

    // Return Lifter
    return [=, kvdb = std::move(kvdb), tr = std::move(tr)](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=, kvdb = std::move(kvdb), tr = std::move(tr)](types::Event e)
            {
                // Get DB key
                std::string dbKey;
                if (isReference)
                {
                    try
                    {
                        auto value = &e->get(key);
                        if (value && value->IsString())
                        {
                            dbKey = value->GetString();
                        }
                        else
                        {
                            tr(failureTrace);
                            return e;
                        }
                    }
                    catch (std::exception& ex)
                    {
                        // TODO Check exception type
                        tr(failureTrace);
                        return e;
                    }
                }
                else
                {
                    dbKey = std::move(key);
                }

                // Get value from the DB
                std::string dbValue = kvdb->read(dbKey);
                if (dbValue.empty())
                {
                    tr(failureTrace);
                    return e;
                }

                // Create and add string to event
                try
                {
                    e->set(target,
                           rapidjson::Value(dbValue.c_str(),
                                            e->m_doc.GetAllocator())
                               .Move());
                    tr(successTrace);
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                    tr(failureTrace);
                    return e;
                }

                return e;
            });
    };
}

types::Lifter opBuilderKVDBExistanceCheck(const types::DocumentValue& def,
                                          bool checkExist,
                                          types::TracerFn tr)
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
        throw std::runtime_error(
            "Invalid number of parameters for kvdb matching operator");
    }

    auto kvdb = KVDBManager::get().getDB(parametersArr[1]);
    if (!kvdb)
    {
        auto msg =
            fmt::format("[{}] DB isn't available for usage", parametersArr[1]);
        throw std::runtime_error(std::move(msg));
    }

    // TODO this is not great
    // Make deep copy of value
    types::Document doc {def};
    std::string successTrace =
        fmt::format("{} KVDBExistanceCheck Found", doc.str());
    std::string failureTrace =
        fmt::format("{} KVDBExistanceCheck NotFound", doc.str());

    // Return Lifter
    return [=, kvdb = std::move(kvdb), tr = std::move(tr)](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=, kvdb = std::move(kvdb), tr = std::move(tr)](types::Event e)
            {
                bool found = false;
                try // TODO We are only using try for JSON::get. Is correct to
                    // wrap everything?
                {
                    auto value = &e->get(key);
                    if (value && value->IsString())
                    {
                        if (kvdb->hasKey(value->GetString()))
                        {
                            found = true;
                        }
                    }
                }
                catch (std::exception& ex)
                {
                    // TODO Check exception type
                }

                tr(found ? successTrace : failureTrace);
                return checkExist ? found : !found;
            });
    };
}

// <field>: +kvdb_match/<DB>
types::Lifter opBuilderKVDBMatch(const types::DocumentValue& def,
                                 types::TracerFn tr)
{
    return opBuilderKVDBExistanceCheck(def, true, tr);
}

// <field>: +kvdb_not_match/<DB>
types::Lifter opBuilderKVDBNotMatch(const types::DocumentValue& def,
                                    types::TracerFn tr)
{
    return opBuilderKVDBExistanceCheck(def, false, tr);
}
} // namespace builder::internals::builders
