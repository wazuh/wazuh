/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderWdbSync.hpp"

#include <string>

#include <fmt/format.h>

#include "syntax.hpp"
#include <utils/stringUtils.hpp>
#include <wdb/wdb.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;

// <wdb_result>: +wdb_update/<quey>|$<quey>
base::Lifter opBuilderWdbSyncUpdate(const base::DocumentValue& def,
                                   types::TracerFn tr)
{
    return opBuilderWdbSyncGenericQuery(def, tr, false);
}

// <wdb_result>: +wdb_query/<quey>|$<quey>
base::Lifter opBuilderWdbSyncQuery(const base::DocumentValue& def,
                                   types::TracerFn tr)
{
    return opBuilderWdbSyncGenericQuery(def, tr, true);
}

base::Lifter opBuilderWdbSyncGenericQuery(const base::DocumentValue& def,
                                   types::TracerFn tr, bool returnPayload)
{
    // Get wdb_result of the extraction
    std::string wdb_result {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Invalid parameter type for wDB sync update "
                                 "operator (str expected)");
    }

    // Parse parameters
    std::string parameter {def.MemberBegin()->value.GetString()};
    auto parametersArr {utils::string::split(parameter, '/')};
    if (parametersArr.size() != 2)
    {
        throw std::runtime_error(
            "Invalid number of parameters for wDB sync update operator");
    }

    // Check for empty parameter
    if(parametersArr.at(1).empty())
    {
        throw std::runtime_error("parameter can't be an empty string");
    }

    // Assigned to parameter in order to avoid handling array with 1 value
    parameter = parametersArr.at(1);

    // instantiate wDB
    constexpr std::string_view TEST_STREAM_SOCK_PATH = "/tmp/testStream.socket";
    // TODO: delete sock_path! is there a way or a cons of using sharedptr
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(TEST_STREAM_SOCK_PATH);

    base::Document doc {def};
    std::string successTrace = fmt::format("{} wdb_update Success", doc.str());
    std::string failureTrace = fmt::format("{} wdb_update Failure", doc.str());

    //Return Lifter
    return [=, parameter = std::move(parameter), tr = std::move(tr)](base::Observable o) mutable
    {
        // Append rxcpp operation
        return o.map(
            [=, parameter = std::move(parameter), tr = std::move(tr)](base::Event e) mutable
            {
                std::string completeQuery {};

                // Get reference key value
                if (parameter[0] == REFERENCE_ANCHOR)
                {
                    auto key = json::formatJsonPath(parameter.substr(1));
                    try
                    {
                        auto value = &e->getEvent()->get(key);
                        if (value && value->IsString())
                        {
                            std::string auxVal{value->GetString()};
                            if(auxVal.empty())
                            {
                                tr(failureTrace);
                                return e;
                            }
                            completeQuery = auxVal;
                        }
                        else
                        {
                            tr(failureTrace);
                            return e;
                        }
                    }
                    catch (std::exception& ex)
                    {
                        tr(failureTrace);
                        return e;
                    }
                }
                else
                {
                    completeQuery = parameter;
                }

                // Connect to wDB
                try
                {
                    wdb->connect();
                }
                catch(const std::runtime_error& err)
                {
                    tr(failureTrace);
                    return e;
                }

                // Execute complete query in DB
                auto returnTuple = wdb->tryQueryAndParseResult(completeQuery);

                // Handle response
                std::string queryResponse;
                auto resultCode = std::get<0>(returnTuple);
                if(returnPayload)
                {
                    if(resultCode == wazuhdb::QueryResultCodes::OK)
                    {
                        queryResponse = std::get<1>(returnTuple).value();
                    }
                    else
                    {
                        tr(failureTrace);
                        return e;
                    }
                }

                // Store value on json
                try
                {
                    if(returnPayload)
                    {
                        //TODO: should I treat different empty result?
                        e->getEvent()->set(wdb_result,
                        rapidjson::Value(queryResponse.c_str(),
                                        e->getEvent()->m_doc.GetAllocator())
                            .Move());
                    }
                    else
                    {
                        e->getEvent()->set(wdb_result,
                        rapidjson::Value().SetBool(resultCode == wazuhdb::QueryResultCodes::OK)
                            .Move());
                    }

                    tr(successTrace);
                }
                catch (std::exception& ex)
                {
                    tr(failureTrace);
                    return e;
                }

                return e;
            });
    };
}

} // namespace builder::internals::builders
