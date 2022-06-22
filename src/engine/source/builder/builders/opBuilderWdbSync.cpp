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

using builder::internals::syntax::REFERENCE_ANCHOR;
using std::string;

namespace builder::internals::builders
{

static inline base::Lifter opBuilderWdbSyncGenericQuery(const base::DocumentValue& def,
                                                        types::TracerFn tr,
                                                        bool doReturnPayload)
{
    // Get wdb_result of the extraction
    string wdb_result {json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Get the raw value of parameter
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Invalid parameter type for wDB sync update "
                                 "operator (str expected)");
    }

    // Parse parameters
    auto parametersArr {utils::string::split(def.MemberBegin()->value.GetString(), '/')};
    if (parametersArr.size() != 2)
    {
        throw std::runtime_error(
            "Invalid number of parameters for wDB sync update operator");
    }

    // Check for empty parameter
    if (parametersArr.at(1).empty())
    {
        throw std::runtime_error("parameter can't be an empty string");
    }

    // Assigned to parameter in order to avoid handling array with 1 value
    const string parameter = parametersArr.at(1);

    base::Document doc {def};
    string successTrace = fmt::format("{} wdb_update Success", doc.str());
    string failureTrace = fmt::format("{} wdb_update Failure", doc.str());

    // Return Lifter
    return [=, tr = std::move(tr)](base::Observable o) {
        // Append rxcpp operation
        return o.map([=, tr = std::move(tr)](base::Event e) {
            string completeQuery {};

            // Get reference key value
            if (parameter[0] == REFERENCE_ANCHOR)
            {
                auto key = json::formatJsonPath(parameter.substr(1));
                try
                {
                    auto value = &e->getEventValue(key);
                    if (value && value->IsString())
                    {
                        string auxVal {value->GetString()};
                        if (auxVal.empty())
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

            // instantiate wDB
            // TODO: delete sock_path! is there a way or a cons of using sharedptr
            auto wdb = std::make_shared<wazuhdb::WazuhDB>(STREAM_SOCK_PATH);

            // Execute complete query in DB
            auto returnTuple = wdb->tryQueryAndParseResult(completeQuery);

            // Handle response
            string queryResponse;
            auto resultCode = std::get<0>(returnTuple);

            // Store value on json
            try
            {
                if (doReturnPayload)
                {
                    queryResponse = std::get<1>(returnTuple).value();
                    if (resultCode == wazuhdb::QueryResultCodes::OK
                        && !queryResponse.empty())
                    {
                        e->setEventValue(wdb_result,
                                         rapidjson::Value(queryResponse.c_str(),
                                                          e->getEventDocAllocator())
                                             .Move());
                        tr(successTrace);
                    }
                    else
                    {
                        tr(failureTrace);
                    }
                }
                else
                {
                    e->setEventValue(
                        wdb_result,
                        rapidjson::Value()
                            .SetBool(resultCode == wazuhdb::QueryResultCodes::OK)
                            .Move());
                    tr(successTrace);
                }
            }
            catch (std::exception& ex)
            {
                tr(failureTrace);
            }

            return e;
        });
    };
}

// <wdb_result>: +wdb_update/<quey>|$<quey>
base::Lifter opBuilderWdbSyncUpdate(const base::DocumentValue& def, types::TracerFn tr)
{
    return opBuilderWdbSyncGenericQuery(def, tr, false);
}

// <wdb_result>: +wdb_query/<quey>|$<quey>
base::Lifter opBuilderWdbSyncQuery(const base::DocumentValue& def, types::TracerFn tr)
{
    return opBuilderWdbSyncGenericQuery(def, tr, true);
}

} // namespace builder::internals::builders
