/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderWdb.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <variant>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/stringUtils.hpp>
#include <wdb/wdb.hpp>

namespace builder::internals::builders
{

static inline base::Expression opBuilderWdbGenericQuery(const std::any& definition,
                                                        bool doReturnPayload)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Depending on rValue type we store the reference or the string value, string in both
    // cases
    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters[0]};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: Target field \"{}\" not found", name, targetField)};
    const auto failureTrace2 {
        fmt::format("[{}] -> Failure: Target field \"{}\" is empty", name, targetField)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure: ", name) + "Result code is \"{}.\""};

    // instantiate WDB
    auto wdb = std::make_shared<wazuhdb::WazuhDB>(wazuhdb::WDB_SOCK_PATH);
    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), wdb = std::move(wdb)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string completeQuery {};

            // Check if the value comes from a reference
            if (helper::base::Parameter::Type::REFERENCE == rValueType)
            {
                auto resolvedRValue {event->getString(rValue)};

                if (resolvedRValue.has_value())
                {
                    completeQuery = resolvedRValue.value();
                    if (completeQuery.empty())
                    {
                        return base::result::makeFailure(event, failureTrace2);
                    }
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else // Direct value
            {
                completeQuery = rValue;
            }

            // Execute complete query in DB
            auto returnTuple {wdb->tryQueryAndParseResult(completeQuery)};

            // Handle response
            auto resultCode {std::get<0>(returnTuple)};

            // Store value on json
            if (doReturnPayload)
            {
                if (wazuhdb::QueryResultCodes::OK == resultCode)
                {
                    const auto& queryResponse {std::get<1>(returnTuple)};
                    if (queryResponse.has_value() && !queryResponse.value().empty())
                    {
                        event->setString(queryResponse.value(), targetField);
                    }
                    else
                    {
                        event->setString("", targetField);
                    }
                    return base::result::makeSuccess(event, successTrace);
                }
                else
                {
                    std::string_view retCode {};
                    for (auto& it : wazuhdb::QueryResStr2Code)
                    {
                        if (it.second == resultCode)
                        {
                            retCode = it.first;
                        }
                    }
                    return base::result::makeFailure(event,
                                                     fmt::format(failureTrace3, retCode));
                }
            }
            else
            {
                event->setBool(wazuhdb::QueryResultCodes::OK == resultCode, targetField);
                return base::result::makeSuccess(event, successTrace);
            }
        });
}

// <wdb_result>: +wdb_update/<quey>|$<quey>
base::Expression opBuilderWdbUpdate(const std::any& definition)
{
    return opBuilderWdbGenericQuery(definition, false);
}

// <wdb_result>: +wdb_query/<quey>|$<quey>
base::Expression opBuilderWdbQuery(const std::any& definition)
{
    return opBuilderWdbGenericQuery(definition, true);
}

} // namespace builder::internals::builders
