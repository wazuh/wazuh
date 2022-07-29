/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "opBuilderARWrite.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <variant>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/stringUtils.hpp>

using base::utils::socketInterface::SendRetval;
using base::utils::socketInterface::unixDatagram;

namespace builder::internals::builders
{

// field: +ar_write/$ar_query
base::Expression opBuilderARWrite(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    std::shared_ptr<unixDatagram> socketAR {nullptr};

    try
    {
        socketAR = std::make_shared<unixDatagram>(AR_QUEUE_PATH);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            "Write AR operator: Error when creating the unixDatagram object.");
    }

    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters[0]};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {fmt::format("[{}] -> Failure: [{}] not found", name, parameters[0].m_value)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure: query is empty", name)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure", name)};

    // field_: name/parameter

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), name = std::move(name)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string query {};
            bool messageSent {false};

            // Check if the value comes from a reference
            if (helper::base::Parameter::Type::REFERENCE == rValueType)
            {
                auto resolvedRValue {event->getString(rValue)};

                if (!resolvedRValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
                else
                {
                    query = resolvedRValue.value();
                }
            }
            else // Direct value
            {
                query = rValue;
            }

            if (query.empty())
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            else
            {
                try
                {
                    if (SendRetval::SUCCESS == socketAR->sendMsg(query))
                    {
                        event->setBool(true, targetField);
                        return base::result::makeSuccess(event, successTrace);
                    }
                    else
                    {
                        return base::result::makeFailure(event, failureTrace3);
                    }
                }
                catch (const std::exception& e)
                {
                    const auto failureTraceEx {fmt::format("[{}] -> Failure: [{}]", name, e.what())};
                    return base::result::makeFailure(event, failureTraceEx);
                }
            }
        });
}

} // namespace builder::internals::builders
