/* Copyright (C) 2015-2023, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "opBuilderHelperUpgradeConfirmation.hpp"

#include <optional>
#include <string>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

namespace sint = base::utils::socketInterface;
using helper::base::Parameter;

namespace builder::internals::builders
{

// field: +upgrade_confirmation_send/ar_message
base::Expression opBuilderHelperSendUpgradeConfirmation(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] = helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(name, parameters, 1);
    // Assert expected parameter type reference
    helper::base::checkParameterType(name, parameters[0], Parameter::Type::REFERENCE);
    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Socket instance
    std::shared_ptr<sint::unixSecureStream> socketUC {std::make_shared<sint::unixSecureStream>(WM_UPGRADE_SOCK)};

    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters[0]};
    rValue = rightParameter.m_value;

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Message reference '{}' not found", name, parameters[0].m_value)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: The message is empty", name)};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: Upgrade confirmation message could not be sent", name)};
    const std::string failureTrace4 {
        fmt::format("[{}] -> Failure: Error trying to send upgrade confirmation message: ", name)};
    const std::string failureTrace5 {
        fmt::format("[{}] -> Failure: Message should be a JSON object: ", name)};
    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), name = std::move(name)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string query {};
            bool messageSent {false};

            std::string resolvedRValue;

            if(!event->isObject(rValue))
            {
                return base::result::makeFailure(event, failureTrace5);
            }
            query = event->str(rValue).value();

            //Verify that its a non-empty object
            if (query.empty() || query == "{}")
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            else
            {
                try
                {
                    if (sint::SendRetval::SUCCESS == socketUC->sendMsg(query))
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
                    return base::result::makeFailure(event, failureTrace4 + e.what());
                }
            }
        });
}

} // namespace builder::internals::builders
