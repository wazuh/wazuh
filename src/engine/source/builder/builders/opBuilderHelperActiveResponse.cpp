/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "opBuilderHelperActiveResponse.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/stringUtils.hpp>
// TODO: move the wazuhRequest to a common path such as "utils"
#include <base/utils/wazuhProtocol/wazuhRequest.hpp>

using base::utils::socketInterface::SendRetval;
using base::utils::socketInterface::unixDatagram;
using helper::base::Parameter;

namespace builder::internals::builders
{

namespace ar
{

// TODO: this is a standard protocol, and it should be changed when the API is merged,
// since it contains the classes to generate the requests and responses.
constexpr const char* AR_JSON_PARAMS {R"({
                                            "extra_args":[],
                                            "alert":{}
                                    })"};

inline bool isStringNumber(const std::string value)
{
    char* p = NULL;
    strtol(value.c_str(), &p, 10); // base 10
    return (!*p);
}

} // namespace ar

// ar_message: +ar_create/<command-name>/<location>/<timeout>/<extra-args>
base::Expression opBuilderHelperCreateAR(const std::any& definition)
{
    // Extract parameters from definition
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);

    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(name, raw_parameters)};

    // Assert expected number of parameters
    helper::base::checkParametersMinSize(name, parameters, 2);

    // Format name for the tracer
    name = helper::base::formatHelperName(name, targetField, parameters);

    // Get command-name -> mandatory parameter, it can be either a value or a reference
    const Parameter::Type commandNameType {parameters[0].m_type};
    std::string commandNameValue {parameters[0].m_value};
    if (commandNameValue.empty())
    {
        throw std::runtime_error(
            fmt::format("Engine active response builder: \"{}\" function: <command-name> "
                        "cannot be empty.",
                        name));
    }

    // Get location -> mandatory value, it can be either a value or a reference
    const Parameter::Type locationType {parameters[1].m_type};
    const std::string locationValue {parameters[1].m_value};
    if (locationValue.empty())
    {
        throw std::runtime_error(fmt::format("Engine active response builder: \"{}\" "
                                             "function: <location> cannot be empty.",
                                             name));
    }

    const auto paramsQtty = parameters.size();

    // Get timeout -> optional parameter, it can be either a value or a reference
    const std::string timeoutValue {(paramsQtty > 2) ? parameters[2].m_value : ""};
    const Parameter::Type timeoutType {(paramsQtty > 2) ? parameters[2].m_type
                                                        : Parameter::Type::VALUE};

    // Get extra-args -> optional parameter, it must be a reference of an array
    if (paramsQtty > 3)
    {
        helper::base::checkParameterType(name, parameters[3], Parameter::Type::REFERENCE);
    }
    const auto extraArgsRefValue {(paramsQtty > 3) ? parameters[3].m_value : ""};

    // If it has more than 4 arguments then an error is raised
    if (paramsQtty > 4)
    {
        throw std::runtime_error(
            fmt::format("Engine active response builder: \"{}\" function: 3 parameters "
                        "were expected at most, {} parameters received.",
                        name,
                        paramsQtty));
    }

    // Tracing
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};

    const std::string failureTrace1 {fmt::format(
        "[{}] -> Failure: Trying to get command name value, '{}' reference not found", name, parameters[0].m_value)};
    std::string failureTrace2 {};
    if (3 <= paramsQtty)
    {
        failureTrace2 = fmt::format(
            "[{}] -> Failure: Trying to get timeout value, '{}' reference not found", name, parameters[2].m_value);
    }
    const std::string failureTrace4 {fmt::format(
        "[{}] -> Failure: Trying to get location value, '{}' reference not found", name, parameters[1].m_value)};
    const std::string failureTrace5 {fmt::format("[{}] -> Failure: Agent ID '{}' not found", name, ar::AGENT_ID_PATH)};
    const std::string failureTrace7 {fmt::format("[{}] -> Failure: Agent ID is not set", name)};
    const std::string failureTrace8 {fmt::format("[{}] -> Failure: Trying to get extra "
                                                 "arguments value, '{}' reference not found",
                                                 name,
                                                 parameters[1].m_value)};
    const std::string failureTrace9 {
        fmt::format("[{}] -> Failure: Wrong extra argument, a string was expected.", name)};
    const std::string failureTrace10 {fmt::format("[{}] -> Failure: Event could not be inserted in alert: ", name)};

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), name = std::move(name)](
            base::Event event) -> base::result::Result<base::Event>
        {
            json::Json jsonParams(ar::AR_JSON_PARAMS);

            // Get and set command name
            std::string commandNameResolvedValue {};
            if (Parameter::Type::REFERENCE == commandNameType)
            {
                commandNameResolvedValue =
                    event->getString(commandNameValue).value_or("");

                if (commandNameResolvedValue.empty())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else
            {
                commandNameResolvedValue = commandNameValue;
            }

            std::string timeoutResolvedValue {};
            if (Parameter::Type::REFERENCE == timeoutType)
            {
                timeoutResolvedValue = event->getString(timeoutValue).value_or("");

                if (timeoutResolvedValue.empty())
                {
                    return base::result::makeFailure(event, failureTrace2);
                }
            }
            else
            {
                timeoutResolvedValue = timeoutValue;
            }

            if (!ar::isStringNumber(timeoutResolvedValue))
            {
                return base::result::makeFailure(
                    event,
                    failureTrace
                        + fmt::format("Timeout value '{}' cannot be converted to a number", timeoutResolvedValue));
            }

            // Adds the timeout at the end of the command name (or "0" if no timeout set)
            commandNameResolvedValue +=
                timeoutResolvedValue.empty() ? "0" : timeoutResolvedValue;

            std::optional<std::string> locationResolvedValue {};
            std::string location {locationValue};
            if (Parameter::Type::REFERENCE == locationType)
            {
                locationResolvedValue = event->getString(locationValue);

                if (!locationResolvedValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace4);
                }

                location = locationResolvedValue.value();
            }

            std::string agentID {};
            bool isLocal {false};
            bool isAll {false};
            bool isID {false};
            // Get location
            if (!location.compare("LOCAL"))
            {
                const auto resolvedAgentID = event->getString(ar::AGENT_ID_PATH);

                if (resolvedAgentID.has_value())
                {
                    agentID = resolvedAgentID.value();
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace5);
                }

                isLocal = true;
            }
            else if (!location.compare("ALL"))
            {
                // TODO: This case generated one message per active agent in analysisd,
                // currently only the "all" text will be sent, which is not supported at
                // the moment by execd.
                agentID = "all";
                isAll = true;
            }
            else // Check if it is a number (specific agent id)
            {
                if (ar::isStringNumber(location))
                {
                    agentID = location;
                    isID = true;
                }
                else
                {
                    return base::result::makeFailure(
                        event, failureTrace + fmt::format("Agent ID '{}' is not a number", location));
                }
            }

            if (agentID.empty())
            {
                return base::result::makeFailure(event, failureTrace7);
            }

            // Check existence and not emptyness of extraArgsRefValue if used
            if (!extraArgsRefValue.empty())
            {
                const auto extraArgsArray = event->getArray(extraArgsRefValue);
                if (!extraArgsArray.has_value())
                {
                    return base::result::makeFailure(event, failureTrace8);
                }
                else
                {
                    for (const auto arrayElement : extraArgsArray.value())
                    {
                        // fill "extra_args" in json with this array
                        const auto resolvedElement {arrayElement.getString()};

                        if (resolvedElement)
                        {
                            jsonParams.appendString(
                                std::string_view {resolvedElement.value()},
                                std::string_view {"/extra_args"});
                        }
                        else
                        {
                            return base::result::makeFailure(event, failureTrace9);
                        }
                    }
                }
            }

            try
            {
                json::Json jsonEvent {event->str().c_str()};
                jsonParams.merge(json::NOT_RECURSIVE, jsonEvent, std::string_view {"/alert"});
            }
            catch (const std::runtime_error& e)
            {
                return base::result::makeFailure(event, failureTrace10 + e.what());
            }

            auto payload = base::utils::wazuhProtocol::WazuhRequest::create(
                commandNameResolvedValue, ar::ORIGIN_NAME, jsonParams);

            // Append header message
            const std::string completeMesage =
                fmt::format("(local_source) [] N{}{} {} {}",
                            isLocal ? 'R' : 'N',
                            (isAll || isID) ? 'S' : 'N',
                            agentID,
                            payload.toStr());

            event->setString(completeMesage, targetField);
            return base::result::makeSuccess(event, successTrace);
        });
}

// field: +ar_send/ar_message
base::Expression opBuilderHelperSendAR(const std::any& definition)
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

    std::shared_ptr<unixDatagram> socketAR {
        std::make_shared<unixDatagram>(ar::AR_QUEUE_PATH)};

    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters[0]};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: Query reference \"{}\" not found",
                    name,
                    parameters[0].m_value)};
    const std::string failureTrace2 {
        fmt::format("[{}] -> Failure: The query is empty", name)};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: AR message could not be send", name)};
    const std::string failureTrace4 {
        fmt::format("[{}] -> Failure: Error trying to send AR message: ", name)};

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), name = std::move(name)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string query {};
            bool messageSent {false};

            // Check if the value comes from a reference
            if (Parameter::Type::REFERENCE == rValueType)
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
                    return base::result::makeFailure(event, failureTrace4 + e.what());
                }
            }
        });
}

} // namespace builder::internals::builders
