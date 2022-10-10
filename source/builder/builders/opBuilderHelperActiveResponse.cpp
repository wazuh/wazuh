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

using base::utils::socketInterface::SendRetval;
using base::utils::socketInterface::unixDatagram;
using helper::base::Parameter;

namespace builder::internals::builders
{

namespace ar
{

// TODO: this is a standard protocol, and it should be changed when the API is merged,
// since it contains the classes to generate the requests and responses.
constexpr const char* AR_JSON_FORMAT {R"({
                                            "version":0,
                                            "origin":{
                                                "name":"",
                                                "module":""
                                            },
                                            "command":"",
                                            "parameters":{
                                                "extra_args":[],
                                                "alert":{}
                                            }
                                    })"};

// JSON Paths
constexpr const char* ALERT_PATH {"/parameters/alert"};
constexpr const char* COMMAND_PATH {"/command"};
constexpr const char* EXTRA_ARGS_PATH {"/parameters/extra_args"};
constexpr const char* ORIGIN_MODULE_PATH {"/origin/module"};
constexpr const char* ORIGIN_NAME_PATH {"/origin/name"};
constexpr const char* VERSION_PATH {"/version"};

// values
constexpr const char* MODULE_NAME {"wazuh-engine"};
constexpr const char* NODE_NAME {"node01"};
constexpr int VERSION {1};

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
    auto parameters {helper::base::processParameters(raw_parameters)};

    // Assert expected number of parameters
    helper::base::checkParametersMinSize(parameters, 2);

    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Get command-name -> mandatory parameter, it can be either a value or a reference
    const auto commandNameType {parameters[0].m_type};
    std::string commandNameValue {parameters[0].m_value};
    if (commandNameValue.empty())
    {
        throw std::runtime_error(
            fmt::format("[base::opBuilderHelperCreateAR] -> "
                        "Failure: <command-name> can not be empty."));
    }

    // Get location -> mandatory value, it can be either a value or a reference
    const auto locationType {parameters[1].m_type};
    const auto locationValue {parameters[1].m_value};
    if (locationValue.empty())
    {
        throw std::runtime_error(fmt::format("[base::opBuilderHelperCreateAR] -> "
                                             "Failure: <location> can not be empty."));
    }

    const auto paramsQtty = parameters.size();

    // Get timeout -> optional parameter, it can be either a value or a reference
    const auto timeoutValue {(paramsQtty > 2) ? parameters[2].m_value : ""};
    const auto timeoutType {(paramsQtty > 2) ? parameters[2].m_type
                                             : Parameter::Type::VALUE};

    // Get extra-args -> optional parameter, it must be a reference of an array
    if (paramsQtty > 3)
    {
        helper::base::checkParameterType(parameters[3], Parameter::Type::REFERENCE);
    }
    const auto extraArgsRefValue {(paramsQtty > 3) ? parameters[3].m_value : ""};

    // If it has more than 4 arguments then an error is raised
    if (paramsQtty > 4)
    {
        throw std::runtime_error(fmt::format("[base::opBuilderHelperCreateAR] -> "
                                             "Failure: Too many arguments"));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};
    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] reference not found",
                    name,
                    (paramsQtty == 4) ? parameters[3].m_value : "")};
    const auto failureTrace2 {fmt::format("[{}] -> Failure: query is empty", name)};
    const auto failureTrace3 {fmt::format(
        "[{}] -> Failure: [{}] reference not found", name, parameters[0].m_value)};
    const auto failureTrace4 {
        fmt::format("[{}] -> Failure: Unable to get agent ID", name)};
    const auto failureTrace5 {
        fmt::format("[{}] -> Failure: inserting event in alert: ", name)};
    const auto failureTrace6 {fmt::format(
        "[{}] -> Failure: Agent ID could not be found", name, parameters[0].m_value)};
    const auto failureTrace7 {fmt::format("[{}] -> Failure: Wrong Agent ID: ", name)};
    const auto failureTrace8 {fmt::format(
        "[{}] -> Failure: Wrong extra argument, a string was expected.", name)};
    const auto failureTrace9 {fmt::format("[{}] -> Failure: Wrong Timeout: ", name)};

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), name = std::move(name)](
            base::Event event) -> base::result::Result<base::Event>
        {
            json::Json baseJson(ar::AR_JSON_FORMAT);

            // TODO: module name and version are fixed values, should it be changed?
            baseJson.setInt(ar::VERSION, ar::VERSION_PATH);

            // TODO: get Node name from ossec.conf -> if not "undefined" -> if not ""
            // it is harcoded by now
            baseJson.setString(ar::NODE_NAME, ar::ORIGIN_NAME_PATH);

            // Set module name
            baseJson.setString(ar::MODULE_NAME, ar::ORIGIN_MODULE_PATH);

            // Get and set command name
            std::string commandNameResolvedValue {};
            if (Parameter::Type::REFERENCE == commandNameType)
            {
                commandNameResolvedValue =
                    event->getString(commandNameValue).value_or("");

                if (commandNameResolvedValue.empty())
                {
                    return base::result::makeFailure(event, failureTrace3);
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
                    return base::result::makeFailure(event, failureTrace3);
                }
            }
            else
            {
                timeoutResolvedValue = timeoutValue;
            }

            if (!ar::isStringNumber(timeoutResolvedValue))
            {
                return base::result::makeFailure(event,
                                                 failureTrace9 + timeoutResolvedValue);
            }

            // Adds the timeout at the end of the command name (or "0" if no timeout set)
            commandNameResolvedValue +=
                timeoutResolvedValue.empty() ? "0" : timeoutResolvedValue;

            baseJson.setString(commandNameResolvedValue, ar::COMMAND_PATH);

            std::optional<std::string> locationResolvedValue {};
            std::string location {locationValue};
            if (Parameter::Type::REFERENCE == locationType)
            {
                locationResolvedValue = event->getString(locationValue);

                if (!locationResolvedValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace3);
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
                    return base::result::makeFailure(event, failureTrace6);
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
                    return base::result::makeFailure(event, failureTrace7 + location);
                }
            }

            if (agentID.empty())
            {
                return base::result::makeFailure(event, failureTrace4);
            }

            // Check existence and not emptyness of extraArgsRefValue if used
            if (!extraArgsRefValue.empty())
            {
                const auto extraArgsArray = event->getArray(extraArgsRefValue);
                if (!extraArgsArray.has_value())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
                else
                {
                    for (const auto arrayElement : extraArgsArray.value())
                    {
                        // fill "extra_args" in json with this array
                        const auto resolvedElement {arrayElement.getString()};

                        if (resolvedElement)
                        {
                            baseJson.appendString(
                                std::string_view {resolvedElement.value()},
                                std::string_view {ar::EXTRA_ARGS_PATH});
                        }
                        else
                        {
                            return base::result::makeFailure(event, failureTrace8);
                        }
                    }
                }
            }

            try
            {
                json::Json jsonEvent {event->str().c_str()};
                baseJson.merge(jsonEvent, std::string_view {ar::ALERT_PATH});
            }
            catch (const std::runtime_error& e)
            {
                return base::result::makeFailure(event, failureTrace5 + e.what());
            }

            const std::string query {baseJson.str()};

            // Append header message
            const std::string completeMesage =
                fmt::format("(local_source) [] N{}{} {} {}",
                            isLocal ? 'R' : 'N',
                            (isAll || isID) ? 'S' : 'N',
                            agentID,
                            query);

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
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 1);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    std::shared_ptr<unixDatagram> socketAR {
        std::make_shared<unixDatagram>(ar::AR_QUEUE_PATH)};

    std::string rValue {};
    const helper::base::Parameter rightParameter {parameters[0]};
    const auto rValueType {rightParameter.m_type};
    rValue = rightParameter.m_value;

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace1 {
        fmt::format("[{}] -> Failure: [{}] not found", name, parameters[0].m_value)};
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
                    const auto failureTraceEx {
                        fmt::format("[{}] -> Failure: [{}]", name, e.what())};
                    return base::result::makeFailure(event, failureTraceEx);
                }
            }
        });
}

} // namespace builder::internals::builders::ar
