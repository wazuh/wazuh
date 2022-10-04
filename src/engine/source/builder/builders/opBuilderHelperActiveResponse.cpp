/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "opBuilderHelperActiveResponse.hpp"

#include <optional>
#include <string>
#include <string_view>

#include <baseHelper.hpp>

namespace ar
{
// create a base JSON object
json::Json baseJson(R"({
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
    })");

// Paths
constexpr auto AGENT_ID_PATH = "/agent/id";
constexpr auto ORIGIN_NAME_PATH = "/origin/name";
constexpr auto ORIGIN_MODULE_PATH = "/origin/module";
constexpr auto COMMAND_PATH = "/command";
constexpr auto VERSION_PATH = "/version";
constexpr auto ALERT_PATH = "/parameters/alert";
constexpr auto EXTRA_ARGS_PATH = "/parameters/extra_args";

// values
constexpr auto NODE_NAME = "node01";
constexpr auto MODULE_NAME = "wazuh-analysisd";
constexpr int VERSION = 1;
constexpr int AGENT_NONE = -1;

}

namespace builder::internals::builders
{

// _ar_message: +ar_message/<event_original_path>/<command-name>/<location>/<timeout>/<$_args>
base::Expression opBuilderHelperActiveResponse(const std::any& definition)
{
    //TODO: check if Active response is enabled first, if not throw runtime_error
    //for this create ActiveResponse Object with init from main.cpp

    // Extract parameters from definition
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);

    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};

    // Assert expected number of parameters
    helper::base::checkParametersMinSize(parameters, 3);

    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Get event original path
    helper::base::checkParameterType(parameters[0], helper::base::Parameter::Type::REFERENCE);
    const auto eventOriginalPath {parameters[0].m_value};

    // Get command-name -> mandatory presence being value or reference
    const helper::base::Parameter commandName {parameters[1]};
    const auto commandNameType {commandName.m_type};
    std::string commandNameValue = commandName.m_value;

    // Get Location -> mandatory value
    // Not checking location value because nothing will be executed on manager
    helper::base::checkParameterType(parameters[2], helper::base::Parameter::Type::VALUE);
    const auto location {parameters[2].m_value};
    if(location.empty())
    {
        throw std::runtime_error(fmt::format("[base::opBuilderHelperActiveResponse] -> "
                                             "Failure: <location> shouldn't be empty"));
    }

    // Get timeout first optional parameter
    const auto parametersSize = parameters.size();
    std::string timeoutField;
    if(parametersSize > 2)
    {
        timeoutField = parameters[3].m_value;
    }

    // Get _args seccond optional parameter -> should be an array
    std::string argsRef;
    if(parametersSize > 3)
    {
        helper::base::checkParameterType(parameters[4], helper::base::Parameter::Type::REFERENCE);
        argsRef = parameters[4].m_value;
    }

    // If it has more than 4 arguments then it's an error
    if(parametersSize > 5)
    {
        throw std::runtime_error(fmt::format("[base::opBuilderHelperActiveResponse] -> "
                                             "Failure: Too many arguments"));
    }

    // Tracing
    const auto successTrace {fmt::format("[{}] -> Success", name)};
    const auto failureTrace1 {fmt::format("[{}] -> Failure: [{}] not found", name, parameters[4].m_value)};
    const auto failureTrace2 {fmt::format("[{}] -> Failure: query is empty", name)};
    const auto failureTrace3 {fmt::format("[{}] -> Failure: [{}] reference not found", name, parameters[1].m_value)};
    const auto failureTrace4 {fmt::format("[{}] -> Failure: Unable to get agent ID", name)};
    const auto failureTrace5 {fmt::format("[{}] -> Failure: [{}] reference not found or not JSON object", name, parameters[0].m_value)};
    const auto failureTrace6 {fmt::format("[{}] -> Failure: inserting event in alert", name)};

    // Function that implements the helper
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         eventOriginalPath = std::move(eventOriginalPath),
         targetField = std::move(targetField),
         location = std::move(location),
         timeoutField = std::move(timeoutField),
         argsRef = std::move(argsRef),
         name = std::move(name)](base::Event event) -> base::result::Result<base::Event> {
            // TODO: module name and version are fixed values, should be changed?
            ar::baseJson.setInt(ar::VERSION, ar::VERSION_PATH);

            // TODO: get Node name from ossec.conf -> if not "undefined" -> if not ""
            // harcoded for now
            ar::baseJson.setString(ar::NODE_NAME, ar::ORIGIN_NAME_PATH);

            // Set module name
            ar::baseJson.setString(ar::MODULE_NAME, ar::ORIGIN_MODULE_PATH);

            // Get and set command name
            if (helper::base::Parameter::Type::REFERENCE == commandNameType)
            {
                auto commandNameResolvedValue {event->getString(commandNameValue)};

                if (!commandNameResolvedValue.has_value())
                {
                    return base::result::makeFailure(event, failureTrace3);
                }
                else
                {
                    ar::baseJson.setString(commandNameResolvedValue.value(), ar::COMMAND_PATH);
                }
            }
            else
            {
                ar::baseJson.setString(commandNameValue, ar::COMMAND_PATH);
            }

            int agentID {ar::AGENT_NONE};
            // Check location
            if (!location.compare("LOCAL"))
            {
                agentID = std::stoi(event->getString(ar::AGENT_ID_PATH).value());
            }
            else if (!location.compare("ALL"))
            {
                // TODO: rigt now not supported (won't be hadled in the Execd)
                // but send a keyword either way
            }
            else
            {
                // Specific ID
                agentID = std::stoi(location);
            }

            if(agentID == ar::AGENT_NONE)
            {
                return base::result::makeFailure(event, failureTrace4);
            }

            // Check existence and not emptyness of argsRef if used
            if (!argsRef.empty())
            {
                const auto extraArgsArray = event->getArray(argsRef);
                if (!extraArgsArray.has_value())
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
                else
                {
                    for (const auto arrayElement : extraArgsArray.value())
                    {
                        // fill "extra_args" in json with this array
                        ar::baseJson.appendString(
                            std::string_view {arrayElement.getString().value()},
                            std::string_view {ar::EXTRA_ARGS_PATH});
                    }
                }
            }

            // Set alert field from event
            if(!event->exists(eventOriginalPath) && !event->isObject(eventOriginalPath))
            {
                return base::result::makeFailure(event, failureTrace5);
            }

            json::Json jsonObjectEvent{event->getString(eventOriginalPath).value().c_str()};
            try
            {
                ar::baseJson.merge(jsonObjectEvent, std::string_view {ar::ALERT_PATH});
            }
            catch(const std::runtime_error& e)
            {
                return base::result::makeFailure(event, failureTrace6 + e.what());
            }

            std::string query {ar::baseJson.str()};

            // Append header message
            const std::string completeMesage =
                fmt::format("(local_source) [] N{}{} {} {}",
                            !location.compare("LOCAL") ? 'R' : 'N',
                            !location.compare("ALL") ? 'S' : 'N',
                            agentID,
                            query);

            event->setString(completeMesage, targetField);
            return base::result::makeSuccess(event, successTrace);

        });
}

} // namespace builder::internals::builders
