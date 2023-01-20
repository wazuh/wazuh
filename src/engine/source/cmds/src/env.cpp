#include <cmds/cmdApiEnvironment.hpp>

#include <iostream>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include "apiclnt/connection.hpp"

namespace cmd
{

namespace
{
constexpr auto API_ENVIRONMENT_COMMAND {"env"};

void setEnv(const std::string& socketPath, const std::string& target)
{
    // target must be start with a '/'
    if (target.empty())
    {
        WAZUH_LOG_ERROR("Engine API Environment: Invalid empty target.");
        return;
    }

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("set", "/action");
    data.setString(target, "/name"); // Skip the first '/'

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    WAZUH_LOG_DEBUG(
        "Engine API Environment: \"{}\" method: Request: \"{}\".", __func__, req.toStr());

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());

        WAZUH_LOG_DEBUG("Engine API Environment: \"{}\" method: Response: \"{}\".",
                        __func__,
                        responseStr);

        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine API Environment: An error occurred while sending a "
                        "request: {}",
                        e.what()); // Doesn't have a closing dot as the lower message does
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        WAZUH_LOG_ERROR("Engine API Environment: Malformed response, no return code "
                        "(\"error\") field found.");
        return;
    }

    const auto msg = response.getString("/message").value_or("OK");
    WAZUH_LOG_INFO("Engine API Environment: Request response: {}.", msg);
    std::cout << msg << std::endl;
}

void getEnv(const std::string& socketPath, const std::string& target)
{

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("get", "/action");

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    WAZUH_LOG_DEBUG(
        "Engine API Environment: \"{}\" method: Request: \"{}\".", __func__, req.toStr());

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());

        WAZUH_LOG_DEBUG("Engine API Environment: \"{}\" method: Response: \"{}\".",
                        __func__,
                        responseStr);

        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine API Environment: An error occurred while sending a "
                        "request: {}",
                        e.what()); // Doesn't have a closing dot as the lower message does
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        WAZUH_LOG_ERROR("Engine API Environment: Malformed response, no return code "
                        "(\"error\") field found.");
        return;
    }

    const auto envs = response.getArray("/data");
    if (!envs)
    {
        WAZUH_LOG_ERROR(
            "Engine API Environment: Malformed response, no \"data\" field found.");
        return;
    }
    else if (envs.value().empty())
    {
        WAZUH_LOG_INFO("Engine API Environment: There are no active environments.");
        return;
    }
    for (const auto& env : *envs)
    {
        if (env.isString())
        {
            const auto msg =
                fmt::format("\"{}\" environment is active", env.getString().value());
            WAZUH_LOG_INFO("Engine API Environment: {}.", msg);
            std::cout << msg << std::endl;
        }
        else
        {
            WAZUH_LOG_ERROR("Engine API Environment: Malformed response, environment "
                            "name is expected to be a string but it is \"{}\".",
                            env.typeName());
        }
    }
}

void deleteEnv(const std::string& socketPath, const std::string& target)
{
    // target must be start with a '/'
    if (target.empty())
    {
        WAZUH_LOG_ERROR("Engine API Environment: An error occurred while trying to "
                        "delete an environment: Target cannot be empty.");
    }

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("delete", "/action");
    data.setString(target, "/name"); // Skip the first '/'

    const auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    WAZUH_LOG_DEBUG(
        "Engine API Environment: \"{}\" method: Request: \"{}\".", __func__, req.toStr());

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());

        WAZUH_LOG_DEBUG("Engine API Environment: \"{}\" method: Response: \"{}\".",
                        __func__,
                        responseStr);

        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Engine API Environment: An error occurred while sending a "
                        "request: {}",
                        e.what()); // Doesn't have a closing dot as the lower message does
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        WAZUH_LOG_ERROR("Engine API Environment: Malformed response, no return code "
                        "(\"error\") field found.");
        return;
    }

    const auto msg = response.getString("/message").value_or("OK");
    WAZUH_LOG_INFO("Engine API Environment: Request response: {}.", msg);
    std::cout << msg << std::endl;
}

} // namespace

void environment(const std::string& socketPath,
                 const std::string& action,
                 const std::string& target)
{
    // TODO: logging level should be configured for every command
    logging::LoggingConfig logConfig;
    logConfig.logLevel = logging::LogLevel::Debug;
    logging::loggingInit(logConfig);

    api::WazuhRequest request {};
    if (action == "set")
    {
        setEnv(socketPath, target);
    }
    else if (action == "get")
    {
        getEnv(socketPath, target);
    }
    else if (action == "delete")
    {
        deleteEnv(socketPath, target);
    }
    else
    {
        WAZUH_LOG_ERROR("Engine API Environment: Invalid action \"{}\", for more "
                        "information use --help.");
        return;
    }

    return;
}
} // namespace cmd
