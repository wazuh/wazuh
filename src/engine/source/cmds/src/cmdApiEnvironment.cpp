#include <cmds/cmdApiEnvironment.hpp>

#include <iostream>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <utils/stringUtils.hpp>

#include "apiclnt/connection.hpp"

namespace cmd
{

namespace
{
constexpr auto API_ENVIRONMENT_COMMAND {"env"};

void setEnv(const std::string& socketPath, const std::string& target)
{
    // split
    const auto parts = utils::string::split(target, '/');
    if (parts.size() != 4 || parts[0] != "" || parts[1] != "env")
    {
        std::cerr << "Invalid target, expected [/env/env-id/version] but got [" << target
                  << "]" << std::endl;
        return;
    }

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("set", "/action");
    data.setString(parts[2], "/name");
    data.setString(parts[3], "/version");

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, data);

    // Send the request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        responseStr =
            responseStr.data() + sizeof(int); // TODO delete this after change conneccion
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        std::cerr << "Error setting environment: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    std::cout << response.getString("/message").value_or("OK");
}

void getEnv(const std::string& socketPath, const std::string& target)
{

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("get", "/action");

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, data);

    // Send the request
    json::Json response {};
    try
    {
        auto responseStr = apiclnt::connection(socketPath, req.toStr());
        responseStr =
            responseStr.data() + sizeof(int); // TODO delete this after change conneccion
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error sending request: " << e.what() << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        std::cerr << "Error getting environment: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }

    auto envs = response.getArray("/data");
    if (!envs)
    {
        std::cerr << "Error getting environment: "
                  << response.getString("/message").value_or("-") << std::endl;
        return;
    }
    else if (envs.value().empty())
    {
        std::cout << "No active environments found" << std::endl;
        return;
    }
    for (const auto& env : *envs)
    {
        std::cout << "Active environment: "
                  << env.getString("/").value_or("** Unexpected Error **") << std::endl;
    }
}

} // namespace

void environment(const std::string& socketPath,
                 const std::string& action,
                 const std::string& target)
{

    api::WazuhRequest request {};
    if (action == "set")
    {
        setEnv(socketPath, target);
    }
    else if (action == "get")
    {
        getEnv(socketPath, target);
    }
    else
    {
        std::cerr << "Invalid action, expected [set] or [get] but got [" << action << "]"
                  << std::endl;
        return;
    }

    return;
}
} // namespace cmd
