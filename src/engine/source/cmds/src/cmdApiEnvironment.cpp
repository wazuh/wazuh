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
    // target must be start with a '/'
    if (target.empty())
    {
        std::cerr << "Engine API Environment: Invalid empty target." << std::endl;
        return;
    }

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("set", "/action");
    data.setString(target, "/name"); // Skip the first '/'

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << fmt::format("Engine API Environment: An error occurred while "
                                 "sending the request \"{}\": {}",
                                 req.toStr(),
                                 e.what())
                  << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        std::cerr << fmt::format("Engine API Environment: Malformed response, no return "
                                 "code (\"error\") field found: \"{}\".",
                                 responseStr) << std::endl;
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

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << fmt::format("Engine API Environment: An error occurred while "
                                 "sending the request \"{}\": {}",
                                 req.toStr(),
                                 e.what())
                  << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        std::cerr << fmt::format("Engine API Environment: Malformed response, no return "
                                 "code (\"error\") field found: \"{}\".",
                                 responseStr) << std::endl;
        return;
    }

    auto envs = response.getArray("/data");
    if (!envs)
    {
        std::cerr << fmt::format("Engine API Environment: Malformed response, no return "
                                 "code (\"data\") field found: \"{}\".",
                                 responseStr) << std::endl;
        return;
    }
    else if (envs.value().empty())
    {
        std::cout << "There are no active environments." << std::endl;
        return;
    }
    for (const auto& env : *envs)
    {
        std::cout << "Active environment: "
                  << env.getString().value_or("** Unexpected Error **") << std::endl;
    }
}


void deleteEnv(const std::string& socketPath, const std::string& target)
{
    // target must be start with a '/'
    if (target.empty())
    {
        std::cerr << "Engine API Environment: Delete environment: Target cannot be empty."
                  << std::endl;
    }

    // Create a request
    json::Json data {};
    data.setObject();
    data.setString("delete", "/action");
    data.setString(target, "/name"); // Skip the first '/'

    auto req = api::WazuhRequest::create(API_ENVIRONMENT_COMMAND, "api", data);

    // Send the request
    json::Json response {};
    std::string responseStr {};
    try
    {
        responseStr = apiclnt::connection(socketPath, req.toStr());
        response = json::Json {responseStr.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << fmt::format("Engine API Environment: An error occurred while "
                                 "sending the request \"{}\": {}",
                                 req.toStr(),
                                 e.what())
                  << std::endl;
        return;
    }

    if (response.getInt("/error").value_or(-1) != 0)
    {
        std::cerr << fmt::format("Engine API Environment: Malformed response, no return "
                                 "code (\"error\") field found: \"{}\".",
                                 responseStr) << std::endl;
        return;
    }

    std::cout << response.getString("/message").value_or("OK");
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
    else if (action == "delete")
    {
        deleteEnv(socketPath, target);
    }
    else
    {
        std::cerr << "Engine API Environment: Invalid action, expected \"set\" or "
                     "\"get\" but got \""
                  << action << "\"." << std::endl;
        return;
    }

    return;
}
} // namespace cmd
