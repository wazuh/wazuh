#include <cmds/env.hpp>

#include <iostream>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include "apiclnt/sendReceive.hpp"
#include "defaultSettings.hpp"

namespace cmd::env
{

namespace
{
struct Options
{
    std::string socketPath;
    std::string target;
};
} // namespace

namespace details
{
std::string commandName(const std::string& command)
{
    return "env";
}

json::Json getParameters(const std::string& action, const std::string& target)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    if (!target.empty())
    {
        data.setString(target, "/name");
    }
    return data;
}

void processResponse(const api::WazuhResponse& response)
{
    if (response.data().size() > 0)
    {
        std::cout << response.data().prettyStr() << std::endl;
    }
    else
    {
        std::cout << response.message().value_or("") << std::endl;
    }
}

void singleRequest(const api::WazuhRequest& request, const std::string& socketPath)
{
    try
    {
        auto response = apiclnt::sendReceive(socketPath, request);
        details::processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

} // namespace details

void runSet(const std::string& socketPath, const std::string& target)
{
    // create request
    auto request = api::WazuhRequest::create(
        details::commandName("set"), details::ORIGIN_NAME, details::getParameters("set", target));

    details::singleRequest(request, socketPath);
}

void runGet(const std::string& socketPath)
{
    // Create a request
    auto request =
        api::WazuhRequest::create(details::commandName("get"), details::ORIGIN_NAME, details::getParameters("get"));

    details::singleRequest(request, socketPath);
}

void runDel(const std::string& socketPath, const std::string& target)
{
    // Create a request
    auto request = api::WazuhRequest::create(
        details::commandName("delete"), details::ORIGIN_NAME, details::getParameters("delete", target));

    details::singleRequest(request, socketPath);
}

void configure(CLI::App_p app)
{
    auto envApp = app->add_subcommand("env", "Manage the running environments.");
    envApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    envApp->add_option("-a, --api_socket", options->socketPath, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK);

    // Subcommands
    // Action: get
    auto get_subcommand = envApp->add_subcommand("get", "Get active environments.");
    get_subcommand->callback([options]() { runGet(options->socketPath); });

    // Action: set
    auto set_subcommand = envApp->add_subcommand("set", "Set an environments to be active.");
    set_subcommand->add_option("environment", options->target, "Name of the environment to be set.")->required();
    set_subcommand->callback([options]() { runSet(options->socketPath, options->target); });

    // Action: delete
    auto delete_subcommand = envApp->add_subcommand("delete", "Delete an environment.");
    delete_subcommand->add_option("environment", options->target, "Name of the environment to be deleted.")->required();
    delete_subcommand->callback([options]() { runDel(options->socketPath, options->target); });
}
} // namespace cmd::env
