#include <cmds/metrics.hpp>

#include <iostream>
#include <fstream>


#include <fmt/format.h>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>
#include <metrics/include/metrics.hpp>
#include <logging/logging.hpp>

#include "apiclnt/client.hpp"
#include "base/utils/getExceptionStack.hpp"
#include "defaultSettings.hpp"

namespace cmd::metrics
{

namespace
{

struct Options
{
    std::string socketPath;
    std::string name;
};

} // namespace


namespace details
{
std::string commandName(const std::string& command)
{
    return command + "_metrics";
}

json::Json getParameters(const std::string& action)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    return data;
}

json::Json getParameters(const std::string& action, const std::string& name)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    if (!name.empty())
    {
        data.setString(name, "/name");
    }
    return data;
}

void processResponse(const api::WazuhResponse& response)
{
    if (response.data().size() > 0)
    {
        std::cout << response.data().str() << std::endl;
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
        apiclnt::Client client {socketPath};
        const auto response = client.send(request);
        details::processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return;
    }
}

} // namespace details

void configure(CLI::App_p app)
{
    auto metricApp = app->add_subcommand("metrics", "Manage the engine's Metrics Module.");
    metricApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    metricApp->add_option("-a, --api_socket", options->socketPath, "engine api address")->default_val(ENGINE_API_SOCK);

    // metrics subcommands
    // dump
    auto dump_subcommand = metricApp->add_subcommand("dump", "Prints all collected metrics.");
    dump_subcommand->callback([options]() { runDump(options->socketPath); });

    // get
    auto name = "name";
    std::string nameDesc = "Name that identifies the metric.";

    auto get_subcommand = metricApp->add_subcommand("get", "Print a single metric as json.");
    get_subcommand->add_option(name, options->name, nameDesc)->required();
    get_subcommand->callback([options]() { runGet(options->socketPath, options->name); });
}

void runDump(const std::string& socketPath)
{
    auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_DUMP_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_METRICS_DUMP_SUBCOMMAND));

    details::singleRequest(req, socketPath);
}

void runGet(const std::string& socketPath, const std::string& name)
{

    auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_GET_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_METRICS_GET_SUBCOMMAND, name));

    details::singleRequest(req, socketPath);
}

} // namespace cmd::metrics
