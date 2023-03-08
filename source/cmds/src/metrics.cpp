#include <cmds/metrics.hpp>

#include <fstream>
#include <iostream>

#include <fmt/format.h>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>
#include <logging/logging.hpp>
#include <metrics/include/metrics.hpp>

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
    std::string instrumentName;
    bool enableState;
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
    auto get_subcommand = metricApp->add_subcommand("get", "Print a single metric as json.");
    get_subcommand->add_option("Instrument name", options->instrumentName, "Name that identifies the instrument.")
        ->required();
    get_subcommand->callback([options]() { runGetInstrument(options->socketPath, options->instrumentName); });

    // enable
    auto enable_subcommand = metricApp->add_subcommand("enable", "Enable or disable a specific instrument.");
    enable_subcommand
        ->add_option(
            "Instrument name", options->instrumentName, "Name of the instrument whose status will be modified.")
        ->default_val("");
    enable_subcommand->add_option("Enable state", options->enableState, "New instrument status.")->default_val(true);
    enable_subcommand->callback(
        [options]() { runEnableInstrument(options->socketPath, options->instrumentName, options->enableState); });

    // list
    auto list_subcommand = metricApp->add_subcommand("list", "Prints name, status and instruments types.");
    list_subcommand->callback([options]() { runListInstruments(options->socketPath); });
}

void runDump(const std::string& socketPath)
{
    auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_DUMP_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_METRICS_DUMP_SUBCOMMAND));

    details::singleRequest(req, socketPath);
}

void runGetInstrument(const std::string& socketPath, const std::string& name)
{

    auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_GET_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_METRICS_GET_SUBCOMMAND, name));

    details::singleRequest(req, socketPath);
}

void runEnableInstrument(const std::string& socketPath, const std::string& nameInstrument, bool enableState)
{
    json::Json params;
    params.setObject();
    if (!nameInstrument.empty())
    {
        params.setString(nameInstrument, "/nameInstrument");
    }

    params.setBool(enableState, "/enableState");

    auto req = api::WazuhRequest::create(
        details::commandName(details::API_METRICS_ENABLE_SUBCOMMAND), details::ORIGIN_NAME, params);

    details::singleRequest(req, socketPath);
}

void runListInstruments(const std::string& socketPath)
{
    auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_LIST_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_METRICS_LIST_SUBCOMMAND));

    details::singleRequest(req, socketPath);
}

} // namespace cmd::metrics
