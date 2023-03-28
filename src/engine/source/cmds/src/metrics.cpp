#include <cmds/metrics.hpp>

#include <eMessages/metrics.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>

#include <json/json.hpp>
#include <metrics/include/metrics.hpp>


namespace
{

struct Options
{
    std::string apiEndpoint;
    std::string instrumentName;
    bool enableState;
};

} // namespace

namespace  cmd::metrics
{

namespace eMetrics = ::com::wazuh::api::engine::metrics;
namespace eEngine = ::com::wazuh::api::engine;

void runDump(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eMetrics::Dump_Request;
    using ResponseType = eMetrics::Dump_Response;
    const std::string command = "metrics/dump";

    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void configure(CLI::App_p app)
{
    auto metricApp = app->add_subcommand("metrics", "Manage the engine's Metrics Module.");
    metricApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    metricApp->add_option("-a, --api_socket", options->apiEndpoint, "engine api address")->default_val(ENGINE_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // metrics subcommands
    // dump
    auto dump_subcommand = metricApp->add_subcommand(details::API_METRICS_DUMP_SUBCOMMAND, "Prints all collected metrics.");
    dump_subcommand->callback([options, client]() { runDump(client);});

    // // get
    // auto get_subcommand = metricApp->add_subcommand("get", "Print a single metric as json.");
    // get_subcommand->add_option("Instrument name", options->instrumentName, "Name that identifies the instrument.")
    //     ->required();
    // get_subcommand->callback([options]() { runGetInstrument(options->socketPath, options->instrumentName); });

    // // enable
    // auto enable_subcommand = metricApp->add_subcommand("enable", "Enable or disable a specific instrument.");
    // enable_subcommand
    //     ->add_option(
    //         "Instrument name", options->instrumentName, "Name of the instrument whose status will be modified.")
    //     ->default_val("");
    // enable_subcommand->add_option("Enable state", options->enableState, "New instrument status.")->default_val(true);
    // enable_subcommand->callback(
    //     [options]() { runEnableInstrument(options->socketPath, options->instrumentName, options->enableState); });

    // // list
    // auto list_subcommand = metricApp->add_subcommand("list", "Prints name, status and instruments types.");
    // list_subcommand->callback([options]() { runListInstruments(options->socketPath); });

    // // test
    // auto test_subcommand = metricApp->add_subcommand("test", "Generate dummy metrics for testing.");
    // test_subcommand->callback([options]() { runTest(options->socketPath); });
}


// void runGetInstrument(const std::string& socketPath, const std::string& name)
// {

//     auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_GET_SUBCOMMAND),
//                                          details::ORIGIN_NAME,
//                                          details::getParameters(details::API_METRICS_GET_SUBCOMMAND, name));

//     details::singleRequest(req, socketPath);
// }

// void runEnableInstrument(const std::string& socketPath, const std::string& nameInstrument, bool enableState)
// {
//     json::Json params;
//     params.setObject();
//     if (!nameInstrument.empty())
//     {
//         params.setString(nameInstrument, "/nameInstrument");
//     }

//     params.setBool(enableState, "/enableState");

//     auto req = api::WazuhRequest::create(
//         details::commandName(details::API_METRICS_ENABLE_SUBCOMMAND), details::ORIGIN_NAME, params);

//     details::singleRequest(req, socketPath);
// }

// void runListInstruments(const std::string& socketPath)
// {
//     auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_LIST_SUBCOMMAND),
//                                          details::ORIGIN_NAME,
//                                          details::getParameters(details::API_METRICS_LIST_SUBCOMMAND));

//     details::singleRequest(req, socketPath);
// }

// void runTest(const std::string& socketPath)
// {
//     auto req = api::WazuhRequest::create(details::commandName(details::API_METRICS_TEST_SUBCOMMAND),
//                                          details::ORIGIN_NAME,
//                                          details::getParameters(details::API_METRICS_TEST_SUBCOMMAND));

//     details::singleRequest(req, socketPath);
// }

} // namespace cmd::metrics
