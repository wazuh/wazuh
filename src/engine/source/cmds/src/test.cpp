#include "cmds/test.hpp"

#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/tests.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::test
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

void run(std::shared_ptr<apiclnt::Client> client, const Options& options)
{
    using RequestType = eTest::Run_Request;
    using ResponseType = eTest::Run_Response;
    const std::string command {"test.resource/run"};

    // Set policy name
    RequestType eRequest;
    eRequest.set_policy(options.policyName);

    // Set protocol queue
    eRequest.set_protocolqueue(options.protocolQueue);

    // Set debug mode
    auto intToDebugMode = [](int debugModeValue) -> eTest::DebugMode
    {
        std::unordered_map<int, ::com::wazuh::api::engine::test::DebugMode> debugModeMap =
        {
            {0, eTest::DebugMode::ONLY_OUTPUT},
            {1, eTest::DebugMode::OUTPUT_AND_TRACES},
            {2, eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS}
        };
        if (debugModeMap.find(debugModeValue) != debugModeMap.end())
        {
            return debugModeMap[debugModeValue];
        }
        else
        {
            return eTest::DebugMode::ONLY_OUTPUT;
        }
    };
    eRequest.set_debugmode(intToDebugMode(options.debugLevel));

    // Set event
    const auto jsonEvent = eMessage::eMessageFromJson<google::protobuf::Value>(options.event);
    const auto eventValue = std::get<google::protobuf::Value>(jsonEvent);
    eRequest.mutable_event()->CopyFrom(eventValue);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print results
    if (eTest::DebugMode::OUTPUT_AND_TRACES == eRequest.debugmode() ||
        eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS == eRequest.debugmode())
    {
        const auto& traces = eResponse.traces();
        const auto jsonDecoders = eMessage::eMessageToJson<google::protobuf::Value>(traces);
        std::cerr << std::endl << std::endl << "DECODERS:" << std::endl << std::endl;
        std::cout << std::get<std::string>(jsonDecoders) << std::endl;
    }

    const auto& output = eResponse.output();
    const auto jsonOutput = eMessage::eMessageToJson<google::protobuf::Value>(output);
    std::cerr << std::endl << std::endl << "OUTPUT:" << std::endl << std::endl;
    std::cout << std::get<std::string>(jsonOutput) << std::endl;
}

void configure(CLI::App_p app)
{
    auto logtestApp = app->add_subcommand("test", "Utility to test the ruleset.");
    auto options = std::make_shared<Options>();

    logtestApp->add_option("-a, --api_socket", options->apiEndpoint, "engine api address")
        ->default_val(ENGINE_SRV_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // Policy
    logtestApp->add_option("--policy", options->policyName, "Name of the policy to be used.")
        ->default_val(ENGINE_DEFAULT_POLICY);

    // Event
    logtestApp->add_option("--event", options->event, "Event to be processed")->required();

    logtestApp->add_option(
            "-q, --protocol_queue", options->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(ENGINE_PROTOCOL_QUEUE);

    // Debug levels
    logtestApp->add_flag("-d, --debug",
                                    options->debugLevel,
                                    "Enable debug mode [0-3]. Flag can appear multiple times. "
                                    "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                                    "Full tracing, ddd[3]: 2 + detailed parser trace.")->default_val(0);

    // Register callback
    logtestApp->callback([options, client]() { run(client, *options); });
}
} // namespace cmd::test
