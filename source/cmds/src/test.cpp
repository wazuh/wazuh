#include "cmds/test.hpp"

#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/test.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::test
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::RunPost_Request;
    using ResponseType = eTest::RunPost_Response;
    const std::string command {"test.run/post"};

    // Set policy name
    RequestType eRequest;
    eRequest.set_name(parameters.sessionName);

    // Set protocol queue
    eRequest.set_protocolqueue(parameters.protocolQueue);

    // Set debug mode
    auto intToDebugMode = [](int debugModeValue) -> eTest::DebugMode
    {
        switch (debugModeValue)
        {
            case 0: return eTest::DebugMode::OUTPUT_ONLY;
            case 1: return eTest::DebugMode::OUTPUT_AND_TRACES;
            case 2: return eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS;
            default: return eTest::DebugMode::OUTPUT_ONLY;
        }
    };
    eRequest.set_debugmode(intToDebugMode(parameters.debugLevel));

    // Set location
    eRequest.set_protocollocation(parameters.protocolLocation);

    // Set event
    json::Json jevent {};
    try
    {
        jevent = json::Json {parameters.event.c_str()};
    }
    catch (const std::exception& e)
    {
        // If not, set it as a string
        jevent.setString(parameters.event);
    }

    // Convert the value to protobuf value
    const auto protoEvent = eMessage::eMessageFromJson<google::protobuf::Value>(jevent.str());
    if (std::holds_alternative<base::Error>(protoEvent)) // Should not happen but just in case
    {
        const auto msj = std::get<base::Error>(protoEvent).message + ". For value " + jevent.str();
        throw ::cmd::ClientException(msj, ClientException::Type::PROTOBUFF_SERIALIZE_ERROR);
    }

    const auto& event = std::get<google::protobuf::Value>(protoEvent);
    *eRequest.mutable_event() = event;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print results
    if (eTest::DebugMode::OUTPUT_AND_TRACES == eRequest.debugmode()
        || eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS == eRequest.debugmode())
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
    auto parameters = std::make_shared<Parameters>();

    logtestApp->add_option("-a, --api_socket", parameters->apiEndpoint, "engine api address")
        ->default_val(ENGINE_SRV_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint);

    // Policy
    logtestApp->add_option("--name", parameters->sessionName, "Name of the session to be used.")->required();

    // Event
    logtestApp->add_option("--event", parameters->event, "Event to be processed")->required();

    logtestApp
        ->add_option(
            "-q, --protocol_queue", parameters->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(ENGINE_PROTOCOL_QUEUE);

    // Debug levels
    logtestApp->add_flag("-d, --debug",
                         parameters->debugLevel,
                         "Enable debug mode [0-3]. Flag can appear multiple times. "
                         "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                         "Full tracing, ddd[3]: 2 + detailed parser trace.");

    logtestApp->add_option("--protocol_location", parameters->protocolLocation, "Protocol location.")
        ->default_val(ENGINE_PROTOCOL_LOCATION);

    // Register callback
    logtestApp->callback([parameters, client]() { run(client, *parameters); });
}
} // namespace cmd::test
