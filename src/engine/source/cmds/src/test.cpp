#include "cmds/test.hpp"

#include <api/test/handlers.hpp>
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
    const std::string command {api::test::handlers::TEST_RUN_API_CMD};

    // Set policy name
    RequestType eRequest;
    eRequest.set_name(parameters.sessionName);

    // Set protocol queue
    eRequest.set_protocol_queue(parameters.protocolQueue);

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
    eRequest.set_debug_mode(intToDebugMode(parameters.debugLevel));

    // Set location
    eRequest.set_protocol_location(parameters.protocolLocation);

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
    if (eTest::DebugMode::OUTPUT_AND_TRACES == eRequest.debug_mode()
        || eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS == eRequest.debug_mode())
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

void sessionCreate(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionPost_Request;
    using ResponseType = eTest::SessionPost_Response;
    const std::string command {api::test::handlers::TEST_POST_SESSION_API_CMD};

    RequestType eRequest;

    // Set session name
    eRequest.set_name(parameters.sessionName);

    // Set policy name
    eRequest.set_policy(parameters.policy);

    // Set lifespan
    eRequest.set_lifespan(parameters.lifespan);

    if (!parameters.description.empty())
    {
        eRequest.set_description(parameters.description);
    }

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void sessionDelete(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionsDelete_Request;
    using ResponseType = eTest::SessionsDelete_Response;
    const std::string command {api::test::handlers::TEST_DELETE_SESSIONS_API_CMD};

    RequestType eRequest;

    if (parameters.deleteAll)
    {
        // Set delete all flag
        eRequest.set_delete_all(true);
    }
    else if (!parameters.sessionName.empty())
    {
        // Set session name
        eRequest.set_name(parameters.sessionName);
    }
    else
    {
        std::cerr << "Sessions delete configuration error: Please provide either --name parameter or --all flag."
                  << std::endl;
        return;
    }

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void sessionGet(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionGet_Request;
    using ResponseType = eTest::SessionGet_Response;
    const std::string command {api::test::handlers::TEST_GET_SESSION_DATA_API_CMD};

    RequestType eRequest;

    // Set session name
    eRequest.set_name(parameters.sessionName);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    const auto output = fmt::format(R"({{"id":"{}","creation_date":"{}","policy":"{}", "filter":"{}","route":"{}",)"
                                    R"("lifespan":{},"description":"{}"}})",
                                    eResponse.id(),
                                    eResponse.creation_date(),
                                    eResponse.policy(),
                                    eResponse.filter(),
                                    eResponse.route(),
                                    eResponse.lifespan(),
                                    eResponse.description());

    std::cout << output << std::endl;
}

void sessionList(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionsGet_Request;
    using ResponseType = eTest::SessionsGet_Response;
    const std::string command {api::test::handlers::TEST_GET_SESSIONS_LIST_API_CMD};

    // Call the API
    RequestType eRequest;
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    for (const auto& str : eResponse.list())
    {
        std::cout << str << std::endl;
    }
}

void configure(CLI::App_p app)
{
    auto testApp = app->add_subcommand("test", "Utility to test events.");
    auto parameters = std::make_shared<Parameters>();

    testApp->add_option("-a, --api_socket", parameters->apiEndpoint, "Set the API socket path.")
        ->default_val(ENGINE_SRV_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint);

    // API test manage sessions
    auto testSessionApp = testApp->add_subcommand("session", "Manage API sessions.");

    // API test session create
    auto testSessionCreateApp = testSessionApp->add_subcommand("create", "Create a new session.");
    testSessionCreateApp->add_option("-n, --name", parameters->sessionName, "Name of the new session.")->required();
    testSessionCreateApp->add_option("-p, --policy", parameters->policy, "Policy to be used.")
        ->default_val(api::test::handlers::DEFAULT_POLICY_FULL_NAME);
    testSessionCreateApp->add_option("-l, --lifespan", parameters->lifespan, "Lifespan of the session in minutes.")
        ->default_val(api::test::handlers::DEFAULT_SESSION_LIFESPAN);
    testSessionCreateApp->add_option("-d, --description", parameters->description, "Description of the session.");
    testSessionCreateApp->callback([parameters, client]() { sessionCreate(client, *parameters); });

    // API test session delete
    auto testSessionDeleteApp = testSessionApp->add_subcommand("delete", "Delete sessions.");
    testSessionDeleteApp->add_option("-n, --name", parameters->sessionName, "Name of the session to be deleted.");
    testSessionDeleteApp->add_flag("--all", parameters->deleteAll, "Delete all the sessions.");
    testSessionDeleteApp->callback([parameters, client]() { sessionDelete(client, *parameters); });

    // API test session data get
    auto testSessionGetApp = testSessionApp->add_subcommand("get", "Get a session data.");
    testSessionGetApp->add_option("-n, --name", parameters->sessionName, "Name of the session to be obtained.")
        ->required();
    testSessionGetApp->callback([parameters, client]() { sessionGet(client, *parameters); });

    // API test session list
    auto testSessionListApp = testSessionApp->add_subcommand("list", "List sessions.");
    testSessionListApp->callback([parameters, client]() { sessionList(client, *parameters); });

    /** ************************************************************************************************************ */

    // API test Run
    auto testRunApp = testApp->add_subcommand("run", "Utility to run a test.");
    testRunApp->add_option("-n, --name", parameters->sessionName, "Name of the session to be used.")->required();
    testRunApp->add_option("-e, --event", parameters->event, "Event to be processed")->required();
    testRunApp
        ->add_option(
            "-q, --protocol_queue", parameters->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(ENGINE_PROTOCOL_QUEUE);
    testRunApp->add_flag("-d, --debug",
                         parameters->debugLevel,
                         "Enable debug mode [0-3]. Flag can appear multiple times. "
                         "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                         "Full tracing, ddd[3]: 2 + detailed parser trace.");
    testRunApp->add_option("--protocol_location", parameters->protocolLocation, "Protocol location.")
        ->default_val(ENGINE_PROTOCOL_LOCATION);
    testRunApp->callback([parameters, client]() { run(client, *parameters); });
}

} // namespace cmd::test
