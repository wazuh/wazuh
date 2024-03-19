#include "cmds/tester.hpp"

#include <iostream>
#include <unistd.h>

#include <google/protobuf/util/json_util.h>

#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/tester.pb.h>
#include <yml/yml.hpp>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace
{

bool gs_doRun {true};

/**
 * @brief Signal handler for SIGINT
 *
 * @param signum Signal number
 */
void sigintHandler(const int signalNumber)
{
    gs_doRun = false;
}

/**
 * @brief Toggles the canonical mode of the terminal.
 *
 * This function modifies the terminal settings to enable or disable canonical mode,
 * depending on the value of the parameter 'doClearIcanon'. When canonical mode is enabled,
 * input is processed line by line; when disabled, input is processed character by character.
 *
 * @param doClearIcanon Flag indicating whether to clear or set the ICANON flag.
 *        - 'true' clears the ICANON flag, disabling canonical mode.
 *        - 'false' sets the ICANON flag, enabling canonical mode.
 *
 * @return Returns 'true' if the operation succeeds and 'false' otherwise.
 */
inline bool clearIcanon(const bool& doClearIcanon)
{
    bool retval {false};
    struct termios settings = {};

    if (tcgetattr(STDIN_FILENO, &settings) >= 0)
    {
        retval = true;

        if (doClearIcanon)
        {
            settings.c_lflag &= ~ICANON;
        }
        else
        {
            settings.c_lflag |= ICANON;
        }

        if (tcsetattr(STDIN_FILENO, TCSANOW, &settings) < 0)
        {
            retval = false;
        }
    }

    return retval;
}



} // namespace

namespace cmd::tester
{

namespace eTest = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;

void processEvent(const std::string& eventStr,
                  const Parameters& parameters,
                  std::shared_ptr<apiclnt::Client> client,
                  eTest::RunPost_Request eRequest)
{
    using RequestType = eTest::RunPost_Request;
    using ResponseType = eTest::RunPost_Response;
    const std::string command {"tester.run/post"};

    // Set event
    json::Json jsonEvent {};
    jsonEvent.setString(eventStr);

    // Convert the value to protobuf value
    const auto protoEvent = eMessage::eMessageFromJson<google::protobuf::Value>(jsonEvent.str());
    if (std::holds_alternative<base::Error>(protoEvent)) // Should not happen but just in case
    {
        const auto msj = std::get<base::Error>(protoEvent).message + ". For value " + jsonEvent.str();
        throw ::cmd::ClientException(msj, ClientException::Type::PROTOBUFF_SERIALIZE_ERROR);
    }

    const auto& event = std::get<google::protobuf::Value>(protoEvent);
    eRequest.set_message(event.string_value());

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print results
    // TODO Check if eResponse.run().output() is empty and errroe in message to json string
    std::string jsonOutputAndTrace;
    google::protobuf::util::MessageToJsonString(eResponse.result().output(), &jsonOutputAndTrace);

    if (parameters.jsonFormat)
    {
        json::Json jPrint {};
        auto jOutput =  json::Json{jsonOutputAndTrace.c_str()};
        jPrint.set("/output", jOutput);
        for (const auto& data : eResponse.result().asset_traces())
        {
            std::string jdataStr {};
            google::protobuf::util::MessageToJsonString(data, &jdataStr);
            auto jTrace = json::Json{jdataStr.c_str()};
            jPrint.appendJson(jTrace, "/traces");
        }
        std::cout << jPrint.str() << std::endl;
    }
    else
    {
        if (eResponse.result().asset_traces_size() != 0) {
            std::cout << "Traces:\n" ;

            for (const auto& data : eResponse.result().asset_traces())
            {

                std::cout << (data.success() ? std::string("[🟢] ") : std::string("[🔴] "));
                std::cout << data.asset() << (data.success() ? std::string(" -> success") : std::string(" -> failed"));
                std::cout << std::endl;
                for (const auto& trace : data.traces())
                {
                    std::cout << "  ↳ " << trace << "\n";
                }

            }
        }

        std::cout << "\n" << yml::utils::ymlToPrettyYaml(jsonOutputAndTrace, true) << "\n\n";

    }
}

void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    const std::string commandGet {"tester.session/get"};

    // Set signal [SIGINT]: Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler = {};
        sigIntHandler.sa_handler = sigintHandler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }
    // Set signal [EPIPE]: Broken pipe handler
    {
        // Set the signal handler for EPIPE (uvw/libuv/libev)
        // https://github.com/skypjack/uvw/issues/291
        struct sigaction sigPipeHandler = {};
        sigPipeHandler.sa_handler = SIG_IGN;
        sigemptyset(&sigPipeHandler.sa_mask);
        sigPipeHandler.sa_flags = 0;
        sigaction(SIGPIPE, &sigPipeHandler, nullptr);
    }

    // Check that the session exists before executing the run command
    eTest::SessionGet_Request eGetRequest;
    eGetRequest.set_name(parameters.sessionName);
    const auto getRequest =
        utils::apiAdapter::toWazuhRequest<eTest::SessionGet_Request>(commandGet, details::ORIGIN_NAME, eGetRequest);
    const auto responseGet = client->send(getRequest);
    const auto eResponseGet = utils::apiAdapter::fromWazuhResponse<eTest::SessionGet_Response>(responseGet);

    // Call run command

    using RequestType = eTest::RunPost_Request;
    using ResponseType = eTest::RunPost_Response;

    const std::string command {"tester.run/post"};

    // Set policy name
    RequestType eRequest;
    eRequest.set_name(parameters.sessionName);

    // Set protocol queue
    eRequest.set_queue(parameters.protocolQueue);

    // Set location
    eRequest.set_location(parameters.protocolLocation);

    // Set debug mode
    // TODO: Need to add one more debug level '-ddd'
    eTest::TraceLevel debugModeMap;
    switch (parameters.debugLevel)
    {
        case OUTPUT_AND_TRACES: debugModeMap = eTest::TraceLevel::ASSET_ONLY; break;
        case OUTPUT_AND_TRACES_WITH_DETAILS: debugModeMap = eTest::TraceLevel::ALL; break;
        case OUTPUT_ONLY: debugModeMap = eTest::TraceLevel::NONE; break;
        default: throw std::runtime_error {"Debug level greater than '-dd' is not supported."};
    }
    eRequest.set_trace_level(debugModeMap);

    // Set assets trace
    for (const auto& asset : parameters.assetTrace)
    {
        eRequest.add_asset_trace(asset);
    }

    // Set namespaces
    for (const auto& name : parameters.namespaceid)
    {
        eRequest.add_namespaces(name);
    }

    std::cout << std::endl << std::endl << "Type one log per line (Crtl+C to exit):" << std::endl << std::endl;

    // Only set non-canonical mode when connected to terminal
    if (isatty(fileno(stdin)) && !clearIcanon(true))
    {
        std::cout << "WARNING: Failed to set non-canonical mode, only logs shorter than 4095 characters will be "
                        "processed correctly."
                    << std::endl
                    << std::endl;
    }

    // Stdin loop
    std::string line;
    while (gs_doRun && std::getline(std::cin, line))
    {
        if (!line.empty())
        {
            processEvent(line, parameters, client, eRequest);
        }
        else
        {
            std::cout << std::endl
                        << std::endl
                        << "Enter a log in single line (Crtl+C to exit):" << std::endl
                        << std::endl;
        }
    }

    if (isatty(fileno(stdin)))
    {
        clearIcanon(false);
    }
}

void sessionCreate(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command {"tester.session/post"};

    RequestType eRequest;

    // Set session name
    eRequest.mutable_session()->set_name(parameters.sessionName);

    // Set policy name
    if (!parameters.policy.empty())
    {
        eRequest.mutable_session()->set_policy(parameters.policy);
    }

    // Set lifetime
    if (0 != parameters.lifetime)
    {
        eRequest.mutable_session()->set_lifetime(parameters.lifetime);
    }

    if (!parameters.description.empty())
    {
        eRequest.mutable_session()->set_description(parameters.description);
    }

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void sessionDelete(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command {"tester.session/delete"};

    RequestType eRequest;

    if (!parameters.sessionName.empty())
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
    const std::string command {"tester.session/get"};

    RequestType eRequest;

    // Set session name
    eRequest.set_name(parameters.sessionName);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    const auto& session = eResponse.session();
    const auto result = eMessage::eMessageToJson<eTest::Session>(session);
    const auto& json = std::get<std::string>(result);

    if (!parameters.jsonFormat)
    {
        rapidjson::Document doc;
        doc.Parse(json.c_str());
        auto yaml = yml::Converter::jsonToYaml(doc);
        YAML::Emitter out;
        out << yaml;
        std::cout << out.c_str() << std::endl;
    }
    else
    {
        std::cout << json << std::endl;
    }
}

void sessionList(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::TableGet_Request;
    using ResponseType = eTest::TableGet_Response;
    const std::string command {"tester.table/get"};

    // Call the API
    RequestType eRequest;
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    auto sessions = eResponse.sessions();
    auto json = eMessage::eRepeatedFieldToJson<eTest::Session>(sessions);

    if (!parameters.jsonFormat)
    {
        rapidjson::Document doc;
        doc.Parse(std::get<std::string>(json).c_str());
        auto yaml = yml::Converter::jsonToYaml(doc);
        YAML::Emitter out;
        out << yaml;
        std::cout << out.c_str() << std::endl;
    }
    else
    {
        std::cout << std::get<std::string>(json) << std::endl;
    }
}

void configure(CLI::App_p app)
{
    auto testApp = app->add_subcommand("tester", "Utility to test events.");
    testApp->require_subcommand(1);
    auto parameters = std::make_shared<Parameters>();

    // Endpoint
    testApp->add_option("-s, --api_socket", parameters->apiEndpoint, "Set the API socket path.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    testApp
        ->add_option("-t, --client_timeout", parameters->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // API test manage sessions
    auto testSessionApp = testApp->add_subcommand("session", "Manage API sessions.");
    testSessionApp->require_subcommand(1);

    // API test session create
    auto testSessionCreateApp = testSessionApp->add_subcommand("create", "Create a new session.");
    testSessionCreateApp->add_option("name", parameters->sessionName, "Name of the new session.")->required();
    testSessionCreateApp->add_option("policy", parameters->policy, "Policy to be used.")->required();
    testSessionCreateApp->add_option("-l, --lifetime", parameters->lifetime, "lifetime of the session in minutes.");
    testSessionCreateApp->add_option("-d, --description", parameters->description, "Description of the session.");
    testSessionCreateApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionCreate(client, *parameters);
        });

    // API test session delete
    auto testSessionDeleteApp = testSessionApp->add_subcommand("delete", "Delete sessions.");
    testSessionDeleteApp->add_option("name", parameters->sessionName, "Name of the session to be deleted.")->required();
    testSessionDeleteApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionDelete(client, *parameters);
        });

    // API test session data get
    auto testSessionGetApp = testSessionApp->add_subcommand("get", "Get a session data.");
    testSessionGetApp->add_option("name", parameters->sessionName, "Name of the session to be obtained.")->required();
    testSessionGetApp->add_flag("-j, --json",
                         parameters->jsonFormat,
                         "Allows the output and trace generated by an event to be printed in Json format.");
    testSessionGetApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionGet(client, *parameters);
        });

    // API test session list
    auto testSessionListApp = testSessionApp->add_subcommand("list", "List sessions.");
    testSessionListApp->add_flag("-j, --json",
                         parameters->jsonFormat,
                         "Allows the output and trace generated by an event to be printed in Json format.");
    testSessionListApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionList(client, *parameters);
        });

    // API test Run
    auto testRunApp = testApp->add_subcommand("run", "Utility to run a test.");
    testRunApp->add_option("name", parameters->sessionName, "Name of the session to be used.")->required();
    testRunApp
        ->add_option(
            "-q, --protocol_queue", parameters->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(std::string {ENGINE_PROTOCOL_DEFAULT_QUEUE});
    auto debug = testRunApp->add_flag("-d, --debug",
                                      parameters->debugLevel,
                                      "Enable debug mode [0-2]. Flag can appear multiple times. "
                                      "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                                      "Full tracing");
    testRunApp
        ->add_option("-t, --trace",
                     parameters->assetTrace,
                     "List of specific assets to be traced, separated by commas. By "
                     "default traces every asset. This only works "
                     "when debug=2.")
        ->needs(debug);
    testRunApp->add_option("-l, --protocol_location", parameters->protocolLocation, "Protocol location.")
        ->default_val(ENGINE_PROTOCOL_LOCATION);
    testRunApp->add_flag("-j, --json",
                         parameters->jsonFormat,
                         "Allows the output and trace generated by an event to be printed in Json format.");
    testRunApp->add_option("-n, --namespace", parameters->namespaceid, "namespace to filter the traces")
        ->default_val(ENGINE_NAMESPACE);
    testRunApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            run(client, *parameters);
        });
}

} // namespace cmd::test
