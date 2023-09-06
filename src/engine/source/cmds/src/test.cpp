#include "cmds/test.hpp"

#include "defaultSettings.hpp"
#include "utils.hpp"

#include <google/protobuf/util/json_util.h>

#include <iostream>

#include <api/test/handlers.hpp>
#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/test.pb.h>
#include <yml/yml.hpp>

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

/**
 * @brief Process a json value and return it as a YAML node
 *
 * @param jsonObject Json object
 * @param jsonPath Json path
 * @param rootName Root name
 *
 * @return std::optional<YAML::Node> YAML node
 */
inline std::optional<YAML::Node>
processJson(const json::Json& json, const std::string& jsonPath, const std::string& rootName)
{
    rapidjson::Document doc;

    const auto jsonValue = json.getJson(jsonPath);

    if (jsonValue.has_value())
    {
        doc.Parse(jsonValue.value().str().c_str());

        const auto yaml = yml::Converter::jsonToYaml(doc);

        YAML::Node rootNode;
        rootNode[rootName] = yaml;

        return rootNode;
    }

    return std::nullopt;
}

/**
 * @brief Print traces in YAML format.
 *
 * This function takes a vector of strings containing traces and formats them in YAML
 * format with indentation.
 *
 * @param tracesStr A vector of strings containing traces to be formatted.
 */
inline void printTracesInYMLFormat(std::vector<std::string> tracesStr)
{
    if (!tracesStr.empty())
    {
        std::vector<std::pair<std::string, std::string>> formattedData;

        for (const auto& trace : tracesStr)
        {
            size_t pos = trace.find(" ");
            if (pos != std::string::npos)
            {
                auto firstPart = trace.substr(0, pos);
                auto secondPart = trace.substr(pos + 1);
                bool found = false;

                // Search if the key already exist in the vector
                for (auto& entry : formattedData)
                {
                    if (entry.first == firstPart)
                    {
                        // Si existe, combinar contenido
                        entry.second += "\n" + secondPart;
                        found = true;
                        break;
                    }
                }

                // If not found the key, add new input to vetor
                if (!found)
                {
                    formattedData.emplace_back(firstPart, secondPart);
                }
            }
        }

        std::cout << std::endl << std::endl << "Traces:" << std::endl;
        for (const auto& entry : formattedData)
        {
            std::cout << "  - \"" << entry.first << "\":" << std::endl;

            // Split the second part in lines and show with indentations
            std::istringstream iss(entry.second);
            std::string line;
            while (std::getline(iss, line))
            {
                std::cout << "    - " << line << std::endl;
            }
        }
    }
}

/**
 * @brief Print data as YAML.
 *
 * This function takes a JSON string, processes it, and prints the resulting data in
 * YAML format. It also prints traces in YAML format if provided.
 *
 * @param strJsonObject A JSON string to be processed and printed as YAML.
 * @param tracesStr A vector of strings containing traces to be printed in YAML format.
 *
 */
inline void printAsYML(const std::string& strJsonObject, std::vector<std::string> tracesStr)
{
    std::optional<YAML::Node> outputNode;
    try
    {
        // Print traces in yml format
        printTracesInYMLFormat(tracesStr);

        // Print output in yml format
        auto jsonObject = json::Json {strJsonObject.c_str()};
        jsonObject.erase("/status");
        outputNode = processJson(jsonObject, "/output", "Output");
        if (outputNode.has_value())
        {
            YAML::Emitter out;
            out << outputNode.value();
            std::cout << std::endl << out.c_str() << std::endl << std::endl;
        }

    }
    catch (const std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl << std::endl;
    }
}

} // namespace

namespace cmd::test
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

void processEvent(const std::string& eventStr,
                  const Parameters& parameters,
                  std::shared_ptr<apiclnt::Client> client,
                  eTest::RunPost_Request eRequest)
{
    using RequestType = eTest::RunPost_Request;
    using ResponseType = eTest::RunPost_Response;
    const std::string command {api::test::handlers::TEST_RUN_API_CMD};

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
    eRequest.mutable_event()->CopyFrom(event);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print results
    std::string jsonOutputAndTrace;
    const auto& run = eResponse.run();
    google::protobuf::util::MessageToJsonString(run, &jsonOutputAndTrace);

    if (parameters.jsonFormat)
    {
        std::cout << jsonOutputAndTrace << std::endl;
    }
    else
    {
        const auto& traces = eResponse.run().traces();
        std::vector<std::string> tracesStr;
        for(const auto& trace : traces)
        {
            tracesStr.emplace_back(trace);
        }
        printAsYML(jsonOutputAndTrace, tracesStr);
    }
}

void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    const std::string commandGet {api::test::handlers::TEST_GET_SESSION_DATA_API_CMD};

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
    const auto eResponseGet = utils::apiAdapter::fromWazuhResponse<eTest::SessionsGet_Response>(responseGet);

    // Call run command

    using RequestType = eTest::RunPost_Request;
    using ResponseType = eTest::RunPost_Response;

    const std::string command {api::test::handlers::TEST_RUN_API_CMD};

    // Set policy name
    RequestType eRequest;
    eRequest.set_name(parameters.sessionName);

    // Set protocol queue
    eRequest.set_protocol_queue(parameters.protocolQueue);

    // Set debug mode
    // TODO: Need to add one more debug level '-ddd'
    eTest::DebugMode debugModeMap;
    switch (parameters.debugLevel)
    {
        case OUTPUT_AND_TRACES: debugModeMap = eTest::DebugMode::OUTPUT_AND_TRACES; break;
        case OUTPUT_AND_TRACES_WITH_DETAILS: debugModeMap = eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS; break;
        case OUTPUT_ONLY: debugModeMap = eTest::DebugMode::OUTPUT_ONLY; break;
        default: throw std::runtime_error {"Debug level greater than '-dd' is not supported."};
    }
    eRequest.set_debug_mode(debugModeMap);

    // Set location
    eRequest.set_protocol_location(parameters.protocolLocation);

    // Set assets trace
    for (const auto& asset : parameters.assetTrace)
    {
        eRequest.add_asset_trace(asset);
    }

    // Set namespaces
    for (const auto& name : parameters.namespaceid)
    {
        eRequest.add_namespaceid(name);
    }

    if (!parameters.event.empty())
    {
        processEvent(parameters.event, parameters, client, eRequest);
    }
    else
    {
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
}

void sessionCreate(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    using RequestType = eTest::SessionPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command {api::test::handlers::TEST_POST_SESSION_API_CMD};

    RequestType eRequest;

    // Set session name
    eRequest.set_name(parameters.sessionName);

    // Set policy name
    if (!parameters.policy.empty())
    {
        eRequest.set_policy(parameters.policy);
    }

    // Set lifespan
    if (0 != parameters.lifespan)
    {
        eRequest.set_lifespan(parameters.lifespan);
    }

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
    using ResponseType = eEngine::GenericStatus_Response;
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

    const auto& session = eResponse.session();
    const auto result = eMessage::eMessageToJson<eTest::Session>(session);
    const auto& json = std::get<std::string>(result);

    std::cout << json << std::endl;
}

void sessionList(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eTest::SessionsGet_Request;
    using ResponseType = eTest::SessionsGet_Response;
    const std::string command {api::test::handlers::TEST_GET_SESSIONS_LIST_API_CMD};

    // Call the API
    RequestType eRequest;
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    auto orderedList = eResponse.list();
    // Sort the list by name
    std::sort(orderedList.begin(), orderedList.end());

    for (const auto& str : orderedList)
    {
        std::cout << str << std::endl;
    }
}

void configure(CLI::App_p app)
{
    auto testApp = app->add_subcommand("test", "Utility to test events.");
    testApp->require_subcommand(1);
    auto parameters = std::make_shared<Parameters>();

    // Endpoint
    testApp->add_option("-a, --api_socket", parameters->apiEndpoint, "Set the API socket path.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    testApp
        ->add_option("--client_timeout", parameters->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // API test manage sessions
    auto testSessionApp = testApp->add_subcommand("session", "Manage API sessions.");
    testSessionApp->require_subcommand(1);

    // API test session create
    auto testSessionCreateApp = testSessionApp->add_subcommand("create", "Create a new session.");
    testSessionCreateApp->add_option("name", parameters->sessionName, "Name of the new session.")->required();
    testSessionCreateApp->add_option("-p, --policy", parameters->policy, "Policy to be used.")
        ->default_val(std::string {api::test::handlers::DEFAULT_POLICY_FULL_NAME});
    testSessionCreateApp->add_option("-l, --lifespan", parameters->lifespan, "Lifespan of the session in minutes.");
    testSessionCreateApp->add_option("-d, --description", parameters->description, "Description of the session.");
    testSessionCreateApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionCreate(client, *parameters);
        });

    // API test session delete
    auto testSessionDeleteApp = testSessionApp->add_subcommand("delete", "Delete sessions.");
    testSessionDeleteApp->add_option("-n, --name", parameters->sessionName, "Name of the session to be deleted.");
    testSessionDeleteApp->add_flag("--all", parameters->deleteAll, "Delete all the sessions.");
    testSessionDeleteApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionDelete(client, *parameters);
        });

    // API test session data get
    auto testSessionGetApp = testSessionApp->add_subcommand("get", "Get a session data.");
    testSessionGetApp->add_option("name", parameters->sessionName, "Name of the session to be obtained.")->required();
    testSessionGetApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionGet(client, *parameters);
        });

    // API test session list
    auto testSessionListApp = testSessionApp->add_subcommand("list", "List sessions.");
    testSessionListApp->callback(
        [parameters]()
        {
            const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint, parameters->clientTimeout);
            sessionList(client);
        });

    // API test Run
    auto testRunApp = testApp->add_subcommand("run", "Utility to run a test.");
    testRunApp->add_option("name", parameters->sessionName, "Name of the session to be used.")->required();
    testRunApp->add_option("-e, --event", parameters->event, "Event to be processed");
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
    testRunApp->add_option("--protocol_location", parameters->protocolLocation, "Protocol location.")
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

