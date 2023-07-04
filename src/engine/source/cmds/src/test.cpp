#include "cmds/test.hpp"

#include "defaultSettings.hpp"
#include "utils.hpp"

#include <google/protobuf/util/json_util.h>

#include <iostream>

#include <api/test/handlers.hpp>
#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/test.pb.h>
#include <utilsYml.hpp>

namespace
{

constexpr auto DEFAULT_SESSION_LIFESPAN = 0; ///< Default session lifespan

std::atomic<bool> gs_doRun {true};
cmd::details::StackExecutor g_exitHanlder {};

/**
 * @brief Signal handler for SIGINT
 *
 * @param signum Signal number
 */
void sigint_handler(const int signalNumber)
{
    gs_doRun = false;
}

/**
 * @brief Signal handler for SIGTERM
 *
 * @param signum Signal number
 */
inline bool clear_icanon(const bool& doClearIcanon)
{
    bool retval {false};
    struct termios settings;

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
 * @param tmp Json value
 * @param jsonPath Json path
 * @param rootName Root name
 * @return std::optional<YAML::Node> YAML node
 */
inline std::optional<YAML::Node>
processJson(const json::Json& jsonObject, const std::string& jsonPath, const std::string& rootName)
{
    const auto jsonValue = jsonObject.getJson(jsonPath);

    if (jsonValue.has_value())
    {
        rapidjson::Document doc;
        doc.Parse(jsonValue.value().str().c_str());

        const auto yaml = utilsYml::Converter::json2yaml(doc);

        YAML::Node rootNode;
        rootNode[rootName] = yaml;

        return rootNode;
    }

    return std::nullopt;
}

/**
 * @brief Print a YAML node
 *
 * @param node YAML node
 */
inline void printYML(const YAML::Node& node)
{
    YAML::Emitter out;
    out << node;
    std::cout << std::endl << out.c_str() << std::endl << std::endl;
}

/**
 * @brief Print a json object string as YAML
 *
 * @param strJsonObject Json value
 */
inline void printJsonAsYML(const std::string& strJsonObject)
{
    std::optional<YAML::Node> outputNode;
    try
    {
        auto jsonObject = json::Json {strJsonObject.c_str()};
        jsonObject.erase("/status");

        outputNode = processJson(jsonObject, "/traces", "Traces");
        if (outputNode.has_value())
        {
            printYML(outputNode.value());
        }

        outputNode = processJson(jsonObject, "/output", "Output");
        if (outputNode.has_value())
        {
            printYML(outputNode.value());
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
    try
    {
        jsonEvent = json::Json {eventStr.c_str()};
    }
    catch (const std::exception& e)
    {
        // If not, set it as a string
        jsonEvent.setString(eventStr);
    }

    // Convert the value to protobuf value
    const auto protoEvent = eMessage::eMessageFromJson<google::protobuf::Value>(jsonEvent.str());
    if (std::holds_alternative<base::Error>(protoEvent)) // Should not happen but just in case
    {
        const auto msj = std::get<base::Error>(protoEvent).message + ". For value " + jsonEvent.str();
        throw ::cmd::ClientException(msj, ClientException::Type::PROTOBUFF_SERIALIZE_ERROR);
    }

    const auto& event = std::get<google::protobuf::Value>(protoEvent);
    *eRequest.mutable_event() = event;

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
        printJsonAsYML(jsonOutputAndTrace);
    }
}

void run(std::shared_ptr<apiclnt::Client> client, const Parameters& parameters)
{
    const std::string commandList {api::test::handlers::TEST_GET_SESSIONS_LIST_API_CMD};

    // Check that the session exists before executing the run command
    eTest::SessionsGet_Request eListRequest;
    const auto listRequest =
        utils::apiAdapter::toWazuhRequest<eTest::SessionsGet_Request>(commandList, details::ORIGIN_NAME, eListRequest);
    const auto responseList = client->send(listRequest);
    const auto eResponseList = utils::apiAdapter::fromWazuhResponse<eTest::SessionsGet_Response>(responseList);

    auto foundSession {false};
    for (const auto& session : eResponseList.list())
    {
        if (parameters.sessionName == session)
        {
            foundSession = true;
        }
    }

    if (!foundSession)
    {
        std::cout << fmt::format("Session '{}' could not be found", parameters.sessionName) << std::endl;
        return;
    }

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
    eTest::DebugMode debugModeMap;
    switch (parameters.debugLevel)
    {
        case OUTPUT_AND_TRACES: debugModeMap = eTest::DebugMode::OUTPUT_AND_TRACES; break;
        case OUTPUT_AND_TRACES_WITH_DETAILS: debugModeMap = eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS; break;
        case OUTPUT_ONLY:
        default: debugModeMap = eTest::DebugMode::OUTPUT_ONLY;
    }
    eRequest.set_debug_mode(debugModeMap);

    // Set location
    eRequest.set_protocol_location(parameters.protocolLocation);

    // Set asset trace
    eRequest.set_asset_trace(parameters.assetTrace);

    if (!parameters.event.empty())
    {
        processEvent(parameters.event, parameters, client, eRequest);
    }
    else
    {
        std::cout << std::endl << std::endl << "Type one log per line (Crtl+C to exit):" << std::endl << std::endl;

        // Only set non-canonical mode when connected to terminal
        if (isatty(fileno(stdin)) && !clear_icanon(true))
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
            clear_icanon(false);
        }

        g_exitHanlder.execute();
    }
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

    for (const auto& str : eResponse.list())
    {
        std::cout << str << std::endl;
    }
}

void configure(CLI::App_p app)
{
    auto testApp = app->add_subcommand("test", "Utility to test events.");
    testApp->require_subcommand(1);
    auto parameters = std::make_shared<Parameters>();

    testApp->add_option("-a, --api_socket", parameters->apiEndpoint, "Set the API socket path.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);
    const auto client = std::make_shared<apiclnt::Client>(parameters->apiEndpoint);

    // API test manage sessions
    auto testSessionApp = testApp->add_subcommand("session", "Manage API sessions.");
    testSessionApp->require_subcommand(1);

    // API test session create
    auto testSessionCreateApp = testSessionApp->add_subcommand("create", "Create a new session.");
    testSessionCreateApp->add_option("-n, --name", parameters->sessionName, "Name of the new session.")->required();
    testSessionCreateApp->add_option("-p, --policy", parameters->policy, "Policy to be used.");
    testSessionCreateApp->add_option("-l, --lifespan", parameters->lifespan, "Lifespan of the session in minutes.");
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
    testSessionListApp->callback([parameters, client]() { sessionList(client); });

    // API test Run
    auto testRunApp = testApp->add_subcommand("run", "Utility to run a test.");
    testRunApp->add_option("-n, --name", parameters->sessionName, "Name of the session to be used.")->required();
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
    testRunApp->callback([parameters, client]() { run(client, *parameters); });
}

} // namespace cmd::test
