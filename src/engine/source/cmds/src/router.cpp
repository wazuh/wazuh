#include <cmds/router.hpp>

#include <eMessages/router.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>
#include <yml/yml.hpp>

namespace
{
struct Options
{
    std::string serverApiSock;
    std::string name;
    std::string filterName;
    bool jsonFormat;
    int priority {};
    std::string policy;
    std::string event;
    int clientTimeout;
    uint eps;
    uint refreshInterval;
};
} // namespace

namespace cmd::router
{

namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;

void runGetTable(std::shared_ptr<apiclnt::Client> client, const bool jsonFormat)
{
    using RequestType = eRouter::TableGet_Request;
    using ResponseType = eRouter::TableGet_Response;
    const std::string command = "router.table/get";

    // Prepare the request
    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the table as JSON array of objects (Entry)
    const auto& table = eResponse.table();
    const auto json = eMessage::eRepeatedFieldToJson<eRouter::Entry>(table);

    if (!jsonFormat)
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

void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, const bool jsonFormat)
{
    if (nameStr.empty())
    {
        runGetTable(client, jsonFormat);
        return;
    }
    using RequestType = eRouter::RouteGet_Request;
    using ResponseType = eRouter::RouteGet_Response;
    const std::string command = "router.route/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print as JSON the entry
    const auto& route = eResponse.route();
    const auto result = eMessage::eMessageToJson<eRouter::Entry>(route);
    const auto& json = std::get<std::string>(result);

    if (!jsonFormat)
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

void runAdd(std::shared_ptr<apiclnt::Client> client,
            const std::string& nameStr,
            int priority,
            const std::string& filterName,
            const std::string& policy)
{
    using RequestType = eRouter::RoutePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.mutable_route()->set_name(nameStr);
    eRequest.mutable_route()->set_priority(priority);
    eRequest.mutable_route()->set_filter(filterName);
    eRequest.mutable_route()->set_policy(policy);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response); // Validate response
}

void runDelete(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr)
{
    using RequestType = eRouter::RouteDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/delete";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runUpdate(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, int priority)
{
    using RequestType = eRouter::RoutePatchPriority_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/patchPriority";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);
    eRequest.set_priority(priority);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runReload(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr)
{
    using RequestType = eRouter::RouteReload_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/reload";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runIngest(std::shared_ptr<apiclnt::Client> client, const std::string& event)
{
    using RequestType = eRouter::QueuePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.queue/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_wazuh_event(event);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runChangeEpsSettings(std::shared_ptr<apiclnt::Client> client, int eps, int intervalSec)
{
    using RequestType = eRouter::EpsUpdate_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.eps/update";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_eps(eps);
    eRequest.set_refresh_interval(intervalSec);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runGetEpsSettings(std::shared_ptr<apiclnt::Client> client, bool jsonFormat)
{
    using RequestType = eRouter::EpsGet_Request;
    using ResponseType = eRouter::EpsGet_Response;
    const std::string command = "router.eps/get";

    // Prepare the request
    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    auto jString = std::get<std::string>(eMessage::eMessageToJson<eRouter::EpsGet_Response>(eResponse));
    if (!jsonFormat)
    {
        rapidjson::Document doc;
        doc.Parse(jString.c_str());
        auto yaml = yml::Converter::jsonToYaml(doc);
        YAML::Emitter out;
        out << yaml;
        std::cout << out.c_str() << std::endl;
    }
    else
    {
        std::cout << jString << std::endl;
    }
}

void runActivateEps(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eRouter::EpsEnable_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.eps/activate";

    // Prepare the request
    RequestType eRequest;

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runDeactivateEps(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eRouter::EpsDisable_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.eps/deactivate";

    // Prepare the request
    RequestType eRequest;

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto routerApp = app->add_subcommand("router", "Manage the event routing of the policies");
    routerApp->require_subcommand(1);

    auto options = std::make_shared<Options>();

    // Endpoint
    routerApp->add_option("-s, --api_socket", options->serverApiSock, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    routerApp
        ->add_option("-t, --client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // Get
    auto getSubcommand = routerApp->add_subcommand(
        "get", "Get the information of an active route, or all active routes if no name is provided.");
    getSubcommand->add_option("name", options->name, "Name of the route to get, empty to list all routes.")
        ->default_val("");
    getSubcommand->add_flag("-j, --json",
                            options->jsonFormat,
                            "Allows the output and trace generated by an event to be printed in Json format.");
    getSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGet(client, options->name, options->jsonFormat);
        });

    // Add
    auto addSubcommand =
        routerApp->add_subcommand("add", "Activate a new route, filter and policy asset must exist in the catalog");
    addSubcommand->add_option("name", options->name, "Name or identifier of the route.")->required();
    addSubcommand->add_option("filter", options->filterName, "Name of the filter to use.")->required();
    addSubcommand->add_option("priority", options->priority, "Priority of the route.")->required();
    addSubcommand->add_option("policy", options->policy, "Target policy of the route.")->required();
    addSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runAdd(client, options->name, options->priority, options->filterName, options->policy);
        });

    // Delete
    auto deleteSubcommand = routerApp->add_subcommand("delete", "Deactivate a route.");
    deleteSubcommand->add_option("name", options->name, "Name of the route to deactivate.")->required();
    deleteSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDelete(client, options->name);
        });

    // Update
    auto updateSubcommand = routerApp->add_subcommand("update", "Modify an active route.");
    updateSubcommand->add_option("name", options->name, "Name of the route to modify.")->required();
    updateSubcommand->add_option("priority", options->priority, "Priority of the route.")->required();
    updateSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runUpdate(client, options->name, options->priority);
        });

    // Reload
    auto reloadSubcommand = routerApp->add_subcommand("reload", "Try to reconstruct a route.");
    reloadSubcommand->add_option("name", options->name, "Name of the route to modify.")->required();
    reloadSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runReload(client, options->name);
        });

    // Ingest
    auto ingestSubcommand = routerApp->add_subcommand("ingest", "Ingest an event on the specified route.");
    ingestSubcommand->add_option("event", options->event, "Event to ingest.")->required();
    ingestSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runIngest(client, options->event);
        });

    // EpsChange
    auto epsChangeSubcommand = routerApp->add_subcommand("eps-update", "Change the EPS settings.");
    epsChangeSubcommand
        ->add_option("events-per-second", options->eps, "Number of events per second allowed to be processed.")
        ->required();
    epsChangeSubcommand->add_option("refresh-interval", options->refreshInterval, "Interval window size in seconds.")
        ->required();
    epsChangeSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runChangeEpsSettings(client, options->eps, options->refreshInterval);
        });

    // EpsGet
    auto epsGetSubcommand = routerApp->add_subcommand("eps-get", "Get the EPS settings.");
    epsGetSubcommand->add_flag("-j, --json",
                               options->jsonFormat,
                               "Allows the output and trace generated by an event to be printed in Json format.");
    epsGetSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGetEpsSettings(client, options->jsonFormat);
        });

    // EpsActivate
    auto epsActivateSubcommand = routerApp->add_subcommand("eps-enable", "Enable the EPS limiter.");
    epsActivateSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runActivateEps(client);
        });

    // EpsDeactivate
    auto epsDeactivateSubcommand = routerApp->add_subcommand("eps-disable", "Disable the EPS limiter.");
    epsDeactivateSubcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDeactivateEps(client);
        });
}
} // namespace cmd::router
