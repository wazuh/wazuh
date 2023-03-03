#include <cmds/router.hpp>

#include <eMessages/router.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp> // Remove

namespace
{
struct Options
{
    std::string apiEndpoint;
    std::string name;
    std::string filterName;
    int priority {};
    std::string environment;
    std::string event;
};
} // namespace

namespace cmd::router
{

namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;

void runGetTable(std::shared_ptr<apiclnt::Client> client)
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
    std::cout << std::get<std::string>(json) << std::endl;
}

void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr)
{
    if (nameStr.empty())
    {
        runGetTable(client);
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
    const auto& route = eResponse.rute();
    const auto result = eMessage::eMessageToJson<eRouter::Entry>(route);
    const auto& json = std::get<std::string>(result);
    std::cout << json << std::endl;
}

void runAdd(std::shared_ptr<apiclnt::Client> client,
            const std::string& nameStr,
            int priority,
            const std::string& filterName,
            const std::string& environment)
{
    using RequestType = eRouter::RoutePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.mutable_route()->set_name(nameStr);
    eRequest.mutable_route()->set_priority(priority);
    eRequest.mutable_route()->set_filter(filterName);
    eRequest.mutable_route()->set_policy(environment);

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
    using RequestType = eRouter::RoutePatch_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/patch";

    // Prepare the request
    RequestType eRequest;
    eRequest.mutable_route()->set_name(nameStr);
    eRequest.mutable_route()->set_priority(priority);

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
    eRequest.set_ossec_event(event);

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
    routerApp->add_option("-a, --api_socket", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->check(CLI::ExistingFile);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // Get
    auto getSubcommand = routerApp->add_subcommand(
        "get", "Get the information of an active route, or all active routes if no name is provided.");
    getSubcommand->add_option("name", options->name, "Name of the route to get, empty to list all routes.")
        ->default_val("");
    getSubcommand->callback([options, client]() { runGet(client, options->name); });

    // Add
    auto addSubcommand = routerApp->add_subcommand(
        "add", "Activate a new route, filter and environment asset must exist in the catalog");
    addSubcommand->add_option("name", options->name, "Name or identifier of the route.")->required();
    addSubcommand->add_option("filter", options->filterName, "Name of the filter to use.")->required();
    addSubcommand->add_option("priority", options->priority, "Priority of the route.")
        ->required()
        ->check(CLI::Range(0, 255));
    addSubcommand->add_option("environment", options->environment, "Target environment of the route.")->required();
    addSubcommand->callback(
        [options, client]()
        { runAdd(client, options->name, options->priority, options->filterName, options->environment); });

    // Delete
    auto deleteSubcommand = routerApp->add_subcommand("delete", "Deactivate a route.");
    deleteSubcommand->add_option("name", options->name, "Name of the route to deactivate.")->required();
    deleteSubcommand->callback([options, client]() { runDelete(client, options->name); });

    // Update
    auto updateSubcommand = routerApp->add_subcommand("update", "Modify an active route.");
    updateSubcommand->add_option("name", options->name, "Name of the route to modify.")->required();
    updateSubcommand->add_option("priority", options->priority, "Priority of the route.")
        ->required()
        ->check(CLI::Range(0, 255));
    updateSubcommand->callback([options, client]() { runUpdate(client, options->name, options->priority); });

    // Ingest
    auto ingestSubcommand = routerApp->add_subcommand("ingest", "Ingest an event on the specified route.");
    ingestSubcommand->add_option("event", options->event, "Event to ingest.")->required();
    ingestSubcommand->callback([options, client]() { runIngest(client, options->event); });
}
} // namespace cmd::router
