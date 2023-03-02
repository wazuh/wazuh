#include <cmds/router.hpp>

#include <eMessages/router.pb.h>

#include "apiclnt/client.hpp" // Remove
#include "utils.hpp"
#include "defaultSettings.hpp"

namespace
{
struct Options
{
    std::string apiEndpoint;
    std::string name;
    std::string filterName;
    int priority;
    std::string environment;
    std::string event;
};
} // namespace

namespace cmd::router
{

namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;

void runGetTable(const std::string& socketPath)
{
    using requestType = eRouter::TableGet_Request;
    using responseType = eRouter::TableGet_Response;
    const std::string command = "router.table/get";

    // Prepare the request
    requestType eRequest;

    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        // Print as JSON the entry
        const auto& table = std::get<responseType>(result).table();
        const auto json = eMessage::eRepeatedFieldToJson<eRouter::Entry>(table);
        std::cout << std::get<std::string>(json) << std::endl;
    }
}

void runGet(const std::string& socketPath, const std::string& nameStr)
{
    if (nameStr.empty())
    {
        runGetTable(socketPath);
        return;
    }
    using requestType = eRouter::RouteGet_Request;
    using responseType = eRouter::RouteGet_Response;
    const std::string command = "router.route/get";

    // Prepare the request
    requestType eRequest;
    eRequest.set_name(nameStr);

    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        // Print as JSON the entry
        const auto& route = std::get<responseType>(result).rute();
        const auto result = eMessage::eMessageToJson<eRouter::Entry>(route);
        const auto& json = std::get<std::string>(result); // Always can serialize to JSON
        std::cout << json << std::endl;
    }
}

void runAdd(const std::string& socketPath, const std::string& nameStr, int priority, const std::string& filterName, const std::string& environment)
{
    using requestType = eRouter::RoutePost_Request;
    using responseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/post";

    // Prepare the request
    requestType eRequest;
    eRequest.mutable_route()->set_name(nameStr);
    eRequest.mutable_route()->set_priority(priority);
    eRequest.mutable_route()->set_filter(filterName);
    eRequest.mutable_route()->set_policy(environment);

    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        std::cout << "ok" << std::endl;
    }
}

void runDelete(const std::string& socketPath, const std::string& nameStr)
{
    using requestType = eRouter::RouteDelete_Request;
    using responseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/delete";

    // Prepare the request
    requestType eRequest;
    eRequest.set_name(nameStr);

    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        std::cout << "ok" << std::endl;
    }
}

void runUpdate(const std::string& socketPath, const std::string& nameStr, int priority)
{
    using requestType = eRouter::RoutePatch_Request;
    using responseType = eEngine::GenericStatus_Response;
    const std::string command = "router.route/patch";

    // Prepare the request
    requestType eRequest;
    eRequest.mutable_route()->set_name(nameStr);
    eRequest.mutable_route()->set_priority(priority);
    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        std::cout << "ok" << std::endl;
    }
}

void runIngest(const std::string& socketPath, const std::string& event)
{
    using requestType = eRouter::QueuePost_Request;
    using responseType = eEngine::GenericStatus_Response;
    const std::string command = "router.queue/post";

    // Prepare the request
    requestType eRequest;
    eRequest.set_ossec_event(event);

    // Call the API
    const auto result = utils::callWAPI<requestType, responseType>(socketPath, command, details::ORIGIN_NAME, eRequest);
    if (std::holds_alternative<std::string>(result))
    {
        std::cerr << std::get<std::string>(result) << std::endl;
    }
    else
    {
        std::cout << "ok" << std::endl;
    }
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

    // Get
    auto getSubcommand = routerApp->add_subcommand(
        "get", "Get the information of an active route, or all active routes if no name is provided.");
    getSubcommand->add_option("name", options->name, "Name of the route to get, empty to list all routes.")
        ->default_val("");
    getSubcommand->callback([options]() { runGet(options->apiEndpoint, options->name); });

    // Add
    auto addSubcommand =
        routerApp->add_subcommand("add", "Activate a new route, filter and environment asset must exist in the catalog");
    addSubcommand->add_option("name", options->name, "Name or identifier of the route.")->required();
    addSubcommand->add_option("filter", options->filterName, "Name of the filter to use.")->required();
    addSubcommand->add_option("priority", options->priority, "Priority of the route.")
        ->required()
        ->check(CLI::Range(0, 255));
    addSubcommand->add_option("environment", options->environment, "Target environment of the route.")->required();
    addSubcommand->callback([options]()
                            { runAdd(options->apiEndpoint, options->name, options->priority, options->filterName, options->environment); });

    // Delete
    auto deleteSubcommand = routerApp->add_subcommand("delete", "Deactivate a route.");
    deleteSubcommand->add_option("name", options->name, "Name of the route to deactivate.")->required();
    deleteSubcommand->callback([options]() { runDelete(options->apiEndpoint, options->name); });

    // Update
    auto updateSubcommand = routerApp->add_subcommand("update", "Modify an active route.");
    updateSubcommand->add_option("name", options->name, "Name of the route to modify.")->required();
    updateSubcommand->add_option("priority", options->priority, "Priority of the route.")
        ->required()
        ->check(CLI::Range(0, 255));
    updateSubcommand->callback([options]() { runUpdate(options->apiEndpoint, options->name, options->priority); });

    // Ingest
    auto ingestSubcommand = routerApp->add_subcommand("ingest", "Ingest an event on the specified route.");
    ingestSubcommand->add_option("event", options->event, "Event to ingest.")->required();
    ingestSubcommand->callback([options]() { runIngest(options->apiEndpoint, options->event); });
}
} // namespace cmd::router
