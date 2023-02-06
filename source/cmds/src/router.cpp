#include <cmds/router.hpp>

#include "apiclnt/client.hpp"
#include "defaultSettings.hpp"

namespace
{
struct Options
{
    std::string apiEndpoint;
    std::string name;
    int priority;
    std::string environment;
    std::string event;
};
} // namespace

namespace cmd::router
{

namespace details
{
json::Json
getParameters(const std::string& action, const std::string& name, int priority, const std::string& environment)
{
    json::Json params;
    params.setObject();
    params.setString(action, "/action");
    if (!name.empty())
    {
        params.setString(name, "/name");
    }
    if (priority != -1)
    {
        params.setInt(priority, "/priority");
    }
    if (!environment.empty())
    {
        params.setString(environment, "/target");
    }

    return params;
}

json::Json getIngestParameters(const std::string& action, const std::string& name, const std::string& event)
{
    json::Json params;
    params.setObject();
    params.setString(action, "/action");
    params.setString(name, "/name");
    params.setString(event, "/event");
    return params;
}

void processResponse(const api::WazuhResponse& response)
{
    auto content = response.data();
    auto message = response.message();
    if (content.size() != 0)
    {
        std::cout << content.str() << std::endl;
    }
    else if (message)
    {
        std::cout << message.value() << std::endl;
    }
}

void singleRequest(const api::WazuhRequest& request, const std::string& socketPath)
{
    try
    {
        apiclnt::Client client {socketPath};
        auto response = client.send(request);
        details::processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
}
} // namespace details

void runGet(const std::string& socketPath, const std::string& nameStr)
{
    json::Json params = details::getParameters("get", nameStr);
    auto request = api::WazuhRequest::create(details::ROUTER_COMMAND, details::ORIGIN_NAME, std::move(params));
    details::singleRequest(request, socketPath);
}

void runAdd(const std::string& socketPath, const std::string& nameStr, int priority, const std::string& environment)
{
    json::Json params = details::getParameters("set", nameStr, priority, environment);
    auto request = api::WazuhRequest::create(details::ROUTER_COMMAND, details::ORIGIN_NAME, std::move(params));
    details::singleRequest(request, socketPath);
}

void runDelete(const std::string& socketPath, const std::string& nameStr)
{
    json::Json params = details::getParameters("delete", nameStr);
    auto request = api::WazuhRequest::create(details::ROUTER_COMMAND, details::ORIGIN_NAME, std::move(params));
    details::singleRequest(request, socketPath);
}

void runUpdate(const std::string& socketPath, const std::string& nameStr, int priority)
{
    json::Json params = details::getParameters("change_priority", nameStr, priority);
    auto request = api::WazuhRequest::create(details::ROUTER_COMMAND, details::ORIGIN_NAME, std::move(params));
    details::singleRequest(request, socketPath);
}

void runIngest(const std::string& socketPath, const std::string& nameStr, const std::string& event)
{
    json::Json params = details::getIngestParameters("enqueue_event", nameStr, event);
    auto request = api::WazuhRequest::create(details::ROUTER_COMMAND, details::ORIGIN_NAME, std::move(params));
    details::singleRequest(request, socketPath);
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
        routerApp->add_subcommand("add", "Activate a new route, route asset must exist in the catalog");
    addSubcommand->add_option("name", options->name, "Name of the route to add.")->required();
    addSubcommand->add_option("priority", options->priority, "Priority of the route.")
        ->required()
        ->check(CLI::Range(0, 255));
    addSubcommand->add_option("environment", options->environment, "Target environment of the route.")->required();
    addSubcommand->callback([options]()
                            { runAdd(options->apiEndpoint, options->name, options->priority, options->environment); });

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
    ingestSubcommand->add_option("name", options->name, "Name of the route to ingest the event.")->required();
    ingestSubcommand->add_option("event", options->event, "Event to ingest.")->required();
}
} // namespace cmd::router
