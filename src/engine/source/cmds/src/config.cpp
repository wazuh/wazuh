#include <cmds/config.hpp>

#include <eMessages/config.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>

namespace
{
struct Options
{
    std::string name;
    std::string apiEndpoint;
    std::string value;
    std::string path;
};
} // namespace

namespace cmd::config
{

namespace eConfig = ::com::wazuh::api::engine::config;
namespace eEngine = ::com::wazuh::api::engine;

void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr)
{
    using RequestType = eConfig::RuntimeGet_Request;
    using ResponseType = eConfig::RuntimeGet_Response;
    const std::string command = "config.runtime/get";

    // Prepare the request
    RequestType eRequest;
    if (!nameStr.empty())
    {
        eRequest.set_name(nameStr);
    }

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the config
    std::cout << eResponse.content() << std::endl;
}

void runSave(std::shared_ptr<apiclnt::Client> client, const std::string& pathStr)
{
    using RequestType = eConfig::RuntimeSave_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "config.runtime/save";

    // Prepare the request
    RequestType eRequest;
    if (!pathStr.empty())
    {
        eRequest.set_path(pathStr);
    }

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runPut(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, const std::string& valueStr)
{
    using RequestType = eConfig::RuntimePut_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "config.runtime/put";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);
    eRequest.set_content(valueStr);
    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto configApp = app->add_subcommand("config", "Manage the Wazuh Engine configuration");
    configApp->require_subcommand();
    auto options = std::make_shared<Options>();

    // Shared options
    // Endpoint
    configApp->add_option("-a, --api_socket", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->check(CLI::ExistingFile);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    auto get_subcommand =
        configApp->add_subcommand("get",
                                  "Get a configuration option value or the whole configuration if no name is "
                                  "provided");
    get_subcommand
        ->add_option("name", options->name, "Name of the configuration option to get, empty to get all configuration")
        ->default_val("");
    get_subcommand->callback([options, client]() { runGet(client, options->name); });

    auto save_subcommand =
        configApp->add_subcommand("save", "Persist the current configuration, to take effect restart the engine");
    save_subcommand
        ->add_option("path", options->path, "Path to save the configuration, empty to save in the default path")
        ->default_val("");
    save_subcommand->callback([options, client]() { runSave(client, options->path); });

    auto put_subcommand = configApp->add_subcommand("put", "Update a configuration option");
    put_subcommand->add_option("name", options->name, "Name of the configuration option to set")->required();
    put_subcommand->add_option("value", options->value, "Value of the configuration option to set")->required();
    put_subcommand->callback([options, client]() { runPut(client, options->name, options->value); });
}
} // namespace cmd::config
