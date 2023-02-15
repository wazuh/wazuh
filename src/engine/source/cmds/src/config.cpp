#include <cmds/config.hpp>

#include "apiclnt/client.hpp"
#include "defaultSettings.hpp"

namespace
{
struct Options
{
    std::string name;
    std::string socketPath;
    std::string value;
    std::string path;
};
} // namespace

namespace cmd::config
{
namespace details
{
void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response)
{
    auto message = response.message();
    if (message)
    {
        std::cout << message.value() << std::endl;
    }
    else
    {
        std::cout << response.data().getString("/content").value() << std::endl;
    }
}

void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath)
{
    apiclnt::Client client(socketPath);
    try
    {
        const auto response = client.send(request);
        processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}
} // namespace details

void runGet(const std::string& socketPath, const std::string& nameStr)
{
    json::Json params;
    params.setObject();
    if (!nameStr.empty())
    {
        params.setString(nameStr, "/name");
    }
    const auto request = base::utils::wazuhProtocol::WazuhRequest::create("config_get", details::ORIGIN_NAME, params);
    details::singleRequest(request, socketPath);
}

void runSave(const std::string& socketPath, const std::string& pathStr)
{
    json::Json params;
    params.setObject();
    if (!pathStr.empty())
    {
        params.setString(pathStr, "/path");
    }

    const auto request = base::utils::wazuhProtocol::WazuhRequest::create("config_save", details::ORIGIN_NAME, params);
    details::singleRequest(request, socketPath);
}

void runPut(const std::string& socketPath, const std::string& nameStr, const std::string& valueStr)
{
    json::Json params;
    params.setObject();
    params.setString(nameStr, "/name");
    params.setString(valueStr, "/value");
    const auto request = base::utils::wazuhProtocol::WazuhRequest::create("config_put", details::ORIGIN_NAME, params);
    details::singleRequest(request, socketPath);
}

void configure(CLI::App_p app)
{
    auto configApp = app->add_subcommand("config", "Manage the Wazuh Engine configuration");
    auto options = std::make_shared<Options>();

    // Shared options
    // Endpoint
    configApp->add_option("-a, --api_socket", options->socketPath, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->check(CLI::ExistingFile);

    auto get_subcommand =
        configApp->add_subcommand("get",
                                  "Get a configuration option value or the whole configuration if no name is "
                                  "provided");
    get_subcommand
        ->add_option("name", options->name, "Name of the configuration option to get, empty to get all configuration")
        ->default_val("");
    get_subcommand->callback([options]() { runGet(options->socketPath, options->name); });

    auto save_subcommand =
        configApp->add_subcommand("save", "Persist the current configuration, to take effect restart the engine");
    save_subcommand
        ->add_option("path", options->path, "Path to save the configuration, empty to save in the default path")
        ->default_val("");
    save_subcommand->callback([options]() { runSave(options->socketPath, options->path); });

    auto put_subcommand = configApp->add_subcommand("put", "Update a configuration option");
    put_subcommand->add_option("name", options->name, "Name of the configuration option to set")->required();
    put_subcommand->add_option("value", options->value, "Value of the configuration option to set")->required();
    put_subcommand->callback([options]() { runPut(options->socketPath, options->name, options->value); });
}
} // namespace cmd::config
