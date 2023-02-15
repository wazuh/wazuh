#include <cmds/catalog.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>

#include <cmds/details/kbhit.hpp>
#include <name.hpp>

#include "apiclnt/client.hpp"
#include "defaultSettings.hpp"

namespace cmd::catalog
{

namespace
{

struct Options
{
    std::string apiEndpoint;
    std::string format;
    int logLevel;
    std::string name;
    std::string content;
    std::string path;
    bool recursive;
};

void readCinIfEmpty(std::string& content)
{
    if (content.empty() && cmd::details::kbhit())
    {
        std::stringstream ss;
        std::string line;
        while (std::getline(std::cin, line))
        {
            ss << line << std::endl;
        }
        content = ss.str();
    }
}

} // namespace

namespace details
{

std::string commandName(const std::string& command)
{
    return command + "_catalog";
}

json::Json getParameters(const std::string& format, const std::string& name, const std::string& content)
{
    json::Json params;
    params.setObject();
    params.setString(format, "/format");
    params.setString(name, "/name");
    if (!content.empty())
    {
        params.setString(content, "/content");
    }

    return params;
}

void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response)
{
    auto content = response.data().getString("/content");
    auto message = response.message();
    if (content)
    {
        std::cout << content.value() << std::endl;
    }
    else if (message)
    {
        std::cout << message.value() << std::endl;
    }
}

void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath)
{
    try
    {
        apiclnt::Client client(socketPath);
        auto response = client.send(request);
        details::processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

} // namespace details

void runGet(const std::string& socketPath, const std::string& format, const std::string& nameStr)
{
    auto request = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName("get"), details::ORIGIN_NAME, details::getParameters(format, nameStr));

    details::singleRequest(request, socketPath);
}

void runUpdate(const std::string& socketPath,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content)
{
    auto request = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName("put"), details::ORIGIN_NAME, details::getParameters(format, nameStr, content));

    details::singleRequest(request, socketPath);
}

void runCreate(const std::string& socketPath,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content)
{
    auto request = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName("post"), details::ORIGIN_NAME, details::getParameters(format, nameStr, content));

    details::singleRequest(request, socketPath);
}

void runDelete(const std::string& socketPath, const std::string& format, const std::string& nameStr)
{
    auto request = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName("delete"), details::ORIGIN_NAME, details::getParameters(format, nameStr));

    details::singleRequest(request, socketPath);
}

void runValidate(const std::string& socketPath,
                 const std::string& format,
                 const std::string& nameStr,
                 const std::string& content)
{
    auto request = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName("validate"), details::ORIGIN_NAME, details::getParameters(format, nameStr, content));

    details::singleRequest(request, socketPath);
}

void runLoad(const std::string& socketPath,
             const std::string& format,
             const std::string& nameStr,
             const std::string& path,
             bool recursive)
{
    // Build and check collection path
    std::error_code ec;
    std::filesystem::path collectionPath;

    try
    {
        collectionPath = std::filesystem::path(path);
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
    if (!std::filesystem::is_directory(collectionPath, ec))
    {
        std::cout << collectionPath << " is not a directory: " << std::endl;
        ec.clear();
        return;
    }

    // Assert collection name is valid
    if ("decoder" != nameStr && "rule" != nameStr && "filter" != nameStr && "output" != nameStr && "schema" != nameStr
        && "environment" != nameStr)
    {
        std::cout << "'" << nameStr << "'"
                  << " is not valid name" << std::endl;
        return;
    }

    auto loadEntry = [&](decltype(*std::filesystem::directory_iterator(collectionPath, ec)) dirEntry)
    {
        // If error ignore entry and continue
        if (ec)
        {
            std::cout << "Ignoring entry " << dirEntry.path() << ": " << ec.message() << std::endl;

            ec.clear();
            return;
        }

        if (dirEntry.is_regular_file(ec))
        {
            // If error ignore entry and continue
            if (ec)
            {
                std::cout << "Ignoring entry " << dirEntry.path() << ": " << ec.message() << std::endl;
                ec.clear();
                return;
            }

            // Read file content
            std::string content;

            try
            {
                std::ifstream file(dirEntry.path());
                content = std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
            }
            catch (const std::exception& e)
            {
                std::cout << "Ignoring entry " << dirEntry.path() << ": " << e.what() << std::endl;
                return;
            }

            // Send request
            auto request = base::utils::wazuhProtocol::WazuhRequest::create(
                details::commandName("post"), details::ORIGIN_NAME, details::getParameters(format, nameStr, content));
            std::cout << dirEntry << " ==> ";
            try
            {
                apiclnt::Client client(socketPath);
                auto response = client.send(request);
                details::processResponse(response);
            }
            catch (const std::exception& e)
            {
                std::cerr << e.what() << std::endl;
                return;
            }
        }
    };

    if (recursive)
    {
        // Iterate directory recursively and send requests to create items
        for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(collectionPath, ec))
        {
            loadEntry(dirEntry);
        }
    }
    else
    {
        // Iterate directory and send requests to create items
        for (const auto& dirEntry : std::filesystem::directory_iterator(collectionPath, ec))
        {
            loadEntry(dirEntry);
        }
    }
}

void configure(CLI::App_p app)
{
    auto catalogApp = app->add_subcommand("catalog", "Manage the engine's catalog.");
    catalogApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Shared options
    // Endpoint
    catalogApp->add_option("-a, --api_socket", options->apiEndpoint, "Sets the API server socket address.")
        ->default_val(ENGINE_API_SOCK)
        ->check(CLI::ExistingFile);

    // format
    catalogApp->add_option("-f, --format", options->format, "Sets the format of the input/output.")
        ->default_val("yaml")
        ->check(CLI::IsMember({"json", "yaml"}));

    // Log level
    catalogApp
        ->add_option(
            "-l, --log_level", options->logLevel, "Sets the logging level: 0 = Debug, 1 = Info, 2 = Warning, 3 = Error")
        ->default_val(3)
        ->check(CLI::Range(0, 3));

    // Shared option definitions among subcommands
    auto name = "name";
    std::string nameDesc = "Name that identifies the ";
    auto item = "item";
    std::string itemDesc = "Content of the item, can be passed as argument or redirected "
                           "from a file using the \"|\" operator or the \"<\" operator.";

    // Catalog subcommands
    // get
    auto get_subcommand =
        catalogApp->add_subcommand("get", "get item-type[/item-id[/item-version]]: Get an item or list a collection.");
    get_subcommand->add_option(name, options->name, nameDesc + "collection to list: item-type[/item-id]")->required();
    get_subcommand->callback([options]() { runGet(options->apiEndpoint, options->format, options->name); });

    // update
    auto update_subcommand =
        catalogApp->add_subcommand("update", "update item-type/item-id/version << item_file: Update an item.");
    update_subcommand->add_option(name, options->name, nameDesc + "item to update: item-type/item-id/version")
        ->required();
    update_subcommand->add_option(item, options->content, itemDesc)->default_val("");
    update_subcommand->callback(
        [options]()
        {
            readCinIfEmpty(options->content);
            runUpdate(options->apiEndpoint, options->format, options->name, options->content);
        });

    // create
    auto create_subcommand = catalogApp->add_subcommand(
        "create", "create item-type << item_file: Create and add an item to the collection.");
    create_subcommand->add_option(name, options->name, nameDesc + "collection to add an item to: item-type")
        ->required();
    create_subcommand->add_option(item, options->content, itemDesc)->default_val("");
    create_subcommand->callback(
        [options]()
        {
            readCinIfEmpty(options->content);
            runCreate(options->apiEndpoint, options->format, options->name, options->content);
        });

    // delete
    auto delete_subcommand =
        catalogApp->add_subcommand("delete", "delete item-type[/item-id[/version]]: Delete an item or a collection.");
    delete_subcommand
        ->add_option(name, options->name, nameDesc + "item or collection to delete: item-type[/item-id[/version]]")
        ->required();
    delete_subcommand->callback([options]() { runDelete(options->apiEndpoint, options->format, options->name); });

    // validate
    auto validate_subcommand =
        catalogApp->add_subcommand("validate", "validate item-type/item-id/version << item_file: Validate an item.");
    validate_subcommand->add_option(name, options->name, nameDesc + "item to validate: item-type/item-id/version")
        ->required();
    validate_subcommand->add_option(item, options->content, itemDesc)->default_val("");
    validate_subcommand->callback(
        [options]()
        {
            readCinIfEmpty(options->content);
            runValidate(options->apiEndpoint, options->format, options->name, options->content);
        });

    // load
    auto load_subcommand = catalogApp->add_subcommand("load",
                                                      "load item-type path: Tries to create and add all the "
                                                      "items found in the path to the collection.");
    load_subcommand
        ->add_option(name,
                     options->name,
                     nameDesc
                         + "type of the items collection: item-type. The supported item "
                           "types are: \"decoder\", \"rule\", \"filter\", \"output\", "
                           "\"schema\" and \"environment\".")
        ->required();
    load_subcommand->add_option("path", options->path, "Sets the path to the directory containing the item files.")
        ->required()
        ->check(CLI::ExistingDirectory);
    load_subcommand->add_flag("-r, --recursive", options->recursive, "Recursive loading of the directory.");
    load_subcommand->callback(
        [options]()
        { runLoad(options->apiEndpoint, options->format, options->name, options->path, options->recursive); });
}
} // namespace cmd::catalog
