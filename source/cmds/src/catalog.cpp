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
#include <base/name.hpp>

#include <eMessages/catalog.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiExcept.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/logging.hpp>

namespace cmd::catalog
{

namespace eCatalog = ::com::wazuh::api::engine::catalog;
namespace eEngine = ::com::wazuh::api::engine;
namespace
{

struct Options
{
    std::string serverApiSock;
    std::string format;
    std::string level;
    std::string name;
    std::string content;
    std::string path;
    bool recursive;
    bool abortOnError;
    std::string policy;
    std::string integration;
    std::string namespaceId;
    std::string role;
    int clientTimeout;
};

eCatalog::ResourceFormat toResourceFormat(const std::string& format)
{
    if (format == "json")
    {
        return eCatalog::ResourceFormat::json;
    }
    else if (format == "yaml")
    {
        return eCatalog::ResourceFormat::yaml;
    }

    throw std::invalid_argument("Invalid Resource format: " + format);
}
/**
 * @brief Convert a string to a ResourceType.
 *
 * decoder, rule, filter, output, policy, schema, collection
 * @param type
 * @return eCatalog::ResourceType
 */
eCatalog::ResourceType toResourceType(const std::string& type)
{
    if (type == "decoder")
    {
        return eCatalog::ResourceType::decoder;
    }
    else if (type == "rule")
    {
        return eCatalog::ResourceType::rule;
    }
    else if (type == "filter")
    {
        return eCatalog::ResourceType::filter;
    }
    else if (type == "output")
    {
        return eCatalog::ResourceType::output;
    }
    else if (type == "schema")
    {
        return eCatalog::ResourceType::schema;
    }
    else if (type == "integration")
    {
        return eCatalog::ResourceType::integration;
    }
    // else if (type == "collection")
    //{
    //     return eCatalog::ResourceType::collection;
    // }

    throw std::invalid_argument("Invalid Resource type: " + type);
}

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

void runGet(std::shared_ptr<apiclnt::Client> client,
            const std::string& format,
            const std::string& nameStr,
            const std::string& namespaceId,
            const std::string& role)
{
    using RequestType = eCatalog::ResourceGet_Request;
    using ResponseType = eCatalog::ResourceGet_Response;
    const std::string command = "catalog.resource/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);
    eRequest.set_format(toResourceFormat(format));
    eRequest.set_namespaceid(namespaceId);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    std::cout << eResponse.content() << std::endl;
}

void runUpdate(std::shared_ptr<apiclnt::Client> client,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content,
               const std::string& role)
{
    using RequestType = eCatalog::ResourcePut_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "catalog.resource/put";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(nameStr);
    eRequest.set_format(toResourceFormat(format));
    eRequest.set_content(content);
    eRequest.set_namespaceid(role);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runCreate(std::shared_ptr<apiclnt::Client> client,
               const std::string& format,
               const std::string& resourceTypeStr,
               const std::string& content,
               const std::string& namespaceId,
               const std::string& role)
{
    using RequestType = eCatalog::ResourcePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "catalog.resource/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_type(toResourceType(resourceTypeStr));
    eRequest.set_format(toResourceFormat(format));
    eRequest.set_content(content);
    eRequest.set_namespaceid(namespaceId);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runDelete(std::shared_ptr<apiclnt::Client> client,
               const std::string& format,
               const std::string& nameStr,
               const std::string& namespaceId,
               const std::string& role)
{
    using RequestType = eCatalog::ResourceDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "catalog.resource/delete";

    // Prepare the request

    RequestType eRequest;
    eRequest.set_name(nameStr);
    eRequest.set_namespaceid(namespaceId);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runValidate(std::shared_ptr<apiclnt::Client> client,
                 const std::string& format,
                 const std::string& resourceType,
                 const std::string& content)
{
    using RequestType = eCatalog::ResourceValidate_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "catalog.resource/validate";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(resourceType);
    eRequest.set_format(toResourceFormat(format));
    eRequest.set_content(content);

    // Call the API, any error will throw an cmd::exception
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runLoad(std::shared_ptr<apiclnt::Client> client,
             const std::string& resourceFormatStr,
             const std::string& resourceTypeStr,
             const std::string& path,
             bool recursive,
             bool abortOnError,
             const std::string& namespaceId,
             const std::string& role)
{

    using RequestType = eCatalog::ResourcePost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "catalog.resource/post";

    // Build and check collection path
    std::error_code ec;
    std::filesystem::path collectionPath;

    try
    {
        collectionPath = std::filesystem::path(path);
    }
    catch (const std::exception& e)
    {
        throw ClientException(std::string("Invalid path: ") + e.what(), ClientException::Type::PATH_ERROR);
    }
    if (!std::filesystem::is_directory(collectionPath, ec))
    {
        ec.clear();
        throw ClientException(collectionPath.string() + " is not a directory: ", ClientException::Type::PATH_ERROR);
    }

    // Assert collection name is valid
    eCatalog::ResourceType type;
    eCatalog::ResourceFormat format;
    try
    {
        type = toResourceType(resourceTypeStr);
        format = toResourceFormat(resourceFormatStr);
    }
    catch (const std::exception& e)
    {
        throw ClientException(e.what(), ClientException::Type::INVALID_ARGUMENT);
    }

    auto loadEntry = [&](decltype(*std::filesystem::directory_iterator(collectionPath, ec)) dirEntry)
    {
        // If error ignore entry and continue
        if (ec)
        {
            const auto msg = std::string {"Failed to read entry "} + dirEntry.path().string() + ": " + ec.message();
            ec.clear();
            if (abortOnError)
            {
                throw ClientException(msg, ClientException::Type::PATH_ERROR);
            }
            std::cerr << msg << std::endl;
            return;
        }

        if (dirEntry.is_regular_file(ec))
        {
            // If error ignore entry and continue
            if (ec)
            {
                const auto msg = std::string {"Failed to read entry "} + dirEntry.path().string() + ": " + ec.message();
                ec.clear();
                if (abortOnError)
                {
                    throw ClientException(msg, ClientException::Type::PATH_ERROR);
                }
                std::cerr << msg << std::endl;
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
                const auto msg = std::string {"Failed to read entry "} + dirEntry.path().string() + ": " + e.what();
                ec.clear();
                if (abortOnError)
                {
                    throw ClientException(msg, ClientException::Type::PATH_ERROR);
                }
                std::cerr << msg << std::endl;
                return;
            }

            // Send request
            RequestType eRequest;
            eRequest.set_type(type);
            eRequest.set_format(format);
            eRequest.set_content(content);
            eRequest.set_namespaceid(namespaceId);

            try
            {
                const auto request =
                    utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
                const auto response = client->send(request);
                utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
            }
            catch (const ClientException& e)
            {
                switch (e.getErrorType())
                {
                    case ClientException::Type::SOCKET_COMMUNICATION_ERROR:
                        // Fatal error, stop iterating, rethrow
                        throw;
                    default:
                        // Non fatal error, continue iterating
                        const auto msg =
                            std::string {"Failed to read entry "} + dirEntry.path().string() + ": " + e.what();
                        ec.clear();
                        if (abortOnError)
                        {
                            throw ClientException(msg, ClientException::Type::PATH_ERROR);
                        }
                        std::cerr << msg << std::endl;
                        break;
                }
                return;
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
    catalogApp->add_option("-a, --api_socket", options->serverApiSock, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    catalogApp
        ->add_option("--client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // format
    catalogApp->add_option("-f, --format", options->format, "Sets the format of the input/output.")
        ->default_val("yaml")
        ->check(CLI::IsMember({"json", "yaml"}));

    // Log level
    catalogApp->add_option("-l, --log_level", options->level, "Sets the logging level.")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::IsMember({"trace", "debug", "info", "warning", "error", "critical", "off"}));

    // RBAC role
    // catalogApp->add_option("-r, --role", options->role, "Sets the RBAC role.")->default_val(ENGINE_RBAC_ROLE);

    // Namespaces
    catalogApp
        ->add_option("-n, --namespaces", options->namespaceId, "Specifies the namespace where the item is located.")
        ->default_val(ENGINE_NAMESPACE);

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
    get_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGet(client, options->format, options->name, {options->namespaceId}, options->namespaceId);
        });

    // update
    auto update_subcommand =
        catalogApp->add_subcommand("update", "update item-type/item-id/version << item_file: Update an item.");
    update_subcommand->add_option(name, options->name, nameDesc + "item to update: item-type/item-id/version")
        ->required();
    update_subcommand->add_option(item, options->content, itemDesc)->default_val("");
    update_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            readCinIfEmpty(options->content);
            runUpdate(client, options->format, options->name, options->content, options->namespaceId);
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
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            readCinIfEmpty(options->content);
            runCreate(
                client, options->format, options->name, options->content, {options->namespaceId}, options->namespaceId);
        });

    // delete
    auto delete_subcommand =
        catalogApp->add_subcommand("delete", "delete item-type[/item-id[/version]]: Delete an item or a collection.");
    delete_subcommand
        ->add_option(name, options->name, nameDesc + "item or collection to delete: item-type[/item-id[/version]]")
        ->required();
    delete_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDelete(client, options->format, options->name, options->namespaceId, options->namespaceId);
        });

    // validate
    auto validate_subcommand =
        catalogApp->add_subcommand("validate", "validate item-type/item-id/version << item_file: Validate an item.");
    validate_subcommand->add_option(name, options->name, nameDesc + "item to validate: item-type/item-id/version")
        ->required();
    validate_subcommand->add_option(item, options->content, itemDesc)->default_val("");
    validate_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            readCinIfEmpty(options->content);
            runValidate(client, options->format, options->name, options->content);
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
                           "\"schema\" and \"policy\".")
        ->required();
    load_subcommand->add_option("path", options->path, "Sets the path to the directory containing the item files.")
        ->required()
        ->check(CLI::ExistingDirectory);
    load_subcommand->add_flag("-r, --recursive", options->recursive, "Recursive loading of the directory.");
    load_subcommand->add_flag("-a, --abort", options->abortOnError, "Abort on error.");
    load_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runLoad(client,
                    options->format,
                    options->name,
                    options->path,
                    options->recursive,
                    options->abortOnError,
                    options->namespaceId,
                    options->role);
        });
}
} // namespace cmd::catalog
