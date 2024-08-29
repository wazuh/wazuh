#include <cmds/geo.hpp>

#include <eMessages/geo.pb.h>
#include <yml/yml.hpp>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace
{
struct Options
{
    std::string path;
    std::string type;
    std::string dbUrl;
    std::string hashUrl;
    std::string serverApiSock;
    bool jsonFormat;
    int clientTimeout;
};
} // namespace

namespace cmd::geo
{
namespace eGeo = ::com::wazuh::api::engine::geo;
namespace eEngine = ::com::wazuh::api::engine;

void runAdd(const std::shared_ptr<apiclnt::Client>& client, const std::string& path, const std::string& type)
{
    using RequestType = eGeo::DbPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "geo.db/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_path(path);
    eRequest.set_type(type);

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runDelete(const std::shared_ptr<apiclnt::Client>& client, const std::string& path)
{
    using RequestType = eGeo::DbDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "geo.db/delete";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_path(path);

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runList(const std::shared_ptr<apiclnt::Client>& client, bool jsonFormat)
{
    using RequestType = eGeo::DbList_Request;
    using ResponseType = eGeo::DbList_Response;
    const std::string command = "geo.db/list";

    // Prepare the request
    RequestType eRequest;

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the list
    const auto& list = eResponse.entries();
    const auto json = eMessage::eRepeatedFieldToJson<eGeo::DbEntry>(list);

    if (jsonFormat)
    {
        std::cout << std::get<std::string>(json) << std::endl;
    }
    else
    {
        rapidjson::Document doc;
        doc.Parse(std::get<std::string>(json).c_str());
        auto yaml = yml::Converter::jsonToYaml(doc);
        YAML::Emitter out;
        out << yaml;
        std::cout << out.c_str() << std::endl;
    }
}

void runRemoteUpsert(const std::shared_ptr<apiclnt::Client>& client,
                     const std::string& path,
                     const std::string& type,
                     const std::string& dbUrl,
                     const std::string& hashUrl)
{
    using RequestType = eGeo::DbRemoteUpsert_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "geo.db/remoteUpsert";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_path(path);
    eRequest.set_type(type);
    eRequest.set_dburl(dbUrl);
    eRequest.set_hashurl(hashUrl);

    // Call the API and parse the response (Throw if error)
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto geoApp = app->add_subcommand("geo", "Manage GeoIP databases");
    geoApp->require_subcommand(1);

    auto options = std::make_shared<Options>();

    // Endpoint
    geoApp->add_option("-s, --api_socket", options->serverApiSock, "Sets the API server socket address.")
        ->default_val(ENGINE_SRV_API_SOCK)
        ->check(CLI::ExistingFile);

    // Client timeout
    geoApp
        ->add_option("-t, --client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // Add
    auto add = geoApp->add_subcommand("add", "Add a GeoIP database");
    add->add_option("path", options->path, "Path to the GeoIP database")->required()->check(CLI::ExistingFile);
    add->add_option("type", options->type, "Type of the GeoIP database")
        ->required()
        ->check(CLI::IsMember({"city", "asn"}));

    add->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runAdd(client, options->path, options->type);
        });

    // Delete
    auto del = geoApp->add_subcommand("delete", "Delete a GeoIP database from the manager. File won't be deleted");
    del->add_option("path", options->path, "Path to the GeoIP database")->required()->check(CLI::ExistingFile);

    del->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDelete(client, options->path);
        });

    // List
    auto list = geoApp->add_subcommand("list", "List all GeoIP databases in use by the manager");
    list->add_flag("-j, --json", options->jsonFormat, "Output in JSON format. Default is YAML");

    list->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runList(client, options->jsonFormat);
        });

    // Remote upsert
    auto remoteUpsert =
        geoApp->add_subcommand("remoteUpsert", "Download and update a GeoIP database from a remote URL");
    remoteUpsert->add_option("path", options->path, "Path where the GeoIP database will be download")->required();
    remoteUpsert->add_option("type", options->type, "Type of the GeoIP database")
        ->required()
        ->check(CLI::IsMember({"city", "asn"}));
    remoteUpsert->add_option("dburl", options->dbUrl, "URL to download the GeoIP database")->required();
    remoteUpsert->add_option("hashurl", options->hashUrl, "URL to download the hash of the GeoIP database")->required();

    remoteUpsert->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runRemoteUpsert(client, options->path, options->type, options->dbUrl, options->hashUrl);
        });
}
} // namespace cmd::geo
