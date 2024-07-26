#include <cmds/kvdb.hpp>

#include <filesystem>

#include <eMessages/kvdb.pb.h>

#include "base/utils/stringUtils.hpp"
#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>

namespace
{
struct Options
{
    std::string serverApiSock {};
    bool loaded {false};
    std::string kvdbName {};
    std::uint32_t page {};
    std::uint32_t records {};
    std::string kvdbInputFilePath {};
    std::string kvdbKey {};
    std::string kvdbValue {};
    std::string prefix {};
    int clientTimeout {};
};

} // namespace

namespace cmd::kvdb
{

namespace eKVDB = ::com::wazuh::api::engine::kvdb;
namespace eEngine = ::com::wazuh::api::engine;

void runList(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, bool loaded)
{
    using RequestType = eKVDB::managerGet_Request;
    using ResponseType = eKVDB::managerGet_Response;
    const std::string command = "kvdb.manager/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_must_be_loaded(loaded);
    if (!kvdbName.empty())
    {
        eRequest.set_filter_by_name(kvdbName);
    }

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print dbs one name by line
    for (const auto& dbName : eResponse.dbs())
    {
        std::cout << dbName << std::endl;
    }
}

void runCreate(std::shared_ptr<apiclnt::Client> client,
               const std::string& kvdbName,
               const std::string& kvdbInputFilePath)
{
    using RequestType = eKVDB::managerPost_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "kvdb.manager/post";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);

    if (!kvdbInputFilePath.empty())
    {
        std::string kvdbPath = kvdbInputFilePath;
        if (!base::utils::string::startsWith(kvdbInputFilePath, "/"))
        {
            std::filesystem::path path(kvdbInputFilePath);
            kvdbPath = std::filesystem::absolute(path).string();
        }

        eRequest.set_path(kvdbPath);
    }

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runDump(std::shared_ptr<apiclnt::Client> client,
             const std::string& kvdbName,
             const unsigned int page,
             const unsigned int records)
{
    using RequestType = eKVDB::managerDump_Request;
    using ResponseType = eKVDB::managerDump_Response;
    const std::string command = "kvdb.manager/dump";

    // Prepare the request
    RequestType eRequest;

    eRequest.set_name(kvdbName);
    eRequest.set_page(page);
    eRequest.set_records(records);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the dump
    const auto& dump = eResponse.entries();
    const auto json = eMessage::eRepeatedFieldToJson<eKVDB::Entry>(dump);
    std::cout << std::get<std::string>(json) << std::endl;
}

void runDelete(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName)
{
    using RequestType = eKVDB::managerDump_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "kvdb.manager/delete";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runGetKV(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, const std::string& kvdbKey)
{
    using RequestType = eKVDB::dbGet_Request;
    using ResponseType = eKVDB::dbGet_Response;
    const std::string command = "kvdb.db/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);
    eRequest.set_key(kvdbKey);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void runInsertKV(std::shared_ptr<apiclnt::Client> client,
                 const std::string& kvdbName,
                 const std::string& kvdbKey,
                 const std::string& kvdbValue)
{
    using RequestType = eKVDB::dbPut_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "kvdb.db/put";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);
    eRequest.mutable_entry()->set_key(kvdbKey);

    // Convert the value to JSON
    json::Json jvalue {};
    try
    {
        jvalue = json::Json {kvdbValue.c_str()};
    }
    catch (const std::exception& e)
    {
        // If not, set it as a string
        jvalue.setString(kvdbValue);
    }

    // Convert the value to protobuf value
    const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(jvalue.str());
    if (std::holds_alternative<base::Error>(protoVal)) // Should not happen but just in case
    {
        const auto msj = std::get<base::Error>(protoVal).message + ". For value " + jvalue.str();
        throw ::cmd::ClientException(msj, ClientException::Type::PROTOBUFF_SERIALIZE_ERROR);
    }
    const auto& value = std::get<google::protobuf::Value>(protoVal);
    *eRequest.mutable_entry()->mutable_value() = value;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runRemoveKV(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, const std::string& kvdbKey)
{
    using RequestType = eKVDB::dbDelete_Request;
    using ResponseType = eEngine::GenericStatus_Response;
    const std::string command = "kvdb.db/delete";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);
    eRequest.set_key(kvdbKey);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runSearch(std::shared_ptr<apiclnt::Client> client,
               const std::string& kvdbName,
               const std::string& prefix,
               const unsigned int page,
               const unsigned int records)
{
    using RequestType = eKVDB::dbSearch_Request;
    using ResponseType = eKVDB::dbSearch_Response;
    const std::string command = "kvdb.db/search";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(kvdbName);
    eRequest.set_prefix(prefix);
    eRequest.set_page(page);
    eRequest.set_records(records);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print the dump
    const auto& dump = eResponse.entries();
    const auto json = eMessage::eRepeatedFieldToJson<eKVDB::Entry>(dump);
    std::cout << std::get<std::string>(json) << std::endl;
}

void configure(const CLI::App_p& app)
{
    auto kvdbApp = app->add_subcommand("kvdb", "Manage the key-value databases (KVDBs).");
    kvdbApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    kvdbApp->add_option("-a, --api_socket", options->serverApiSock, "engine api address")
        ->default_val(ENGINE_SRV_API_SOCK);

    // Client timeout
    kvdbApp->add_option("--client_timeout", options->clientTimeout, "Sets the timeout for the client in miliseconds.")
        ->default_val(ENGINE_CLIENT_TIMEOUT)
        ->check(CLI::NonNegativeNumber);

    // KVDB list subcommand
    auto list_subcommand = kvdbApp->add_subcommand(details::API_KVDB_LIST_SUBCOMMAND, "List all KVDB availables.");
    list_subcommand->add_flag("--loaded", options->loaded, "List only KVDBs loaded on memory.");
    list_subcommand
        ->add_option("-n, --name", options->kvdbName, "KVDB name to match the start of the name of the available ones.")
        ->default_val("");
    list_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runList(client, options->kvdbName, options->loaded);
        });

    // KVDB create subcommand
    auto create_subcommand =
        kvdbApp->add_subcommand(details::API_KVDB_CREATE_SUBCOMMAND, "Creates a KeyValueDB named db-name.");
    // create kvdb name
    create_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be added.")->required();
    // create kvdb from file with path
    create_subcommand
        ->add_option("-p, --path",
                     options->kvdbInputFilePath,
                     "Path to the file to be used as input to create the KVDB. If not provided,"
                     "the KVDB will be created empty.\n"
                     "The file must be a JSON file with the following format: {\"key\": VALUE} "
                     "where VALUE can be any JSON type.")
        ->check(CLI::ExistingFile);
    create_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runCreate(client, options->kvdbName, options->kvdbInputFilePath);
        });

    // KVDB dump subcommand
    auto dump_subcommand = kvdbApp->add_subcommand(details::API_KVDB_DUMP_SUBCOMMAND,
                                                   "Dumps the full content of a DB named db-name to a JSON.");
    // dump kvdb name
    dump_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be dumped.")->required();
    dump_subcommand->add_option("-p, --page", options->page, "Page number of pagination.")
        ->default_val(ENGINE_KVDB_CLI_PAGE);
    dump_subcommand->add_option("-r, --records", options->records, "Number of records per page.")
        ->default_val(ENGINE_KVDB_CLI_RECORDS);
    dump_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDump(client, options->kvdbName, options->page, options->records);
        });

    // KVDB delete subcommand
    auto delete_subcommand =
        kvdbApp->add_subcommand(details::API_KVDB_DELETE_SUBCOMMAND, "Deletes a KeyValueDB named db-name.");
    // delete KVDB name
    delete_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be deleted.")->required();
    delete_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runDelete(client, options->kvdbName);
        });

    // KVDB get subcommand
    auto get_subcommand = kvdbApp->add_subcommand(details::API_KVDB_GET_SUBCOMMAND,
                                                  "Gets key or key and value (if possible) of a DB named db-name.");
    // get kvdb name
    get_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    // get key
    get_subcommand->add_option("-k, --key", options->kvdbKey, "key name to be obtained.")->required();
    get_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runGetKV(client, options->kvdbName, options->kvdbKey);
        });

    // KVDB insert subcommand
    auto insert_subcommand =
        kvdbApp->add_subcommand(details::API_KVDB_INSERT_SUBCOMMAND, "Inserts key or key value into db-name.");
    // insert kvdb name
    insert_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    // insert key
    insert_subcommand->add_option("-k, --key", options->kvdbKey, "key name to be inserted.")->required();
    // insert value
    insert_subcommand->add_option("-v, --value", options->kvdbValue, "value to be inserted on key.")
        ->default_val("null");
    insert_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runInsertKV(client, options->kvdbName, options->kvdbKey, options->kvdbValue);
        });

    // KVDB remove subcommand
    auto remove_subcommand = kvdbApp->add_subcommand("remove", "Removes key from db-name.");
    // remove kvdb name
    remove_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    // remove key
    auto key = remove_subcommand->add_option("-k, --key", options->kvdbKey, "key name to be removed.")->required();
    remove_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runRemoveKV(client, options->kvdbName, options->kvdbKey);
        });

    // KVDB search subcommand
    auto search_subcommand = kvdbApp->add_subcommand(details::API_KVDB_SEARCH_SUBCOMMAND,
                                                     "Gets a list of keys filtered by a prefix of a DB named db-name.");
    search_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    search_subcommand->add_option("-f, --filter_prefix", options->prefix, "prefix to filter.")->required();
    search_subcommand->add_option("-p, --page", options->page, "Page number of pagination.")
        ->default_val(ENGINE_KVDB_CLI_PAGE);
    search_subcommand->add_option("-r, --records", options->records, "Number of records per page.")
        ->default_val(ENGINE_KVDB_CLI_RECORDS);
    search_subcommand->callback(
        [options]()
        {
            const auto client = std::make_shared<apiclnt::Client>(options->serverApiSock, options->clientTimeout);
            runSearch(client, options->kvdbName, options->prefix, options->page, options->records);
        });
}

} // namespace cmd::kvdb
