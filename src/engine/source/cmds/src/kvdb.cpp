#include <cmds/kvdb.hpp>

#include <eMessages/kvdb.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>
namespace cmd::kvdb
{
namespace
{
struct Options
{
    std::string apiEndpoint;
    bool loaded;
    std::string kvdbName;
    std::string kvdbInputFilePath;
    std::string kvdbKey;
    std::string kvdbValue;
};

} // namespace

namespace details
{
std::string commandName(const std::string& command)
{
    return command + "_kvdb";
}

json::Json getParameters(const std::string& action, const std::string& name, bool loaded)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    data.setString(name, "/name");
    data.setBool(loaded, "/mustBeLoaded");
    return data;
}

json::Json getParameters(const std::string& action, const std::string& name, const std::string& path)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    data.setString(name, "/name");
    data.setString(path, "/path");
    return data;
}

json::Json getParameters(const std::string& action, const std::string& name)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    data.setString(name, "/name");
    return data;
}

json::Json getParametersKey(const std::string& action, const std::string& name, const std::string& key)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    data.setString(name, "/name");
    data.setString(key, "/key");
    return data;
}

json::Json getParametersKeyValue(const std::string& action,
                                 const std::string& name,
                                 const std::string& key,
                                 const std::string& value)
{
    json::Json data {};
    data.setObject();
    data.setString(action, "/action");
    data.setString(name, "/name");
    data.setString(key, "/key");

    // check if value is a json
    try
    {
        json::Json jvalue {value.c_str()};
        data.set("/value", jvalue);
    }
    catch (const std::exception& e)
    {
        // If not, set it as a string
        data.setString(value, "/value");
    }

    return data;
}

void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response)
{
    if (response.data().size() > 0)
    {
        std::cout << response.data().str() << std::endl;
    }
    else
    {
        std::cout << response.message().value_or("") << std::endl;
    }
}

void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& apiEndpoint)
{
    try
    {
        apiclnt::Client client {apiEndpoint};
        const auto response = client.send(request);
        details::processResponse(response);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return;
    }
}

} // namespace details

void runList(const std::string& apiEndpoint, const std::string& kvdbName, bool loaded)
{
    auto req = base::utils::wazuhProtocol::WazuhRequest::create(details::commandName(details::API_KVDB_LIST_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_KVDB_LIST_SUBCOMMAND, kvdbName, loaded));

    details::singleRequest(req, apiEndpoint);
}

void runCreate(const std::string& apiEndpoint, const std::string& kvdbName, const std::string& kvdbInputFilePath)
{
    auto req = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName(details::API_KVDB_CREATE_SUBCOMMAND),
        details::ORIGIN_NAME,
        details::getParameters(details::API_KVDB_CREATE_SUBCOMMAND, kvdbName, kvdbInputFilePath));

    details::singleRequest(req, apiEndpoint);
}

void runDump(const std::string& apiEndpoint, const std::string& kvdbName)
{
    auto req = base::utils::wazuhProtocol::WazuhRequest::create(details::commandName(details::API_KVDB_DUMP_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_KVDB_DUMP_SUBCOMMAND, kvdbName));

    details::singleRequest(req, apiEndpoint);
}

void runDelete(const std::string& apiEndpoint, const std::string& kvdbName)
{
    auto req = base::utils::wazuhProtocol::WazuhRequest::create(details::commandName(details::API_KVDB_DELETE_SUBCOMMAND),
                                         details::ORIGIN_NAME,
                                         details::getParameters(details::API_KVDB_DELETE_SUBCOMMAND, kvdbName));

    details::singleRequest(req, apiEndpoint);
}

void runGetKV(const std::string& apiEndpoint, const std::string& kvdbName, const std::string& kvdbKey)
{
    auto req =
        base::utils::wazuhProtocol::WazuhRequest::create(details::commandName(details::API_KVDB_GET_SUBCOMMAND),
                                  details::ORIGIN_NAME,
                                  details::getParametersKey(details::API_KVDB_GET_SUBCOMMAND, kvdbName, kvdbKey));

    details::singleRequest(req, apiEndpoint);
}

void runInsertKV(const std::string& apiEndpoint,
                 const std::string& kvdbName,
                 const std::string& kvdbKey,
                 const std::string& kvdbValue)
{
    auto req = base::utils::wazuhProtocol::WazuhRequest::create(
        details::commandName(details::API_KVDB_INSERT_SUBCOMMAND),
        details::ORIGIN_NAME,
        details::getParametersKeyValue(details::API_KVDB_INSERT_SUBCOMMAND, kvdbName, kvdbKey, kvdbValue));

    details::singleRequest(req, apiEndpoint);
}

void runRemoveKV(const std::string& apiEndpoint, const std::string& kvdbName, const std::string& kvdbKey)
{
    auto req =
        base::utils::wazuhProtocol::WazuhRequest::create(details::commandName(details::API_KVDB_REMOVE_SUBCOMMAND),
                                  details::ORIGIN_NAME,
                                  details::getParametersKey(details::API_KVDB_REMOVE_SUBCOMMAND, kvdbName, kvdbKey));

    details::singleRequest(req, apiEndpoint);
}

void configure(CLI::App_p app)
{
    auto kvdbApp = app->add_subcommand("kvdb", "Manage the key-value databases (KVDBs).");
    kvdbApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    kvdbApp->add_option("-a, --api_socket", options->apiEndpoint, "engine api address")->default_val(ENGINE_API_SOCK);

    // KVDB list subcommand
    auto list_subcommand = kvdbApp->add_subcommand(details::API_KVDB_LIST_SUBCOMMAND, "List all KVDB availables.");
    list_subcommand->add_flag("--loaded", options->loaded, "List only KVDBs loaded on memory.");
    list_subcommand
        ->add_option("-n, --name", options->kvdbName, "KVDB name to match the start of the name of the available ones.")
        ->default_val("");
    list_subcommand->callback([options]() { runList(options->apiEndpoint, options->kvdbName, options->loaded); });

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
    create_subcommand->callback([options]()
                                { runCreate(options->apiEndpoint, options->kvdbName, options->kvdbInputFilePath); });

    // KVDB dump subcommand
    auto dump_subcommand = kvdbApp->add_subcommand(details::API_KVDB_DUMP_SUBCOMMAND,
                                                   "Dumps the full content of a DB named db-name to a JSON.");
    // dump kvdb name
    dump_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be dumped.")->required();
    dump_subcommand->callback([options]() { runDump(options->apiEndpoint, options->kvdbName); });

    // KVDB delete subcommand
    auto delete_subcommand =
        kvdbApp->add_subcommand(details::API_KVDB_DELETE_SUBCOMMAND, "Deletes a KeyValueDB named db-name.");
    // delete KVDB name
    delete_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be deleted.")->required();
    delete_subcommand->callback([options]() { runDelete(options->apiEndpoint, options->kvdbName); });

    // KVDB get subcommand
    auto get_subcommand = kvdbApp->add_subcommand(details::API_KVDB_GET_SUBCOMMAND,
                                                  "Gets key or key and value (if possible) of a DB named db-name.");
    // get kvdb name
    get_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    // get key
    get_subcommand->add_option("-k, --key", options->kvdbKey, "key name to be obtained.")->required();
    get_subcommand->callback([options]() { runGetKV(options->apiEndpoint, options->kvdbName, options->kvdbKey); });

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
        [options]() { runInsertKV(options->apiEndpoint, options->kvdbName, options->kvdbKey, options->kvdbValue); });

    // KVDB remove subcommand
    auto remove_subcommand = kvdbApp->add_subcommand("remove", "Removes key from db-name.");
    // remove kvdb name
    remove_subcommand->add_option("-n, --name", options->kvdbName, "KVDB name to be queried.")->required();
    // remove key
    auto key = remove_subcommand->add_option("-k, --key", options->kvdbKey, "key name to be removed.")->required();
    remove_subcommand->callback([options]() { runRemoveKV(options->apiEndpoint, options->kvdbName, options->kvdbKey); });
}

} // namespace cmd::kvdb
