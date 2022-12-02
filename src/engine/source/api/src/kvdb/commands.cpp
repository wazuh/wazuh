#include "api/kvdb/commands.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{
api::CommandFn kvdbCreateCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        // Get KVDB's name
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        if (kvdbName.value().empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        // Get KVDB's path
        const auto kvdbPath = params.getString("/path");

        const std::string result {kvdbManager->CreateAndFillDBfromFile(
            kvdbName.value(), kvdbPath.value_or(""))};
        if (result != "OK")
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, fmt::format("[{}] {}", kvdbName.value(), result)};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn kvdbDeleteCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        // get json params
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        if (kvdbName.value().empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        bool deleteOnlyLoaded {false};
        const auto result = kvdbManager->deleteDB(kvdbName.value(), deleteOnlyLoaded);
        if (!result)
        {
            // TODO: test for this case is missing
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("Database \"{}\" could not be deleted", kvdbName.value())};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn kvdbDumpCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        json::Json data;
        data.setArray("/data");
        auto retVal {kvdbManager->dumpContent(kvdbNameValue, data)};

        if (!retVal.has_value())
        {
            return api::WazuhResponse {json::Json {"{}"}, 200, retVal.value()};
        }

        auto val = data.str();
        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn kvdbGetKeyCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        const auto optKey = params.getString("/key");
        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_MISSING};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_EMPTY};
        }

        const auto retVal = kvdbManager->getKeyValue(kvdbNameValue, key);
        if (!retVal.has_value())
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("Key \"{}\" could not be found on database \"{}\"",
                            key,
                            kvdbNameValue)};
        }

        json::Json data {};
        data.setObject("/data");
        data.setString(key, "/key");
        data.setString(retVal.value(), "/value");
        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn kvdbInsertKeyCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        const auto optKey = params.getString("/key");
        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_MISSING};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_EMPTY};
        }

        const bool retVal {kvdbManager->writeKey(
            kvdbNameValue, key, params.getString("/value").value_or(""))};

        if (!retVal)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Key-value could not be written to the database"};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn kvdbListCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        // get json params
        const auto kvdbNameToMatch = params.getString("/name");
        bool filtered {false};
        if (kvdbNameToMatch.has_value() && !kvdbNameToMatch.value().empty())
        {
            filtered = true;
        }

        const auto filterLoadedKVDB = params.getBool("/mustBeLoaded");
        bool listOnlyLoaded {false};
        if (filterLoadedKVDB.has_value())
        {
            listOnlyLoaded = filterLoadedKVDB.value();
        }

        auto kvdbLists = kvdbManager->listDBs(listOnlyLoaded);
        json::Json data;
        data.setArray("/data");
        if (kvdbLists.size())
        {
            for (const std::string& dbName : kvdbLists)
            {
                if (filtered)
                {
                    if (dbName.rfind(kvdbNameToMatch.value(), 0) != std::string::npos)
                    {
                        // Filter according to name start
                        data.appendString(dbName);
                    }
                }
                else
                {
                    data.appendString(dbName);
                }
            }
        }

        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn kvdbRemoveKeyCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");

        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_NAME_EMPTY};
        }

        const auto optKey = params.getString("/key");

        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_MISSING};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, KVDB_KEY_EMPTY};
        }

        const bool retVal {kvdbManager->deleteKey(kvdbNameValue, key)};

        if (!retVal)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("Key \"{}\" could not be deleted", key)};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

// TODO: missing tests for this method
void registerAllCmds(std::shared_ptr<KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("create_kvdb", kvdbCreateCmd(kvdbManager));
        registry->registerCommand("delete_kvdb", kvdbDeleteCmd(kvdbManager));
        registry->registerCommand("dump_kvdb", kvdbDumpCmd(kvdbManager));
        registry->registerCommand("get_kvdb", kvdbGetKeyCmd(kvdbManager));
        registry->registerCommand("insert_kvdb", kvdbInsertKeyCmd(kvdbManager));
        registry->registerCommand("list_kvdb", kvdbListCmd(kvdbManager));
        registry->registerCommand("remove_kvdb", kvdbRemoveKeyCmd(kvdbManager));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("KVDB API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::kvdb::cmds
