#include "api/kvdb/commands.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{

namespace
{
std::tuple<bool, std::string> getNameOrError(const json::Json& params)
{
    const auto kvdbName = params.getString("/name");
    if (!kvdbName)
    {
        if (params.exists("/name"))
        {
            return {false, KVDB_NAME_NOT_A_STRING};
        }
        return {false, KVDB_NAME_MISSING};
    }

    if (kvdbName.value().empty())
    {
        return {false, KVDB_NAME_EMPTY};
    }

    return {true, kvdbName.value()};
}

} // namespace

api::CommandFn kvdbCreateCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const json::Json& params) -> api::WazuhResponse
    {
        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::WazuhResponse {kvdbName};
        }

        // Get KVDB's path
        const auto kvdbPath = params.getString("/path");

        const auto error = kvdbManager->CreateFromJFile(kvdbName, kvdbPath.value_or(""));
        if (error)
        {
            return api::WazuhResponse {error.value().message};
        }

        return api::WazuhResponse {
            fmt::format("KVDB '{}' successfully created", kvdbName)};
    };
}

api::CommandFn kvdbDeleteCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const json::Json& params) -> api::WazuhResponse
    {
        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::WazuhResponse {kvdbName};
        }

        const auto error = kvdbManager->deleteDB(kvdbName);
        if (error)
        {
            return api::WazuhResponse {error.value().message};
        }

        return api::WazuhResponse {
            fmt::format("KVDB '{}' successfully deleted", kvdbName)};
    };
}

api::CommandFn kvdbDumpCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const json::Json& params) -> api::WazuhResponse
    {
        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::WazuhResponse {kvdbName};
        }

        auto result = kvdbManager->jDumpDB(kvdbName);
        if (std::holds_alternative<base::Error>(result))
        {
            return api::WazuhResponse {std::get<base::Error>(result).message};
        }

        return api::WazuhResponse {
            std::get<json::Json>(result),
            fmt::format("KVDB '{}' successfully dumped", kvdbName)};
    };
}

api::CommandFn kvdbGetKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const json::Json& params) -> api::WazuhResponse
    {
        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::WazuhResponse {kvdbName};
        }

        const auto optKey = params.getString("/key");
        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {KVDB_KEY_MISSING};
        }

        const auto key = optKey.value();
        if (key.empty())
        {
            return api::WazuhResponse {KVDB_KEY_EMPTY};
        }

        const auto result = kvdbManager->getJValue(kvdbName, key);
        if (std::holds_alternative<base::Error>(result))
        {
            return api::WazuhResponse {std::get<base::Error>(result).message};
        }
        const auto& value {std::get<json::Json>(result)};

        json::Json data {};
        data.setObject("/data");
        data.setString(key, "/key");
        data.set("/value", value);
        return api::WazuhResponse {std::move(data), 0, ""};
    };
}

api::CommandFn kvdbInsertKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_EMPTY};
        }

        const auto optKey = params.getString("/key");
        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_MISSING};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_EMPTY};
        }

        const auto optValue = params.getJson("/value");
        const auto error = kvdbManager->writeKey(
            kvdbNameValue, key, params.getJson("/value").value_or(json::Json("null")));

        if (error)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                0,
                std::string {"Key-value could not be written to the database:"}
                    + error.value().message};
        }

        return api::WazuhResponse {json::Json {"{}"}, 0, "OK"};
    };
}

api::CommandFn kvdbListCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
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

        return api::WazuhResponse {std::move(data), 0, "OK"};
    };
}

api::CommandFn kvdbRemoveKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        const auto kvdbName = params.getString("/name");

        if (!kvdbName)
        {
            if (params.exists("/name"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_MISSING};
        }

        const std::string kvdbNameValue {kvdbName.value()};
        if (kvdbNameValue.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_NAME_EMPTY};
        }

        const auto optKey = params.getString("/key");

        if (!optKey.has_value())
        {
            if (params.exists("/key"))
            {
                return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_NOT_A_STRING};
            }
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_MISSING};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 0, KVDB_KEY_EMPTY};
        }

        const auto retVal = kvdbManager->deleteKey(kvdbNameValue, key);

        if (retVal)
        {
            return api::WazuhResponse {json::Json {"{}"}, 0, retVal.value().message};
        }

        return api::WazuhResponse {json::Json {"{}"}, 0, "OK"};
    };
}

void registerAllCmds(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry)
{
    try // TODO: TRY ????
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
