#include "api/kvdb/commands.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{

namespace
{
/**
 * @brief Get the KVDB's name from the params or return an error
 *
 * @param params The json /data from the request
 * @return [bool, std::string] True if the name is valid, false otherwise
 *                             The name if it's valid, the error message otherwise.
 */
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

/**
 * @brief Get the KVDB's key from the params or return an error
 *
 * @param params The json /data from the request
 * @return [bool, std::string] True if the key is valid, false otherwise
 *                            The key if it's valid, the error message otherwise.
 */
std::tuple<bool, std::string> getKeyOrError(const json::Json& params)
{
    const auto key = params.getString("/key");
    if (!key)
    {
        if (params.exists("/key"))
        {
            return {false, KVDB_KEY_NOT_A_STRING};
        }
        return {false, KVDB_KEY_MISSING};
    }

    if (key.value().empty())
    {
        return {false, KVDB_KEY_EMPTY};
    }

    return {true, key.value()};
}

} // namespace

api::CommandFn kvdbCreateCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

        // Get KVDB's path
        const auto kvdbPath = params.getString("/path");

        const auto error = kvdbManager->createFromJFile(kvdbName, kvdbPath.value_or(""));
        if (error)
        {
            return api::wpResponse {error.value().message};
        }

        return api::wpResponse {
            fmt::format("KVDB '{}' successfully created", kvdbName)};
    };
}

api::CommandFn kvdbDeleteCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

        const auto error = kvdbManager->deleteDB(kvdbName);
        if (error)
        {
            return api::wpResponse {error.value().message};
        }

        return api::wpResponse {
            fmt::format("KVDB '{}' successfully deleted", kvdbName)};
    };
}

api::CommandFn kvdbDumpCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

        auto result = kvdbManager->jDumpDB(kvdbName);
        if (std::holds_alternative<base::Error>(result))
        {
            return api::wpResponse {std::get<base::Error>(result).message};
        }

        return api::wpResponse {
            std::get<json::Json>(result),
            fmt::format("KVDB '{}' successfully dumped", kvdbName)};
    };
}

api::CommandFn kvdbGetKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

       // get key
        const auto [okKey, key] = getKeyOrError(params);
        if (!okKey)
        {
            return api::wpResponse {key};
        }

        const auto result = kvdbManager->getJValue(kvdbName, key);
        if (std::holds_alternative<base::Error>(result))
        {
            return api::wpResponse {std::get<base::Error>(result).message};
        }
        const auto& value {std::get<json::Json>(result)};

        json::Json data {};
        data.setObject();
        data.setString(key, "/key");
        data.set("/value", value);
        return api::wpResponse {std::move(data), 0, ""};
    };
}

api::CommandFn kvdbInsertKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

       // Get key
        const auto [okKey, key] = getKeyOrError(params);
        if (!okKey)
        {
            return api::wpResponse {key};
        }

        const auto optValue = params.getJson("/value").value_or(json::Json("null"));
        const auto error = kvdbManager->writeKey(kvdbName, key, optValue);

        if (error)
        {
            auto msg = std::string {"Key-value could not be written to the database: "}
                       + error.value().message;
            return api::wpResponse {std::move(msg)};
        }

        return api::wpResponse {"Key-value successfully written to the database"};
    };
}

api::CommandFn kvdbListCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

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
        data.setArray();

        for (const std::string& dbName : kvdbLists)
        {
            if (filtered)
            {
                if (dbName.find(kvdbNameToMatch.value()) == 0)
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

        return api::wpResponse {std::move(data), 0};
    };
}

api::CommandFn kvdbRemoveKeyCmd(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        // Get KVDB's name
        const auto [ok, kvdbName] = getNameOrError(params);
        if (!ok)
        {
            return api::wpResponse {kvdbName};
        }

        // Get key
        const auto [okKey, key] = getKeyOrError(params);
        if (!okKey)
        {
            return api::wpResponse {key};
        }

        const auto retVal = kvdbManager->deleteKey(kvdbName, key);

        if (retVal)
        {
            return api::wpResponse {retVal.value().message};
        }

        return api::wpResponse {"ok"};
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
