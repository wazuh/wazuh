#include "api/kvdb/commands.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{
api::CommandFn createKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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

        const bool result {kvdbManager->CreateAndFillKVDBfromFile(kvdbName.value(),
                                                                  kvdbPath.value_or(""))};
        if (!result)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("Database \"{}\" could not be created", kvdbName.value())};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn deleteKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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

        const auto filterLoadedKVDB = params.getBool("/mustBeLoaded");
        bool deleteOnlyLoaded {false};
        if (filterLoadedKVDB.has_value())
        {
            deleteOnlyLoaded = filterLoadedKVDB.value();
        }

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

api::CommandFn dumpKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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

        std::string dbContent;
        const size_t retVal {kvdbManager->dumpContent(kvdbNameValue, dbContent)};

        json::Json data;
        data.setArray("/data");
        if (retVal)
        {
            std::istringstream iss(dbContent);
            for (std::string line; std::getline(iss, line);)
            {
                std::string jsonFill;
                auto splittedLine = utils::string::split(line, ':');
                const size_t lineMemebers = splittedLine.size();
                if (!lineMemebers || 2 < lineMemebers)
                {
                    return api::WazuhResponse {json::Json {"{}"}, 400, "KVDB was ill formed"};
                }
                else if (2 == lineMemebers)
                {
                    jsonFill = fmt::format("{{\"key\": \"{}\",\"value\": \"{}\"}}",
                                        splittedLine.at(0),
                                        splittedLine.at(1));
                }
                else if (1 == lineMemebers)
                {
                    jsonFill = fmt::format("{{\"key\": \"{}\"}}", splittedLine.at(0));
                }

                const json::Json keyValueObject {jsonFill.c_str()};
                data.appendJson(keyValueObject);
            }
        }

        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn getKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is missing"};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is empty"};
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

api::CommandFn insertKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is missing"};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is empty"};
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

api::CommandFn listKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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

        auto kvdbLists = kvdbManager->getAvailableKVDBs(listOnlyLoaded);
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

api::CommandFn removeKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
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
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is missing"};
        }

        const std::string key {optKey.value()};
        if (key.empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter \"key\" is empty"};
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
        registry->registerCommand("create_kvdb", createKvdbCmd(kvdbManager));
        registry->registerCommand("delete_kvdb", deleteKvdbCmd(kvdbManager));
        registry->registerCommand("dump_kvdb", dumpKvdbCmd(kvdbManager));
        registry->registerCommand("get_kvdb", getKvdbCmd(kvdbManager));
        registry->registerCommand("insert_kvdb", insertKvdbCmd(kvdbManager));
        registry->registerCommand("list_kvdb", listKvdbCmd(kvdbManager));
        registry->registerCommand("remove_kvdb", removeKvdbCmd(kvdbManager));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("KVDB API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::kvdb::cmds
