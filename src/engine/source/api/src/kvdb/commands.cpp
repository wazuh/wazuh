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
        // get json params
        auto kvdbName = params.getString("/name");
        if (!kvdbName)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] string parameter"};
        }

        if (kvdbName.value().empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter [name] can't be an empty string"};
        }

        // get path for file
        auto inputFilePath = params.getString("/path");
        std::string inputFilePathValue {};

        if (inputFilePath.has_value() && !inputFilePath.value().empty())
        {
            inputFilePathValue = inputFilePath.value();
        }

        bool result =
            kvdbManager->CreateAndFillKVDBfromFile(kvdbName.value(), inputFilePathValue);
        if (!result)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("DB with name [{}] already exists.", kvdbName.value())};
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
        auto kvdbName = params.getString("/name");
        if (!kvdbName.has_value())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] string parameter"};
        }

        if (kvdbName.value().empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Parameter [name] can't be an empty string"};
        }

        auto filterLoadedKVDB = params.getBool("/mustBeLoaded");
        bool deleteOnlyLoaded = false;
        if (filterLoadedKVDB.has_value())
        {
            deleteOnlyLoaded = filterLoadedKVDB.value();
        }

        auto result = kvdbManager->deleteDB(kvdbName.value(), deleteOnlyLoaded);
        if (!result)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("DB with name [{}] doesn't exists or is in use.",
                            kvdbName.value())};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn dumpKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        auto optKvdbName = params.getString("/name");
        if (!optKvdbName)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Field [name] is missing."};
        }

        const std::string kvdbName = optKvdbName.value();
        if (kvdbName.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [name] is empty."};
        }

        std::string dbContent;
        const size_t retVal = kvdbManager->dumpContent(kvdbName, dbContent);
        if (!retVal)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "KVDB has no content"};
        }

        json::Json data;
        data.setArray("/data");

        std::istringstream iss(dbContent);
        for (std::string line; std::getline(iss, line);)
        {
            std::string jsonFill;
            auto splittedLine = utils::string::split(line, ':');
            const size_t lineMemebers = splittedLine.size();
            if (!lineMemebers || lineMemebers > 2)
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

            json::Json keyValueObject {jsonFill.c_str()};
            data.appendJson(keyValueObject);
        }

        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn getKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager =
                std::move(kvdbManager)](const json::Json& params) -> api::WazuhResponse
    {
        std::string kvdbName {};
        std::string key {};
        std::string value {};

        auto optKvdbName = params.getString("/name");

        if (!optKvdbName.has_value())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Field [name] is missing."};
        }
        kvdbName = optKvdbName.value();

        if (kvdbName.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [name] is empty."};
        }

        auto optKey = params.getString("/key");

        if (!optKey.has_value())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is missing."};
        }
        key = optKey.value();

        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is empty."};
        }

        auto retVal = kvdbManager->getKeyValue(kvdbName, key);

        if (!retVal.has_value())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Key Not found."};
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
        std::string kvdbName {};
        std::string key {};
        std::string value {};

        auto optKvdbName = params.getString("/name");

        if (!optKvdbName.has_value())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Field [name] is missing."};
        }
        kvdbName = optKvdbName.value();

        if (kvdbName.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [name] is empty."};
        }

        auto optKey = params.getString("/key");

        if (!optKey.has_value())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is missing."};
        }
        key = optKey.value();

        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is empty."};
        }

        value = params.getString("/value").value_or("");

        bool retVal = kvdbManager->writeKey(kvdbName, key, value);

        if (!retVal)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Key-value could not be written."};
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
        auto kvdbNameToMatch = params.getString("/name");
        bool filtered = false;
        if (kvdbNameToMatch.has_value() && !kvdbNameToMatch.value().empty())
        {
            filtered = true;
        }

        auto filterLoadedKVDB = params.getBool("/mustBeLoaded");
        bool listOnlyLoaded = false;
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
        std::string kvdbName {};
        std::string key {};

        auto optKvdbName = params.getString("/name");

        if (!optKvdbName.has_value())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Field [name] is missing."};
        }
        kvdbName = optKvdbName.value();

        if (kvdbName.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [name] is empty."};
        }

        auto optKey = params.getString("/key");

        if (!optKey.has_value())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is missing."};
        }
        key = optKey.value();

        if (key.empty())
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Field [key] is empty."};
        }

        bool retVal = kvdbManager->deleteKey(kvdbName, key);

        if (!retVal)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Key could not be deleted."};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

void registerAllCmds(std::shared_ptr<api::Registry> registry,
                     std::shared_ptr<KVDBManager> kvdbManager)
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
        std::throw_with_nested(std::runtime_error(
            "[api::kvdb::cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace api::kvdb::cmds
