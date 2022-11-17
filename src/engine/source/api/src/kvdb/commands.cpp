#include "api/kvdb/commands.hpp"

#include <string>

#include <json/json.hpp>

#include <utils/stringUtils.hpp>

namespace api::kvdb::cmds
{

api::CommandFn createKvdbCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse {

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

        try
        {
            bool result = KVDBManager::get().CreateAndFillKVDBfromFile(kvdbName.value(), inputFilePathValue);
            if (!result)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("DB with name [{}] already exists.",
                                kvdbName.value())};
            }
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] string parameter"};
        }

        json::Json data;
        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn deleteKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {
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
        bool listOnlyLoaded = false;
        if (filterLoadedKVDB.has_value())
        {
            listOnlyLoaded = filterLoadedKVDB.value();
        }

        try
        {
            auto result = KVDBManager::get().deleteDB(kvdbName.value(), listOnlyLoaded);
            if (!result)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("DB with name [{}] doesn't exists or is in use.", kvdbName.value())};
            }
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] string parameter"};
        }

        json::Json data;
        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn dumpKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse
        {
            std::string kvdbName {};
            try
            {
                auto optKvdbName = params.getString("/name");

                if (!optKvdbName)
                {
                    return api::WazuhResponse {
                        json::Json {"{}"}, 400, "Field \"name\" is missing."};
                }

                kvdbName = optKvdbName.value();
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the \"name\" field: ")
                        + e.what()};
            }

            if (kvdbName.empty())
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Field \"name\" is empty."};
            }

            KVDBHandle kvdbHandle {};
            try
            {
                kvdbHandle = KVDBManager::get().getDB(kvdbName, false);
            }
            catch(const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the database handle: ")
                        + e.what()};
            }

            if (nullptr == kvdbHandle)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Database could not be found."};
            }

            size_t retVal;
            std::string dbContent;
            try
            {
                retVal = kvdbHandle->dumpContent(dbContent);
            }
            catch(const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while writing the key-value: ")
                        + e.what()};
            }

            if (!retVal)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "KVDB has no content."};
            }
            json::Json data;
            data.setObject("/data");

            std::istringstream iss(dbContent);
            for (std::string line; std::getline(iss, line);)
            {
                auto splittedLine = utils::string::split(line,':');
                data.setString("/data/" + splittedLine.at(1),splittedLine.at(0));
            }

            return api::WazuhResponse {std::move(data), 200, "OK"};
        };
}

api::CommandFn getKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {
        return api::WazuhResponse {json::Json {"{}"}, 400, ""};
    };
}

api::CommandFn insertKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse
        {
            std::string kvdbName {};
            std::string key {};
            std::string value {};

            try
            {
                auto optKvdbName = params.getString("/name");

                if (!optKvdbName)
                {
                    return api::WazuhResponse {
                        json::Json {"{}"}, 400, "Field \"name\" is missing."};
                }

                kvdbName = optKvdbName.value();
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the \"name\" field: ")
                        + e.what()};
            }

            if (kvdbName.empty())
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Field \"name\" is empty."};
            }

            try
            {
                auto optKey = params.getString("/key");

                if (!optKey)
                {
                    return api::WazuhResponse {
                        json::Json {"{}"}, 400, "Field \"key\" is missing."};
                }

                key = optKey.value();
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the \"key\" field: ")
                        + e.what()};
            }

            if (key.empty())
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Field \"key\" is empty."};
            }

            try
            {
                auto optValue = params.getString("/value");
                if (!optValue)
                {
                    return api::WazuhResponse {
                        json::Json {"{}"}, 400, "Field \"value\" is missing."};
                }

                // TODO: is it allowed to have an empty value?
                value = optValue.value();
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the \"value\" field: ")
                        + e.what()};
            }

            KVDBHandle kvdbHandle {};
            try
            {
                kvdbHandle = KVDBManager::get().getDB(kvdbName, false);
            }
            catch(const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while obtaining the database handle: ")
                        + e.what()};
            }

            if (nullptr == kvdbHandle)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Database could not be found."};
            }

            bool retVal {false};

            try
            {
                retVal = kvdbHandle->write(key, value);
            }
            catch(const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    std::string("An error ocurred while writing the key-value: ")
                        + e.what()};
            }

            if (!retVal)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Key-value could not be written."};
            }

            return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
        };
}

api::CommandFn listKvdbCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse {

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

        auto kvdbLists = KVDBManager::get().getAvailableKVDBs(listOnlyLoaded);
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

api::CommandFn removeKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {
        return api::WazuhResponse {json::Json {"{}"}, 400, ""};
    };
}

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("create_kvdb", createKvdbCmd());
        registry->registerCommand("delete_kvdb", deleteKvdbCmd());
        registry->registerCommand("dump_kvdb", dumpKvdbCmd());
        registry->registerCommand("get_kvdb", getKvdbCmd());
        registry->registerCommand("insert_kvdb", insertKvdbCmd());
        registry->registerCommand("list_kvdb", listKvdbCmd());
        registry->registerCommand("remove_kvdb", removeKvdbCmd());
    }
    catch (const std::exception& e)
    {
        std::throw_with_nested(std::runtime_error(
            "[api::kvdb::cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace api::kvdb::cmds
