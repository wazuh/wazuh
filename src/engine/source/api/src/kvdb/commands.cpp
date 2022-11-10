#include "api/kvdb/commands.hpp"

#include <json/json.hpp>

namespace api::kvdb::cmds
{

api::CommandFn createKvdbCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse {
        // get json params
        auto kvdbName = params.getString("/name");
        if (!kvdbName || !kvdbName.has_value() || kvdbName.value().empty())
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] or empty string parameter"};
        }

        try
        {
            auto kvdbHandle = KVDBManager::get().addDb(kvdbName.value());
            if (kvdbHandle == nullptr)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("DB with name [{}] already exists.", kvdbName.value())};
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
    return [](const json::Json& params) -> api::WazuhResponse {};
}

api::CommandFn dumpKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {};
}

api::CommandFn getKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {};
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
                kvdbHandle = KVDBManager::get().getDB(kvdbName);
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
        auto kvdbLists = KVDBManager::get().getAvailableKVDBs();
        json::Json data;
        data.setArray("/data");
        if (kvdbLists.size())
        {
            for (const auto& dbName : kvdbLists)
            {
                data.appendString(dbName);
            }
        }

        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn removeKvdbCmd(void)
{
    return [](const json::Json& params) -> api::WazuhResponse {};
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
