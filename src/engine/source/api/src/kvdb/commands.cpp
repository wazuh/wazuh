#include "api/kvdb/commands.hpp"

#include <json/json.hpp>

namespace api::kvdb::cmds
{

api::CommandFn listKvdbCmd()
{
    return [](const json::Json& params) -> api::WazuhResponse
    {
        auto kvdbLists = KVDBManager::get().getAvailableKVDBs();
        json::Json data;
        data.setArray("/data");
        if (kvdbLists.size())
        {
            for (const auto & dbName : kvdbLists)
            {
                data.appendString(dbName);
            }   
        }

        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

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

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("list_kvdb", listKvdbCmd());
        registry->registerCommand("create_kvdb", createKvdbCmd());
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error(
            "[api::kvdb::cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace api::kvdb::cmds
