#include "api/kvdb/commands.hpp"

#include <json/json.hpp>

namespace api::kvdb::cmds
{

// TODO: change position of createKvdbCmd and listKvdbCmd to keep the functions alphabetycally ordered
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

api::CommandFn deleteKvdbCmd(void)
{

}
api::CommandFn dumpKvdbCmd(void)
{

}
api::CommandFn getKvdbCmd(void)
{

}
api::CommandFn insertKvdbCmd(void)
{

}

// TODO: change position of createKvdbCmd and listKvdbCmd to keep the functions alphabetycally ordered
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

api::CommandFn removeKvdbCmd(void)
{

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
