#include "api/kvdb/commands.hpp"

#include <json/json.hpp>

namespace api::kvdb::cmds
{

api::CommandFn lisKvdbCmd()
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

void registerAllCmds(std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("list_kvdb", lisKvdbCmd());
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error(
            "[api::kvdb::cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace api::kvdb::cmds
