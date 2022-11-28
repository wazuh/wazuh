#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{
constexpr char KVDB_NAME_NOT_A_STRING[] {"KVDB \"name\" parameter must be a string"};
constexpr char KVDB_NAME_MISSING[] {"KVDB \"name\" parameter is missing"};
constexpr char KVDB_NAME_EMPTY[] {"KVDB \"name\" parameter cannot be empty"};

constexpr char KVDB_KEY_NOT_A_STRING[] {"KVDB \"key\" parameter must be a string"};
constexpr char KVDB_KEY_MISSING[] {"KVDB \"key\" parameter is missing"};
constexpr char KVDB_KEY_EMPTY[] {"KVDB \"key\" parameter cannot be empty"};

api::CommandFn createKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn deleteKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn dumpKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn getKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn insertKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn listKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn removeKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);

void registerAllCmds(std::shared_ptr<KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry);
} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
