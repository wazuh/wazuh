#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{
constexpr int API_SUCCESS_CODE {0};
constexpr int API_ERROR_CODE {-1};

constexpr char KVDB_NAME_NOT_A_STRING[] {"KVDB \"name\" parameter must be a string"};
constexpr char KVDB_NAME_MISSING[] {"KVDB \"name\" parameter is missing"};
constexpr char KVDB_NAME_EMPTY[] {"KVDB \"name\" parameter cannot be empty"};

constexpr char KVDB_KEY_NOT_A_STRING[] {"KVDB \"key\" parameter must be a string"};
constexpr char KVDB_KEY_MISSING[] {"KVDB \"key\" parameter is missing"};
constexpr char KVDB_KEY_EMPTY[] {"KVDB \"key\" parameter cannot be empty"};

api::CommandFn kvdbCreateCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbDeleteCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbDumpCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbGetKeyCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbInsertKeyCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbListCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn kvdbRemoveKeyCmd(std::shared_ptr<KVDBManager> kvdbManager);

void registerAllCmds(std::shared_ptr<KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry);
} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
