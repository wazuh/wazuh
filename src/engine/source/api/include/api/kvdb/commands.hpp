#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{

// New commands
api::CommandFn managerGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::CommandFn managerPost(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::CommandFn managerDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::CommandFn managerDump(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

api::CommandFn dbGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::CommandFn dbDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::CommandFn dbPut(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);


void registerAllCmds(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry);
} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
