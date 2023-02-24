#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{

// New commands
api::Handler managerGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerPost(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler managerDump(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);

api::Handler dbGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler dbDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);
api::Handler dbPut(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager);


void registerAllCmds(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager,
                     std::shared_ptr<api::Registry> registry);
} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
