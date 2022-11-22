#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{

api::CommandFn createKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn deleteKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn dumpKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn getKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn insertKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn listKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);
api::CommandFn removeKvdbCmd(std::shared_ptr<KVDBManager> kvdbManager);

void registerAllCmds(std::shared_ptr<api::Registry> registry,
                     std::shared_ptr<KVDBManager> kvdbManager);
} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
