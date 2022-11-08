#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{

api::CommandFn createKvdbCmd();
api::CommandFn deleteKvdbCmd();
api::CommandFn dumpKvdbCmd();
api::CommandFn getKvdbCmd();
api::CommandFn insertKvdbCmd();
api::CommandFn listKvdbCmd();
api::CommandFn removeKvdbCmd();

void registerAllCmds(std::shared_ptr<api::Registry> registry);

} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
