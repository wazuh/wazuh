#ifndef _KVDB_COMMANDS_HPP
#define _KVDB_COMMANDS_HPP

#include <memory>

#include <kvdb/kvdbManager.hpp>

#include "api/registry.hpp"

namespace api::kvdb::cmds
{

api::CommandFn lisKvdbCmd();

void registerAllCmds(std::shared_ptr<api::Registry> registry);

} // namespace api::kvdb::cmds

#endif // _KVDB_COMMANDS_HPP
