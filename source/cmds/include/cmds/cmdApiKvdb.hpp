#ifndef _CMD_API_KVDB_HPP
#define _CMD_API_KVDB_HPP

#include <string>

namespace cmd
{

void kvdb(const std::string& kvdbPath,
          const std::string& kvdbName,
          const std::string& socketPath,
          const std::string& action);
} // namespace cmd

#endif // _CMD_API_KVDB_HPP
