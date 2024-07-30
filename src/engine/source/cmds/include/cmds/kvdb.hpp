#ifndef _CMD_KVDB_HPP
#define _CMD_KVDB_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace cmd::kvdb
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_kvdb_api";

/* KVDB api command (endpoints) */
constexpr auto API_KVDB_CREATE_SUBCOMMAND {"create"};
constexpr auto API_KVDB_DELETE_SUBCOMMAND {"delete"};
constexpr auto API_KVDB_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_KVDB_GET_SUBCOMMAND {"get"};
constexpr auto API_KVDB_INSERT_SUBCOMMAND {"insert"};
constexpr auto API_KVDB_LIST_SUBCOMMAND {"list"};
constexpr auto API_KVDB_REMOVE_SUBCOMMAND {"remove"};
constexpr auto API_KVDB_SEARCH_SUBCOMMAND {"search"};

} // namespace details

void runList(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, bool loaded);
void runCreate(std::shared_ptr<apiclnt::Client> client,
               const std::string& kvdbName,
               const std::string& kvdbInputFilePath);
void runDump(std::shared_ptr<apiclnt::Client> client,
             const std::string& kvdbName,
             const unsigned int page,
             const unsigned int records);
void runDelete(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName);
void runGetKV(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, const std::string& kvdbKey);
void runInsertKV(std::shared_ptr<apiclnt::Client> client,
                 const std::string& kvdbName,
                 const std::string& kvdbKey,
                 const std::string& kvdbValue);
void runRemoveKV(std::shared_ptr<apiclnt::Client> client, const std::string& kvdbName, const std::string& kvdbKey);
void runSearch(std::shared_ptr<apiclnt::Client> client,
               const std::string& kvdbName,
               const std::string& prefix,
               const unsigned int page,
               const unsigned int records);
void configure(const CLI::App_p& app);

} // namespace cmd::kvdb

#endif // _CMD_KVDB_HPP
