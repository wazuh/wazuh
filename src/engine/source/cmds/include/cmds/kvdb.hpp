#ifndef _CMD_KVDB_HPP
#define _CMD_KVDB_HPP

#include <memory>
#include <string>

#include <CLI/CLI.hpp>

#include <base/utils/wazuhProtocol/wazuhRequest.hpp>
#include <base/utils/wazuhProtocol/wazuhResponse.hpp>
#include <json/json.hpp>

namespace cmd::kvdb
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_kvdb_api";

constexpr auto API_KVDB_CREATE_SUBCOMMAND {"create"};
constexpr auto API_KVDB_DELETE_SUBCOMMAND {"delete"};
constexpr auto API_KVDB_DUMP_SUBCOMMAND {"dump"};
constexpr auto API_KVDB_GET_SUBCOMMAND {"get"};
constexpr auto API_KVDB_INSERT_SUBCOMMAND {"insert"};
constexpr auto API_KVDB_LIST_SUBCOMMAND {"list"};
constexpr auto API_KVDB_REMOVE_SUBCOMMAND {"remove"};

std::string commandName(const std::string& command);
json::Json getParameters(const std::string& action, const std::string& name, bool loaded);
json::Json getParameters(const std::string& action, const std::string& name, const std::string& path);
json::Json getParametersKey(const std::string& action, const std::string& name, const std::string& key);
json::Json getParametersKeyValue(const std::string& action,
                                 const std::string& name,
                                 const std::string& key,
                                 const std::string& value);
json::Json getParameters(const std::string& action, const std::string& name);
void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response);
void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void runList(const std::string& socketPath, const std::string& kvdbName, bool loaded);
void runCreate(const std::string& socketPath, const std::string& kvdbName, const std::string& kvdbInputFilePath);
void runDump(const std::string& socketPath, const std::string& kvdbName);
void runDelete(const std::string& socketPath, const std::string& kvdbName);
void runGetKV(const std::string& socketPath, const std::string& kvdbName, const std::string& kvdbKey);
void runInsertKV(const std::string& socketPath,
                 const std::string& kvdbName,
                 const std::string& kvdbKey,
                 const std::string& kvdbValue);
void runRemoveKV(const std::string& socketPath, const std::string& kvdbName, const std::string& kvdbKey);

void configure(CLI::App_p app);

} // namespace cmd::kvdb

#endif // _CMD_KVDB_HPP
