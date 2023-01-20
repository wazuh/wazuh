#ifndef _CMD_ENV_HPP
#define _CMD_ENV_HPP

#include <string>

#include <CLI/CLI.hpp>

#include <api/wazuhRequest.hpp>
#include <api/wazuhResponse.hpp>
#include <json/json.hpp>

namespace cmd::env
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_env_api";
std::string commandName(const std::string& command);
json::Json getParameters(const std::string& action, const std::string& target = "");
void processResponse(const api::WazuhResponse& response);
void singleRequest(const api::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void runSet(const std::string& socketPath, const std::string& target);
void runGet(const std::string& socketPath);
void runDel(const std::string& socketPath, const std::string& target);

void configure(CLI::App& app);
} // namespace cmd::env

#endif // _CMD_ENV_HPP
