#ifndef _CMD_CONFIG_HPP
#define _CMD_CONFIG_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include <base/utils/wazuhProtocol/wazuhRequest.hpp>
#include <base/utils/wazuhProtocol/wazuhResponse.hpp>
#include <json/json.hpp>

namespace cmd::config
{
namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_config_api";
void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response);
void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void runGet(const std::string& socketPath, const std::string& nameStr = "");
void runSave(const std::string& socketPath, const std::string& pathStr = "");
void runPut(const std::string& socketPath, const std::string& nameStr, const std::string& valueStr);

void configure(CLI::App_p app);
} // namespace cmd::config

#endif // _CMD_CONFIG_HPP
