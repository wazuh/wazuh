#ifndef _CMD_CONFIG_HPP
#define _CMD_CONFIG_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>


namespace cmd::config
{
namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_config_api";
} // namespace details

void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr = "");
void runSave(std::shared_ptr<apiclnt::Client> client, const std::string& pathStr = "");
void runPut(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, const std::string& valueStr);

void configure(CLI::App_p app);
} // namespace cmd::config

#endif // _CMD_CONFIG_HPP
