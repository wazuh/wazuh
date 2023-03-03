#ifndef _CMD_ROUTER_HPP
#define _CMD_ROUTER_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

namespace cmd::router
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_router_api";
} // namespace details

void runGet(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr);
void runAdd(std::shared_ptr<apiclnt::Client> client,
            const std::string& nameStr,
            int priority,
            const std::string& filterName,
            const std::string& environment);
void runDelete(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr);
void runUpdate(std::shared_ptr<apiclnt::Client> client, const std::string& nameStr, int priority);
void runIngest(std::shared_ptr<apiclnt::Client> client, const std::string& event);

void configure(CLI::App_p app);
} // namespace cmd::router

#endif // _CMD_ROUTER_HPP
