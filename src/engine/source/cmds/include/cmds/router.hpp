#ifndef _CMD_ROUTER_HPP
#define _CMD_ROUTER_HPP

#include <string>

#include <CLI/CLI.hpp>

#include <base/utils/wazuhProtocol/wazuhRequest.hpp>
#include <base/utils/wazuhProtocol/wazuhResponse.hpp>
#include <json/json.hpp>

namespace cmd::router
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_router_api";
constexpr auto ROUTER_COMMAND = "router";
json::Json getParameters(const std::string& action,
                         const std::string& name = "",
                         int priority = -1,
                         const std::string& filterName = "",
                         const std::string& environment = "");
json::Json getIngestParameters(const std::string& action, const std::string& event);
void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response);
void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void runGet(const std::string& socketPath, const std::string& nameStr);
void runAdd(const std::string& socketPath, const std::string& nameStr, int priority, const std::string& environment);
void runDelete(const std::string& socketPath, const std::string& nameStr);
void runUpdate(const std::string& socketPath, const std::string& nameStr, int priority);
void runIngest(const std::string& socketPath, const std::string& event);

void configure(CLI::App_p app);
} // namespace cmd::router

#endif // _CMD_ROUTER_HPP
