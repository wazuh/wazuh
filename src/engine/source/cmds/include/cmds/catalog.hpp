#ifndef _CMD_CATALOG_HPP
#define _CMD_CATALOG_HPP

#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include <base/utils/wazuhProtocol/wazuhRequest.hpp>
#include <base/utils/wazuhProtocol/wazuhResponse.hpp>
#include <json/json.hpp>

namespace cmd::catalog
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_catalog_api";
std::string commandName(const std::string& command);
json::Json getParameters(const std::string& format, const std::string& name, const std::string& content = "");
void processResponse(const base::utils::wazuhProtocol::WazuhResponse& response);
void singleRequest(const base::utils::wazuhProtocol::WazuhRequest& request, const std::string& socketPath);
} // namespace details

void runGet(const std::string& socketPath, const std::string& format, const std::string& nameStr);

void runUpdate(const std::string& socketPath,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content);

void runCreate(const std::string& socketPath,
               const std::string& format,
               const std::string& nameStr,
               const std::string& content);

void runDelete(const std::string& socketPath, const std::string& nameStr);

void runValidate(const std::string& socketPath,
                 const std::string& format,
                 const std::string& nameStr,
                 const std::string& content);

void runLoad(const std::string& socketPath,
             const std::string& format,
             const std::string& nameStr,
             const std::string& path,
             bool recursive);

void configure(CLI::App_p app);
} // namespace cmd::catalog

#endif // _CMD_CATALOG_HPP
