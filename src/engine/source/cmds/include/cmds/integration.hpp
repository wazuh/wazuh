#ifndef _CMD_INTEGRATION_HPP
#define _CMD_INTEGRATION_HPP

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>
#include <json/json.hpp>

namespace cmd::integration
{

namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_catalog_api";
} // namespace details

void runAddTo(std::shared_ptr<apiclnt::Client> client,
              const std::string& policyName,
              const std::string& integrationName);
void removeFrom(std::shared_ptr<apiclnt::Client> client,
                const std::string& policyName,
                const std::string& integrationName);
void configure(CLI::App_p app);
} // namespace cmd::integration

#endif // _CMD_INTEGRATION_HPP
