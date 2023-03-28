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
constexpr auto ORIGIN_NAME = "engine_integrated_catalog_api"; ///< Origin name for the API
} // namespace details

/**
 * @brief Callback for the "integration.policy/add_to" command
 *
 * @param client Client to use
 * @param policyName Name of the policy to add the integration to
 * @param integrationName Name of the integration to add to the policy
 *
 * @throw std::runtime_error If the command fails for any reason
 */
void runAddTo(std::shared_ptr<apiclnt::Client> client,
              const std::string& policyName,
              const std::string& integrationName);

/**
 * @brief Callback for the "integration.policy/remove_from" command
 *
 * @param client Client to use
 * @param policyName Name of the policy to remove the integration from
 * @param integrationName Name of the integration to remove from the policy
 *
 * @throw std::runtime_error If the command fails for any reason
 */
void removeFrom(std::shared_ptr<apiclnt::Client> client,
                const std::string& policyName,
                const std::string& integrationName);

/**
 * @brief Configure the CLI for the integration command
 *
 * @param app CLI to configure
 */
void configure(CLI::App_p app);
} // namespace cmd::integration

#endif // _CMD_INTEGRATION_HPP
