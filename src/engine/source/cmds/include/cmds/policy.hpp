#ifndef _CMD_POLICY_HPP
#define _CMD_POLICY_HPP

#include <string>

#include <CLI/CLI.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <cmds/apiclnt/client.hpp>
#include <base/json.hpp>

namespace cmd::policy
{
namespace details
{
constexpr auto ORIGIN_NAME = "engine_integrated_policy_api";
} // namespace details

void runAddPolicy(std::shared_ptr<apiclnt::Client> client, const std::string& policyName);
void runRemovePolicy(std::shared_ptr<apiclnt::Client> client, const std::string& policyName);
void runGetPolicy(std::shared_ptr<apiclnt::Client> client,
                  const std::string& policyName,
                  std::vector<std::string> namespaceIds);
void runListPolicies(std::shared_ptr<apiclnt::Client> client);

void runAddAsset(std::shared_ptr<apiclnt::Client> client,
                 const std::string& policyName,
                 const std::string& namespaceId,
                 const std::string& assetName);
void runRemoveAsset(std::shared_ptr<apiclnt::Client> client,
                    const std::string& policyName,
                    const std::string& namespaceId,
                    const std::string& assetName);
void runListAssets(std::shared_ptr<apiclnt::Client> client,
                   const std::string& policyName,
                   const std::string& namespaceId);
void runCleanDeletedAssets(std::shared_ptr<apiclnt::Client> client, const std::string& policyName);

void runGetDefaultParent(std::shared_ptr<apiclnt::Client> client,
                         const std::string& policyName,
                         const std::string& namespaceId);
void runSetDefaultParent(std::shared_ptr<apiclnt::Client> client,
                         const std::string& policyName,
                         const std::string& namespaceId,
                         const std::string& parentAssetName);
void runRemoveDefaultParent(std::shared_ptr<apiclnt::Client> client,
                            const std::string& policyName,
                            const std::string& namespaceId,
                            const std::string& parentAssetName);

void configure(CLI::App_p app);
} // namespace cmd::policy
#endif // _CMD_POLICY_HPP
