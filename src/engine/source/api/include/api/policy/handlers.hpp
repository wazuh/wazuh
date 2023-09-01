#ifndef _API_POLICY_HANDLERS_HPP
#define _API_POLICY_HANDLERS_HPP

#include <api/api.hpp>
#include <policy/ipolicy.hpp>

namespace api::policy::handlers
{
/* Store of policy handlers */
api::Handler storePost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler storeGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Specific policy handlers */
api::Handler policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Default parent policy handlers */
api::Handler policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::Handler policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Policy manager handlers */
api::Handler policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/**
 * @brief Register all policy commands
 *
 * @param policy Policy to use for commands
 * @param api API to register the handlers
 * @throw std::runtime_error if the policy is not initialized
 */
void registerHandlers(const std::shared_ptr<policy::IPolicy>& policy, std::shared_ptr<api::Api> api);
} // namespace api::policy::handlers

#endif /* _API_POLICY_HANDLERS_HPP */
