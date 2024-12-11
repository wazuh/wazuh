#ifndef _API_POLICY_HANDLERS_HPP
#define _API_POLICY_HANDLERS_HPP

#include <api/api.hpp>
#include <api/policy/ipolicy.hpp>

namespace api::policy::handlers
{
/* Store of policy handlers */
api::HandlerSync storePost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync storeDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync storeGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Specific policy handlers */
api::HandlerSync policyAssetPost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync policyAssetDelete(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync policyAssetGet(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync policyCleanDeleted(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Default parent policy handlers */
api::HandlerSync policyDefaultParentGet(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync policyDefaultParentPost(const std::shared_ptr<policy::IPolicy>& policyManager);
api::HandlerSync policyDefaultParentDelete(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Policy manager handlers */
api::HandlerSync policiesGet(const std::shared_ptr<policy::IPolicy>& policyManager);

/* Policy namespaces handlers */
api::HandlerSync policyNamespacesGet(const std::shared_ptr<policy::IPolicy>& policyManager);

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
