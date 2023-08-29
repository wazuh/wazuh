#ifndef _API_POLICY_IPOLICY_HPP
#define _API_POLICY_IPOLICY_HPP

#include <list>

#include <error.hpp>
#include <name.hpp>
#include <store/namespaceId.hpp>

namespace api::policy
{

// TODO: add setters and getters for default parent
class IPolicy
{
public:
    /**
     * @brief Create a new policy with the given name
     *
     * Create a empty policy with the given name.
     * @param policyName
     * @return base::OptError
     */
    virtual base::OptError create(const base::Name& policyName) = 0;

    /**
     * @brief Delete a policy with the given name
     *
     * Delete a policy with the given name.
     * @param policyName
     * @return base::OptError
     */
    virtual base::OptError del(const base::Name& policyName) = 0;

    /**
     * @brief Add a new asset to a policy
     *
     * Add a new asset to a policy.
     * @param policyName
     * @param namespaceId
     * @param assetName
     * @return base::OptError
     */
    virtual base::OptError
    addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) = 0;

    /**
     * @brief Remove an asset from a policy
     *
     * Remove an asset from a policy.
     * @param policyName
     * @param namespaceId
     * @param assetName
     * @return base::OptError
     */
    virtual base::OptError
    delAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) = 0;

    /**
     * @brief List assets from a policy
     *
     * List assets from a policy.
     * @param policyName
     * @param namespaceId
     * @return base::RespOrError<std::list<AssetName>>
     */
    virtual base::RespOrError<std::list<base::Name>> listAssets(const base::Name& policyName,
                                                                const store::NamespaceId& namespaceId) const = 0;
};
} // namespace api::policy

#endif // _API_POLICY_IPOLICY_HPP
