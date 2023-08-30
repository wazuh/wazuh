#ifndef _API_POLICY_IPOLICY_HPP
#define _API_POLICY_IPOLICY_HPP

#include <list>

#include <error.hpp>
#include <name.hpp>
#include <store/namespaceId.hpp>

namespace api::policy
{

class IPolicy
{
public:
    /**
     * @brief Create a new policy with the given name
     *
     * @param policyName
     * @return base::OptError
     */
    virtual base::OptError create(const base::Name& policyName) = 0;

    /**
     * @brief Delete a policy with the given name
     *
     * @param policyName
     * @return base::OptError
     */
    virtual base::OptError del(const base::Name& policyName) = 0;

    /**
     * @brief List all policies
     *
     * @return base::RespOrError<std::list<base::Name>>
     */
    virtual base::RespOrError<std::vector<base::Name>> list() const = 0;


    /**
     * @brief Add a new asset to a policy
     *
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
     * @param policyName
     * @param namespaceId
     * @return base::RespOrError<std::list<AssetName>>
     */
    virtual base::RespOrError<std::list<base::Name>> listAssets(const base::Name& policyName,
                                                                const store::NamespaceId& namespaceId) const = 0;

    /**
     * @brief Get the namespace default parent from a policy
     *
     */
    virtual base::RespOrError<base::Name> getDefaultParent(const base::Name& policyName,
                                                           const store::NamespaceId& namespaceId) const = 0;

    /**
     * @brief Set namespace default parent from a policy
     * 
     * @param policyName
     * @param namespaceId
     */
    virtual base::OptError setDefaultParent(const base::Name& policyName, const store::NamespaceId& namespaceId,
                                            const base::Name& parentName) = 0;

};
} // namespace api::policy

#endif // _API_POLICY_IPOLICY_HPP
