#ifndef _API_POLICY_IPOLICY_HPP
#define _API_POLICY_IPOLICY_HPP

#include <list>

#include <base/error.hpp>
#include <base/name.hpp>
#include <store/namespaceId.hpp>

namespace api::policy
{

class IPolicy
{
public:
    /**
     * @brief Create a new policy with the given name
     *
     * @param policyName Policy name to create
     * @return base::OptError Error if the policy already exists or if the policy name is invalid
     */
    virtual base::OptError create(const base::Name& policyName) = 0;

    /**
     * @brief Delete a policy with the given name
     *
     * @param policyName Policy name to delete
     * @return base::OptError Error if the policy does not exist or if the policy name is invalid
     */
    virtual base::OptError del(const base::Name& policyName) = 0;

    /**
     * @brief Get the policy with the given name, filtered by the given namespace in a human readable format
     *
     * @param policyName Policy name
     * @param namespaceIds Namespace ids to filter. If empty, no filter is applied
     * @return base::RespOrError<std::string> Policy in a human readable format or an error
     */
    virtual base::RespOrError<std::string> get(const base::Name& policyName,
                                               const std::vector<store::NamespaceId>& namespaceIds) const = 0;

    /**
     * @brief List all policies
     *
     * @return base::RespOrError<std::list<base::Name>> List of policies or an error
     */
    virtual base::RespOrError<std::vector<base::Name>> list() const = 0;

    /**
     * @brief Add a new asset to a policy
     *
     * @param policyName Policy name
     * @param namespaceId Namespace of the asset
     * @param assetName Asset name
     * @return base::RespOrError<std::string> Error if cannot add the asset to the policy, warning message if validation
     * errors on the policy, empty string if success
     */
    virtual base::RespOrError<std::string>
    addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) = 0;

    /**
     * @brief Remove an asset from a policy
     *
     * @param policyName Policy name to delete the asset from
     * @param namespaceId Namespace of the asset
     * @param assetName Asset name
     * @return base::RespOrError<std::string> Error if cannot add the asset to the policy, warning message if validation
     * errors on the policy, empty string if success
     */
    virtual base::RespOrError<std::string>
    delAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) = 0;

    /**
     * @brief List assets from a policy
     *
     * @param policyName Policy name to list the assets from
     * @param namespaceId Namespace of the assets
     * @return base::RespOrError<std::list<AssetName>> List of assets or an error
     */
    virtual base::RespOrError<std::list<base::Name>> listAssets(const base::Name& policyName,
                                                                const store::NamespaceId& namespaceId) const = 0;

    /**
     * @brief Get the namespace default parent from a policy
     *
     * @param policyName Policy name to get the default parent from
     * @param namespaceId Namespace of the default parent
     * @return base::RespOrError<std::list<base::Name>> Default parents or an error
     */
    virtual base::RespOrError<std::list<base::Name>> getDefaultParent(const base::Name& policyName,
                                                                      const store::NamespaceId& namespaceId) const = 0;

    /**
     * @brief Set namespace default parent from a policy
     *
     * @param policyName Policy name to set the default parent to
     * @param namespaceId Namespace of the default parent
     * @param parentName Default parent name
     * @return base::RespOrError<std::string> Error if cannot add the asset to the policy, warning message if validation
     * errors on the policy, empty string if success
     */
    virtual base::RespOrError<std::string> setDefaultParent(const base::Name& policyName,
                                                            const store::NamespaceId& namespaceId,
                                                            const base::Name& parentName) = 0;

    /**
     * @brief Delete namespace default parent from a policy
     *
     * @param policyName Policy name to delete the default parent from
     * @param namespaceId Namespace of the default parent
     * @return base::RespOrError<std::string> Error if cannot add the asset to the policy, warning message if validation
     * errors on the policy, empty string if success
     */
    virtual base::RespOrError<std::string> delDefaultParent(const base::Name& policyName,
                                                            const store::NamespaceId& namespaceId,
                                                            const base::Name& parentName) = 0;

    /**
     * @brief Get the list of namespaces from a policy
     *
     * @param policyName Policy name to get the namespaces from
     * @return base::RespOrError<std::list<store::NamespaceId>> List of namespaces or an error
     */
    virtual base::RespOrError<std::list<store::NamespaceId>> listNamespaces(const base::Name& policyName) const = 0;

    /**
     * @brief Get the hash of a policy
     *
     * @param policyName Policy name to get the hash from
     * @return base::RespOrError<std::string> Hash of the policy or an error
     */
    virtual base::RespOrError<std::string> getHash(const base::Name& policyName) const = 0;

    /**
     * @brief Copy a existing policy to a new one
     *
     * @param policyName Policy name to copy
     * @param newPolicyName New policy name
     * @return base::OptError Error if cannot copy the policy
     */
    virtual base::OptError copy(const base::Name& policyName, const base::Name& newPolicyName) = 0;

    /**
     * @brief Delete all deleted assets from the policy, returning the deleted assets
     *
     * @param policyName Policy name to clean
     * @return base::RespOrError<std::string> Deleted assets or an error
     */
    virtual base::RespOrError<std::string> cleanDeleted(const base::Name& policyName) = 0;
};
} // namespace api::policy

#endif // _API_POLICY_IPOLICY_HPP
