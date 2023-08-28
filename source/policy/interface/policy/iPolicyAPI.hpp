#ifndef _POLICY_IPOLICYAPI_HPP
#define _POLICY_IPOLICYAPI_HPP

#include <error.hpp>
#include <name.hpp>
#include <store/namespaceId.hpp>

namespace policy {

// TODO Should be base::Name or a new tipe with base name a and check valid name
using PolicyName = base::Name;
using AssetName = base::Name;

class IPolicyAPI {

    public:

    /**
     * @brief Create a new policy with the given name
     *
     * Create a empty policy with the given name.
     * @param policyName The name of the policy
     * @return base::OptError
     */
    virtual base::OptError create(PolicyName policyName) = 0;

    /**
     * @brief Delete a policy with the given name
     *
     * Delete a policy with the given name.
     * @param policyName The name of the policy
     * @return base::OptError
     */
    virtual base::OptError remove(PolicyName policyName) = 0;

    /**
     * @brief Add a new asset to a policy
     *
     * Add a new asset to a policy.
     * @param policyName The name of the policy
     * @param namespaceId The namespaceId of the asset (TODO Its necessary?)
     * @param assetName The name of the asset
     * @return base::OptError
     */
    virtual base::OptError addAsset(PolicyName policyName, store::NamespaceId namespaceId, AssetName assetName) = 0;

    /**
     * @brief Remove an asset from a policy
     *
     * Remove an asset from a policy.
     * @param policyName The name of the policy
     * @param assetName The name of the asset
     * @return base::OptError
     */
    virtual base::OptError removeAsset(PolicyName policyName, AssetName assetName) = 0;


    /**
     * @brief List assets from a policy
     *
     * List assets from a policy.
     * @param policyName The name of the policy
     * @param namespaceId The namespaceId of the asset
     * @return base::RespOrError<std::list<AssetName>>
     */
    virtual base::RespOrError<std::list<AssetName>> listAssets(PolicyName policyName, store::NamespaceId namespaceId) = 0;

    /**
     * @brief Load a policy from a json
     *
     * TODO: Check if is necessary to load a policy from a json
     * @param policyName The name of the policy
     * @param json The json to load
     * @return base::OptError
     */
    virtual base::OptError load(json::Json json) = 0;

    /**
     * @brief Dump a policy to a json
     *
     * TODO: Check if is necessary to dump a policy to a json
     * @param policyName The name of the policy
     * @return base::RespOrError<json::Json>
     */
    virtual base::RespOrError<json::Json> dump(PolicyName policyName) = 0;


}
} // namespace policy

#endif // _POLICY_IPOLICYAPI_HPP
