#ifndef _API_POLICY_POLICY_HPP
#define _API_POLICY_POLICY_HPP

#include <memory>

#include <builder/ivalidator.hpp>
#include <policy/ipolicy.hpp>
#include <store/istore.hpp>

namespace api::policy
{

class Policy : public IPolicy
{
private:
    class PolicyRep; ///< PIMPL forward declaration of the PolicyRep class

    std::shared_ptr<store::IStore> m_store;   ///< Store instance to access policies documents and query assets
    std::shared_ptr<builder::IValidator> m_validator; ///< Validator instance to validate policy documents

    /**
     * @brief Read a policy document from the store
     *
     * @param policyName
     * @return base::RespOrError<PolicyRep> Policy representation or error
     */
    base::RespOrError<PolicyRep> read(const base::Name& policyName) const;

    /**
     * @brief Upsert a policy document to the store
     *
     * @param policy Policy representation
     * @return base::OptError
     */
    base::OptError upsert(PolicyRep policy);

public:
    Policy(std::shared_ptr<store::IStore> store, std::shared_ptr<builder::IValidator> validator)
        : m_store {store}
        , m_validator {validator}
    {
    }

    /**
     * @copydoc IPolicy::create
     */
    base::OptError create(const base::Name& policyName) override;

    /**
     * @copydoc IPolicy::del
     */
    base::OptError del(const base::Name& policyName) override;


    /**
     * @brief Get the policy with the given name, filtered by the given namespace in a human readable format
     *
     * @param policyName Policy name
     * @param namespaceIds Namespace ids to filter. If empty, no filter is applied
     * @return base::RespOrError<std::string>
     */
    base::RespOrError<std::string> get(const base::Name& policyName,
                                       const std::vector<store::NamespaceId>& namespaceIds) const override;
    /**
     * @copydoc IPolicy::list
     */
    base::RespOrError<std::vector<base::Name>> list() const override;

    /**
     * @copydoc IPolicy::addAsset
     */
    base::OptError
    addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) override;

    /**
     * @copydoc IPolicy::delAsset
     */
    base::OptError
    delAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) override;

    /**
     * @copydoc IPolicy::listAssets
     */
    base::RespOrError<std::list<base::Name>> listAssets(const base::Name& policyName,
                                                        const store::NamespaceId& namespaceId) const override;

    /**
     * @copydoc IPolicy::getDefaultParent
     */
    base::RespOrError<base::Name> getDefaultParent(const base::Name& policyName,
                                                   const store::NamespaceId& namespaceId) const override;

    /**
     * @copydoc IPolicy::setDefaultParent
     */
    base::OptError setDefaultParent(const base::Name& policyName,
                                    const store::NamespaceId& namespaceId,
                                    const base::Name& assetName) override;

    /**
     * @copydoc IPolicy::delDefaultParent
     */
    base::OptError delDefaultParent(const base::Name& policyName, const store::NamespaceId& namespaceId) override;

    /**
     * @copydoc IPolicy::listNamespaces
     */
    base::RespOrError<std::list<store::NamespaceId>> listNamespaces(const base::Name& policyName) const override;
};
} // namespace api::policy

#endif // _API_POLICY_POLICY_HPP
