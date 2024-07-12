#ifndef _API_POLICY_POLICY_HPP
#define _API_POLICY_POLICY_HPP

#include <memory>

#include <api/policy/ipolicy.hpp>
#include <builder/ivalidator.hpp>
#include <store/istore.hpp>

namespace api::policy
{

class Policy : public IPolicy
{
private:
    class PolicyRep; ///< PIMPL forward declaration of the PolicyRep class

    std::shared_ptr<store::IStore> m_store;           ///< Store instance to access policies documents and query assets
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
     * @param ignoreValidation Ignore validation errors
     * @return base::RespOrError<std::string>
     */
    base::RespOrError<std::string> upsert(const PolicyRep& policy, bool ignoreValidation = false);

public:
    Policy(std::shared_ptr<store::IStore> store, std::shared_ptr<builder::IValidator> validator)
        : m_store {store}
        , m_validator {validator}
    {
        if (!m_store)
        {
            throw std::runtime_error("Policy API got null store instance");
        }

        if (!m_validator)
        {
            throw std::runtime_error("Policy API got null validator instance");
        }
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
    base::RespOrError<std::string>
    addAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) override;

    /**
     * @copydoc IPolicy::delAsset
     */
    base::RespOrError<std::string>
    delAsset(const base::Name& policyName, const store::NamespaceId& namespaceId, const base::Name& assetName) override;

    /**
     * @copydoc IPolicy::listAssets
     */
    base::RespOrError<std::list<base::Name>> listAssets(const base::Name& policyName,
                                                        const store::NamespaceId& namespaceId) const override;

    /**
     * @copydoc IPolicy::getDefaultParent
     */
    base::RespOrError<std::list<base::Name>> getDefaultParent(const base::Name& policyName,
                                                              const store::NamespaceId& namespaceId) const override;

    /**
     * @copydoc IPolicy::setDefaultParent
     */
    base::RespOrError<std::string> setDefaultParent(const base::Name& policyName,
                                                    const store::NamespaceId& namespaceId,
                                                    const base::Name& parentName) override;

    /**
     * @copydoc IPolicy::delDefaultParent
     */
    base::RespOrError<std::string> delDefaultParent(const base::Name& policyName,
                                                    const store::NamespaceId& namespaceId,
                                                    const base::Name& parentName) override;

    /**
     * @copydoc IPolicy::listNamespaces
     */
    base::RespOrError<std::list<store::NamespaceId>> listNamespaces(const base::Name& policyName) const override;

    /**
     * @copydoc IPolicy::getHash
     */
    base::RespOrError<std::string> getHash(const base::Name& policyName) const override;

    /**
     * @copydoc IPolicy::copy
     */
    base::OptError copy(const base::Name& policyName, const base::Name& newPolicyName) override;

    /**
     * @copydoc IPolicy::cleanDeleted
     */
    base::RespOrError<std::string> cleanDeleted(const base::Name& policyName) override;
};
} // namespace api::policy

#endif // _API_POLICY_POLICY_HPP
