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

    std::shared_ptr<store::IStoreInternal> m_store;   ///< Store instance to access policies documents
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
    Policy(std::shared_ptr<store::IStoreInternal> store, std::shared_ptr<builder::IValidator> validator)
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
};
} // namespace api::policy

#endif // _API_POLICY_POLICY_HPP
