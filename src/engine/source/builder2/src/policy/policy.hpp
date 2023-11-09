#ifndef _BUILDER2_POLICY_HPP
#define _BUILDER2_POLICY_HPP

#include <builder/ipolicy.hpp>

#include <memory>
#include <unordered_map>

#include <fmt/format.h>

#include <store/istore.hpp>

namespace builder::policy
{
class Policy : public IPolicy
{
private:
    base::Name m_name;                                                   ///< Name of the policy
    std::string m_hash;                                                  ///< Hash of the policy
    std::unordered_map<store::NamespaceId, base::Name> m_defaultParents; ///< Default parents of decoders by namespace
    std::unordered_map<store::NamespaceId, std::unordered_set<base::Name>>
        m_assets; ///< Assets of the policy by namespace

    /**
     * @brief Read the policy data from the policy document and store it in the class.
     *
     * @param doc The policy document.
     * @param store The store interface to query asset namespace.
     */
    void readData(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store);

public:
    Policy() = default;

    Policy(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store);

    /**
     * @copydoc IPolicy::name
     */
    inline base::Name name() const override { return m_name; }

    /**
     * @copydoc IPolicy::assets
     */
    std::unordered_set<base::Name> assets() const override;

    /**
     * @copydoc IPolicy::expression
     */
    base::Expression expression() const override;

    /**
     * @copydoc IPolicy::getGraphivzStr
     */
    std::string getGraphivzStr() const override;

    /*
     * @brief Get the policy hash.
     *
     * @return std::string Hash of the policy.
     */
    const std::string& hash() const override;
};
} // namespace builder::policy

#endif // _BUILDER2_POLICY_HPP
