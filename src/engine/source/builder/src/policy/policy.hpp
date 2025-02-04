#ifndef _BUILDER_POLICY_POLICY_HPP
#define _BUILDER_POLICY_POLICY_HPP

#include <builder/ipolicy.hpp>

#include <defs/idefinitions.hpp>
#include <store/istore.hpp>

#include "builders/ibuildCtx.hpp"

namespace builder::policy
{
/**
 * @brief Class representing a built policy
 *
 */
class Policy : public IPolicy
{
private:
    base::Name m_name;                       ///< Name of the policy
    std::string m_hash;                      ///< Hash of the policy
    std::unordered_set<base::Name> m_assets; ///< Assets in the policy
    base::Expression m_expression;           ///< Expression of the policy

public:
    Policy() = default;
    ~Policy() = default;

    /**
     * @brief Construct a new Policy object
     *
     * @param doc Store document with the policy data
     * @param store Store reader instance
     * @param definitionsBuilder Definitions builder
     * @param registry Registry instance
     * @param schema Schema validator instance
     * @param trace Indicates whether to enable or disable the trace
     * @param sandbox If it is set to true, it indicates a test environment and if it is set to false, it indicates a
     * production environment.
     */
    Policy(const store::Doc& doc,
           const std::shared_ptr<store::IStoreReader>& store,
           const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
           const std::shared_ptr<builders::RegistryType>& registry,
           const std::shared_ptr<schemf::IValidator>& schema,
           const bool trace = false,
           const bool sandbox = false);

    /**
     * @copydoc IPolicy::name
     */
    inline const base::Name& name() const override { return m_name; }

    /*
     * @brief Get the policy hash.
     *
     * @return std::string Hash of the policy.
     */
    inline const std::string& hash() const override { return m_hash; }

    /**
     * @copydoc IPolicy::assets
     */
    inline const std::unordered_set<base::Name>& assets() const override { return m_assets; }

    /**
     * @copydoc IPolicy::expression
     */
    inline const base::Expression& expression() const override { return m_expression; }

    /**
     * @copydoc IPolicy::getGraphivzStr
     */
    // TODO: Implement
    inline std::string getGraphivzStr() const override { throw std::runtime_error("Not implemented"); }
};
} // namespace builder::policy

#endif // _BUILDER_POLICY_POLICY_HPP
