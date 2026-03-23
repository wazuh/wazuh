#ifndef _BUILDER_BUILDERS_IBUILDCTX_HPP
#define _BUILDER_BUILDERS_IBUILDCTX_HPP

#include <memory>
#include <optional>
#include <string>

#include <builder/iallowedFields.hpp>
#include <cmstore/icmstore.hpp>
#include <defs/idefinitions.hpp>
#include <schemf/ivalidator.hpp>

#include "builders.hpp"
#include "iregistry.hpp"

namespace builder::builders
{

/**
 * @brief Control flags for the runtime.
 */
struct RunState
{
    bool trace;   ///< Whether trace messages are active.
    bool sandbox; ///< Whether test/sandbox mode is active.
    bool check;   ///< Whether hard type enforcement mode is active.
};

/**
 * @brief Context for the builder, tracks the current build scope.
 */
struct Context
{
    std::string assetName;           ///< Name of the current asset being built.
    std::string integrationName;     ///< Name of the current integration being built.
    std::string integrationCategory; ///< Category of the current integration being built.
    std::string policyName;          ///< Name of the current policy being built.
    std::string stageName;           ///< Name of the current stage being built.
    std::string opName;              ///< Name of the current operation being built.
    std::optional<std::unordered_map<std::string, bool>>
        availableKvdbs;              ///< Available KVDBs: nullopt = no validation, value = validate with this map.
    bool indexDiscardedEvents;       ///< Policy configuration: whether to index discarded events.
};

/**
 * @brief Interface for the build context shared by all builders
 *
 */
class IBuildCtx
{
public:
    virtual ~IBuildCtx() = default;
    /**
     * @brief Clone the current build context
     *
     * @return std::shared_ptr<IBuildCtx>
     */
    virtual std::shared_ptr<IBuildCtx> clone() const = 0;

    /**
     * @brief Get the definitions object
     *
     * @return const defs::IDefinitions&
     */
    virtual const defs::IDefinitions& definitions() const = 0;

    /**
     * @brief Set the Definitions object
     *
     * @param definitions
     */
    virtual void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) = 0;

    /**
     * @brief Get the registry object
     *
     * @return const RegistryType&
     */
    virtual const RegistryType& registry() const = 0;

    /**
     * @brief Set the Registry object
     *
     * @param registry
     */
    virtual void setRegistry(const std::shared_ptr<const RegistryType>& registry) = 0;

    /**
     * @brief Get the validator object
     *
     * @return const schemf::IValidator&
     */
    virtual const schemf::IValidator& validator() const = 0;

    /**
     * @brief Set the Validator object
     *
     * @param validator
     */
    virtual void setValidator(const std::shared_ptr<const schemf::IValidator>& validator) = 0;

    /**
     * @brief Get the validator pointer object
     *
     * @return std::shared_ptr<const schemf::IValidator>
     */
    virtual std::shared_ptr<const schemf::IValidator> validatorPtr() const = 0;

    /**
     * @brief Get the context object
     *
     * @return const Context&
     */
    virtual const Context& context() const = 0;

    /**
     * @brief Get the context object
     *
     * @return Context&
     */
    virtual Context& context() = 0;

    /**
     * @brief Get the run state object
     *
     * @return std::shared_ptr<const RunState>
     */
    virtual std::shared_ptr<const RunState> runState() const = 0;

    /**
     * @brief Get the allowed fields object
     *
     * @return const builder::IAllowedFields&
     */
    virtual const builder::IAllowedFields& allowedFields() const = 0;

    /**
     * @brief Get the allowed fields pointer object
     *
     * @return std::shared_ptr<const builder::IAllowedFields>
     */
    virtual std::shared_ptr<const builder::IAllowedFields> allowedFieldsPtr() const = 0;

    /**
     * @brief Set the Allowed Fields object
     *
     * @param allowedFields
     */
    virtual void setAllowedFields(const std::shared_ptr<const builder::IAllowedFields>& allowedFields) = 0;

    /**
     * @brief Get the store namespace reader object
     *
     * @return const cm::store::ICMStoreNSReader&
     */
    virtual const cm::store::ICMStoreNSReader& getStoreNSReader() const = 0;

    /**
     * @brief set the store namespace reader object
     *
     * @param nsReader
     */
    virtual void setStoreNSReader(const std::shared_ptr<cm::store::ICMStoreNSReader> nsReader) = 0;

    /**
     * @brief Get the allow missing dependencies flag
     *
     * @return true
     * @return false
     */
    virtual bool allowMissingDependencies() const = 0;

    /**
     * @brief Set the allow missing dependencies flag
     *
     * @param allow
     */
    virtual void setAllowMissingDependencies(bool allow) = 0;

    /**
     * @brief Check if a KVDB is available and enabled in the current integration context
     *
     * @param kvdbName Name of the KVDB to check
     * @return std::pair<bool, bool> First: exists, Second: is enabled (only valid if exists)
     */
    virtual std::pair<bool, bool> isKvdbAvailable(const std::string& kvdbName) const = 0;

    /**
     * @brief Get the index discarded events configuration from the policy
     *
     * @return bool True if discarded events should be indexed, false otherwise
     */
    virtual bool getIndexDiscardedEvents() const = 0 ;
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_IBUILDCTX_HPP
