#ifndef _BUILDER_BUILDERS_IBUILDCTX_HPP
#define _BUILDER_BUILDERS_IBUILDCTX_HPP

#include <memory>
#include <string>

#include <builder/iallowedFields.hpp>
#include <defs/idefinitions.hpp>
#include <schemf/ivalidator.hpp>

#include "builders.hpp"
#include "iregistry.hpp"

namespace builder::builders
{

/**
 * @brief Control flags for the runtime
 *
 */
struct RunState
{
    bool trace;   // Active/Inactive trace messages
    bool sandbox; // Active/Inactive test mode
    bool check;   // Active/Inactive hard type enforcement mode
};

/**
 * @brief Context for the builder
 *
 */
struct Context
{
    std::string assetName;  // Name of the current asset being built
    std::string policyName; // Name of the current policy being built
    std::string stageName;  // Name of the current stage being built
    std::string opName;     // Name of the current operation being built
};

class IBuildCtx
{
public:
    virtual ~IBuildCtx() = default;
    virtual std::shared_ptr<IBuildCtx> clone() const = 0;

    virtual const defs::IDefinitions& definitions() const = 0;
    virtual void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) = 0;

    virtual const RegistryType& registry() const = 0;
    virtual void setRegistry(const std::shared_ptr<const RegistryType>& registry) = 0;

    virtual const schemf::IValidator& validator() const = 0;
    virtual void setValidator(const std::shared_ptr<const schemf::IValidator>& validator) = 0;
    virtual std::shared_ptr<const schemf::IValidator> validatorPtr() const = 0;

    virtual const Context& context() const = 0;
    virtual Context& context() = 0;

    virtual std::shared_ptr<const RunState> runState() const = 0;

    virtual const builder::IAllowedFields& allowedFields() const = 0;
    virtual std::shared_ptr<const builder::IAllowedFields> allowedFieldsPtr() const = 0;
    virtual void setAllowedFields(const std::shared_ptr<const builder::IAllowedFields>& allowedFields) = 0;
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_IBUILDCTX_HPP
