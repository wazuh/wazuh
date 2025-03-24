#ifndef _BUILDER_BUILDERS_BUILDCTX_HPP
#define _BUILDER_BUILDERS_BUILDCTX_HPP

#include <string>

#include "ibuildCtx.hpp"

namespace builder::builders
{

class BuildCtx final : public IBuildCtx
{
private:
    std::shared_ptr<RunState> m_runState; // Runtime state
    Context m_context;                    // Context

    std::shared_ptr<const RegistryType> m_registry; // Builders registry

    std::shared_ptr<const defs::IDefinitions> m_definitions; // Definitions

    std::shared_ptr<const schemf::IValidator> m_schemaValidator; // Schema validator

    std::shared_ptr<const schemf::ISchema> m_schema; // Schema

    std::shared_ptr<const builder::IAllowedFields> m_allowedFields; // Allowed fields

public:
    BuildCtx()
    {
        m_runState = std::make_shared<RunState>();
        m_context = Context();
        m_registry = nullptr;
        m_definitions = nullptr;
        m_schemaValidator = nullptr;
        m_allowedFields = nullptr;
    }

    ~BuildCtx() = default;

    BuildCtx(const std::shared_ptr<RunState>& runState,
             const Context& context,
             const std::shared_ptr<const RegistryType>& registry,
             const std::shared_ptr<const defs::IDefinitions>& definitions,
             const std::shared_ptr<const schemf::IValidator>& schemaValidator,
             const std::shared_ptr<const builder::IAllowedFields>& allowedFields)
        : m_runState(runState)
        , m_context(context)
        , m_registry(registry)
        , m_definitions(definitions)
        , m_schemaValidator(schemaValidator)
        , m_allowedFields(allowedFields)
    {
    }

    BuildCtx(const BuildCtx&) = default;

    inline std::shared_ptr<IBuildCtx> clone() const override
    {
        return std::make_shared<BuildCtx>(
            m_runState, m_context, m_registry, m_definitions, m_schemaValidator, m_allowedFields);
    }

    inline const RegistryType& registry() const override { return *m_registry; }
    inline void setRegistry(const std::shared_ptr<const RegistryType>& registry) override { m_registry = registry; }

    inline const defs::IDefinitions& definitions() const override { return *m_definitions; }
    inline void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) override
    {
        m_definitions = definitions;
    }

    inline const schemf::IValidator& validator() const override { return *m_schemaValidator; }
    inline void setValidator(const std::shared_ptr<const schemf::IValidator>& validator) override
    {
        m_schemaValidator = validator;
    }
    inline std::shared_ptr<const schemf::IValidator> validatorPtr() const override { return m_schemaValidator; }

    inline const Context& context() const override { return m_context; }
    inline Context& context() override { return m_context; }

    inline std::shared_ptr<const RunState> runState() const override { return m_runState; }
    inline RunState& runState() { return *m_runState; }

    inline const builder::IAllowedFields& allowedFields() const override { return *m_allowedFields; }
    inline std::shared_ptr<const builder::IAllowedFields> allowedFieldsPtr() const override { return m_allowedFields; }
    inline void setAllowedFields(const std::shared_ptr<const builder::IAllowedFields>& allowedFields) override
    {
        m_allowedFields = allowedFields;
    }
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BUILDCTX_HPP
