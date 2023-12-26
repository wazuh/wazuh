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

    std::shared_ptr<const schemval::IValidator> m_schemaValidator; // Schema validator

    std::shared_ptr<const schemf::ISchema> m_schema; // Schema

public:
    BuildCtx()
    {
        m_runState = std::make_shared<RunState>();
        m_context = Context();
        m_registry = nullptr;
        m_definitions = nullptr;
        m_schemaValidator = nullptr;
    }

    ~BuildCtx() = default;

    BuildCtx(const std::shared_ptr<RunState>& runState,
             const Context& context,
             const std::shared_ptr<const RegistryType>& registry,
             const std::shared_ptr<defs::IDefinitions>& definitions,
             const std::shared_ptr<const schemval::IValidator>& schemaValidator)
        : m_runState(runState)
        , m_context(context)
        , m_registry(registry)
        , m_definitions(definitions)
        , m_schemaValidator(schemaValidator)
    {
    }

    BuildCtx(const BuildCtx&) = default;

    inline std::shared_ptr<IBuildCtx> clone() const override { return std::make_shared<BuildCtx>(*this); }

    inline const RegistryType& registry() const override { return *m_registry; }
    inline void setRegistry(const std::shared_ptr<const RegistryType>& registry) override { m_registry = registry; }

    inline const defs::IDefinitions& definitions() const override { return *m_definitions; }
    inline void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) override
    {
        m_definitions = definitions;
    }

    inline const schemval::IValidator& validator() const override { return *m_schemaValidator; }
    inline void setValidator(const std::shared_ptr<const schemval::IValidator>& validator) override
    {
        m_schemaValidator = validator;
    }

    inline const schemf::ISchema& schema() const override { return *m_schema; }
    inline std::shared_ptr<const schemf::ISchema> schemaPtr() const override { return m_schema; }
    inline void setSchema(const std::shared_ptr<const schemf::ISchema>& schema) override { m_schema = schema; }

    inline const Context& context() const override { return m_context; }
    inline Context& context() override { return m_context; }

    inline std::shared_ptr<const RunState> runState() const override { return m_runState; }
    inline RunState& runState() { return *m_runState; }
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BUILDCTX_HPP
