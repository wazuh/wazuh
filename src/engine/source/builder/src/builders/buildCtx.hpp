#ifndef _BUILDER_BUILDERS_BUILDCTX_HPP
#define _BUILDER_BUILDERS_BUILDCTX_HPP

#include <string>

#include "ibuildCtx.hpp"

namespace builder::builders
{

class BuildCtx final : public IBuildCtx
{
private:
    std::shared_ptr<RunState> m_runState; ///< Runtime state
    Context m_context;                    ///< Context

    std::shared_ptr<const RegistryType> m_registry; ///< Builders registry

    std::shared_ptr<const defs::IDefinitions> m_definitions; ///< Definitions

    std::shared_ptr<const schemf::IValidator> m_schemaValidator; ///< Schema validator

    std::shared_ptr<const schemf::ISchema> m_schema; ///< Schema

    std::shared_ptr<const builder::IAllowedFields> m_allowedFields; ///< Allowed fields

    std::shared_ptr<cm::store::ICMStoreNSReader> m_storeNSReader; ///< Store namespace reader

    bool m_allowMissingDependencies {false}; ///< Allow missing dependencies flag

public:
    BuildCtx()
    {
        m_runState = std::make_shared<RunState>();
        m_context = Context();
        m_registry = nullptr;
        m_definitions = nullptr;
        m_schemaValidator = nullptr;
        m_allowedFields = nullptr;
        m_storeNSReader = nullptr;
        m_allowMissingDependencies = false;
        m_context.availableKvdbs = std::nullopt;
        m_context.indexDiscardedEvents = false;
    }

    ~BuildCtx() = default;

    /**
     * @brief Construct a new Build Ctx object
     *
     * @param runState Runtime state
     * @param context Context
     * @param registry Builders registry
     * @param definitions Definitions
     * @param schemaValidator Schema validator
     * @param allowedFields Allowed fields
     */
    BuildCtx(const std::shared_ptr<RunState>& runState,
             const Context& context,
             const std::shared_ptr<const RegistryType>& registry,
             const std::shared_ptr<const defs::IDefinitions>& definitions,
             const std::shared_ptr<const schemf::IValidator>& schemaValidator,
             const std::shared_ptr<const builder::IAllowedFields>& allowedFields,
             const std::shared_ptr<cm::store::ICMStoreNSReader>& storeNSReader,
             bool allowMissingDependencies)
        : m_runState(runState)
        , m_context(context)
        , m_registry(registry)
        , m_definitions(definitions)
        , m_schemaValidator(schemaValidator)
        , m_allowedFields(allowedFields)
        , m_storeNSReader(storeNSReader)
        , m_allowMissingDependencies(allowMissingDependencies)
    {
    }

    BuildCtx(const BuildCtx&) = default;

    /**
     * @copydoc IBuildCtx::clone
     */
    inline std::shared_ptr<IBuildCtx> clone() const override
    {
        return std::make_shared<BuildCtx>(m_runState,
                                          m_context,
                                          m_registry,
                                          m_definitions,
                                          m_schemaValidator,
                                          m_allowedFields,
                                          m_storeNSReader,
                                          m_allowMissingDependencies);
    }

    /**
     * @copydoc IBuildCtx::registry
     */
    inline const RegistryType& registry() const override { return *m_registry; }

    /**
     * @copydoc IBuildCtx::setRegistry
     */
    inline void setRegistry(const std::shared_ptr<const RegistryType>& registry) override { m_registry = registry; }

    /**
     * @copydoc IBuildCtx::definitions
     */
    inline const defs::IDefinitions& definitions() const override { return *m_definitions; }

    /**
     * @copydoc IBuildCtx::setDefinitions
     */
    inline void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) override
    {
        m_definitions = definitions;
    }

    /**
     * @copydoc IBuildCtx::validator
     */
    inline const schemf::IValidator& validator() const override { return *m_schemaValidator; }

    /**
     * @copydoc IBuildCtx::setValidator
     */
    inline void setValidator(const std::shared_ptr<const schemf::IValidator>& validator) override
    {
        m_schemaValidator = validator;
    }

    /**
     * @copydoc IBuildCtx::validatorPtr
     */
    inline std::shared_ptr<const schemf::IValidator> validatorPtr() const override { return m_schemaValidator; }

    /**
     * @copydoc IBuildCtx::context
     */
    inline const Context& context() const override { return m_context; }

    /**
     * @copydoc IBuildCtx::context
     */
    inline Context& context() override { return m_context; }

    /**
     * @copydoc IBuildCtx::runState
     */
    inline std::shared_ptr<const RunState> runState() const override { return m_runState; }

    /**
     * @copydoc IBuildCtx::runState
     */
    inline RunState& runState() { return *m_runState; }

    /**
     * @copydoc IBuildCtx::allowedFields
     */
    inline const builder::IAllowedFields& allowedFields() const override { return *m_allowedFields; }

    /**
     * @copydoc IBuildCtx::allowedFieldsPtr
     */
    inline std::shared_ptr<const builder::IAllowedFields> allowedFieldsPtr() const override { return m_allowedFields; }

    /**
     * @copydoc IBuildCtx::setAllowedFields
     */
    inline void setAllowedFields(const std::shared_ptr<const builder::IAllowedFields>& allowedFields) override
    {
        m_allowedFields = allowedFields;
    }

    /**
     * @copydoc IBuildCtx::getStoreNSReader
     */
    inline const cm::store::ICMStoreNSReader& getStoreNSReader() const override
    {
        if (!m_storeNSReader)
        {
            throw std::runtime_error("Store namespace reader not set in build context");
        }
        return *m_storeNSReader;
    }

    /**
     * @copydoc IBuildCtx::setStoreNSReader
     */
    inline void setStoreNSReader(std::shared_ptr<cm::store::ICMStoreNSReader> nsReader) override
    {
        m_storeNSReader = std::move(nsReader);
    }

    /**
     * @copydoc IBuildCtx::allowMissingDependencies
     */
    inline bool allowMissingDependencies() const override { return m_allowMissingDependencies; }

    /**
     * @copydoc IBuildCtx::setAllowMissingDependencies
     */
    inline void setAllowMissingDependencies(bool allow) override { m_allowMissingDependencies = allow; }

    /**
     * @copydoc IBuildCtx::isKvdbAvailable
     */
    inline std::pair<bool, bool> isKvdbAvailable(const std::string& kvdbName) const override
    {
        if (!m_context.availableKvdbs.has_value())
        {
            return {false, false};
        }

        auto it = m_context.availableKvdbs.value().find(kvdbName);
        if (it == m_context.availableKvdbs.value().end())
        {
            return {false, false};
        }

        return {true, it->second};
    }

    /**
     * @brief Get the index discarded events configuration from the policy
     *
     * @return bool True if discarded events should be indexed, false otherwise
     */
    inline bool getIndexDiscardedEvents() const override { return m_context.indexDiscardedEvents; }
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BUILDCTX_HPP
