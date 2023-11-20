#ifndef _BUILDER_BUILDERS_BUILDSTATE_HPP
#define _BUILDER_BUILDERS_BUILDSTATE_HPP

#include <string>

#include "ibuildState.hpp"

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
};

class BuildState final
    : public IBuildStateStage
    , public IBuildStateOp
{
private:
    RunState m_runState; // Runtime state
    Context m_context;   // Context

    std::shared_ptr<const StageRegistry> m_stageRegistry; // Stage registry
    std::shared_ptr<const OpRegistry> m_opRegistry;       // Operation registry

    std::shared_ptr<defs::IDefinitions> m_definitions; // Definitions

public:
    BuildState() = default;
    ~BuildState() = default;

    inline const RunState& runState() const { return m_runState; }
    inline RunState& runState() { return m_runState; }

    inline const Context& context() const { return m_context; }
    inline Context& context() { return m_context; }

    inline const StageRegistry& stageRegistry() const override { return *m_stageRegistry; }
    inline const OpRegistry& opRegistry() const override { return *m_opRegistry; }

    inline const defs::IDefinitions& definitions() const override { return *m_definitions; }
    inline void setDefinitions(const std::shared_ptr<defs::IDefinitions>& definitions) { m_definitions = definitions; }
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BUILDSTATE_HPP
