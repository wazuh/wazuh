#ifndef _BUILDER_BUILDERS_IBUILDSTATE_HPP
#define _BUILDER_BUILDERS_IBUILDSTATE_HPP

#include "iregistry.hpp"
#include "types.hpp"

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>
#include <expression.hpp>
#include <schemf/ischema.hpp>

namespace builder::builders
{

// class IBuildState
// {
// private:
//     class impl;
//     std::unique_ptr<impl> m_impl;

// public:
//     virtual ~IBuildState() = default;

//     IBuildState();
//     IBuildState(const IBuildState& other) { m_impl = std::make_unique<impl>(*other.m_impl); };

//     IBuildState(IBuildState&& other) noexcept { m_impl = std::move(other.m_impl); };
// };

class IBuildState
{
public:
    virtual ~IBuildState() = default;
};

class IBuildStateStage;
class IBuildStateOp;

using OpBuilder = std::function<base::EngineOp(const Reference&, const OpArgs&, const std::shared_ptr<IBuildStateOp>&)>;
using OpEntry = std::tuple<schemf::Type, OpBuilder>;
using OpRegistry = IRegistry<OpEntry>;

using StageBuilder = std::function<base::Expression(const json::Json&, const std::shared_ptr<IBuildStateStage>&)>;
using StageRegistry = IRegistry<StageBuilder>;

class IBuildStateOp : public IBuildState
{
public:
    virtual ~IBuildStateOp() = default;

    virtual const defs::IDefinitions& definitions() const = 0;
};

class IBuildStateStage : public IBuildState
{
public:
    virtual ~IBuildStateStage() = default;
    virtual const StageRegistry& stageRegistry() const = 0;
    virtual const OpRegistry& opRegistry() const = 0;
};

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_IBUILDSTATE_HPP
