#ifndef _BUILDER_BUILDERS_HPP
#define _BUILDER_BUILDERS_HPP

#include <functional>
#include <memory>

#include <baseTypes.hpp>
#include <expression.hpp>
#include <schemval/ivalidator.hpp>

#include "argument.hpp"
#include "iregistry.hpp"
#include "syntax.hpp"

namespace builder::builders
{

// Forward declarations for circular dependencies
class IBuildCtx;

using MapResult = base::result::Result<json::Json>;
using MapOp = std::function<MapResult(base::ConstEvent)>;
using MapBuilder = std::function<MapOp(const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using TransformResult = base::result::Result<base::Event>;
using TransformOp = std::function<TransformResult(base::Event)>;
using TransformBuilder =
    std::function<TransformOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using FilterResult = base::result::Result<bool>;
using FilterOp = std::function<FilterResult(base::ConstEvent)>;
using FilterBuilder =
    std::function<FilterOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>;

using Op = std::variant<MapOp, TransformOp, FilterOp>;
using OpBuilder = std::variant<MapBuilder, TransformBuilder, FilterBuilder>;

using DynamicValToken =
    std::function<schemval::ValidationToken(const std::vector<OpArg>&, const schemval::IValidator&)>;
using ValidationInfo = std::variant<schemval::ValidationToken, DynamicValToken>;
using OpBuilderEntry = std::tuple<ValidationInfo, OpBuilder>;

using StageBuilder = std::function<base::Expression(const json::Json&, const std::shared_ptr<const IBuildCtx>&)>;

using RegistryType = MetaRegistry<OpBuilderEntry, StageBuilder>;

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_HPP
