#ifndef _BUILDER_BUILDERS_HPP
#define _BUILDER_BUILDERS_HPP

#include <functional>
#include <memory>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <schemf/ivalidator.hpp>

#include "argument.hpp"
#include "iregistry.hpp"
#include "syntax.hpp"

namespace builder::builders
{

// Forward declarations for circular dependencies
class IBuildCtx;

using MapResult = base::result::Result<json::Json>;                ///< Result type for map operations.
using MapOp = std::function<MapResult(base::ConstEvent)>;          ///< Map operation function type.
using MapBuilder = std::function<MapOp(const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>; ///< Builder for map operations.

using TransformResult = base::result::Result<base::Event>;         ///< Result type for transform operations.
using TransformOp = std::function<TransformResult(base::Event)>;   ///< Transform operation function type.
using TransformBuilder =
    std::function<TransformOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>; ///< Builder for transform operations.

using FilterResult = base::result::Result<bool>;                   ///< Result type for filter operations.
using FilterOp = std::function<FilterResult(base::ConstEvent)>;    ///< Filter operation function type.
using FilterBuilder =
    std::function<FilterOp(const Reference&, const std::vector<OpArg>&, const std::shared_ptr<const IBuildCtx>&)>; ///< Builder for filter operations.

using Op = std::variant<MapOp, TransformOp, FilterOp>;             ///< Variant of all operation types.
using OpBuilder = std::variant<MapBuilder, TransformBuilder, FilterBuilder>; ///< Variant of all operation builders.

using DynamicValToken = std::function<schemf::ValidationToken(const std::vector<OpArg>&, const schemf::IValidator&)>; ///< Dynamic validation token factory.
using ValidationInfo = std::variant<schemf::ValidationToken, DynamicValToken>; ///< Validation information (static or dynamic).
using OpBuilderEntry = std::tuple<ValidationInfo, OpBuilder>;      ///< Registry entry: validation info + builder.

using StageBuilder = std::function<base::Expression(const json::Json&, const std::shared_ptr<const IBuildCtx>&)>; ///< Builder for pipeline stages.

/**
 * @brief Function type to build an enrichment expression.
 * @param bool Indicates if the enrichment need generate a trace or not.
 * @return std::tuple<base::Expression, std::string> The built enrichment expression and its traceable name.
 */
using EnrichmentBuilder = std::function<std::pair<base::Expression, std::string>(bool)>;

using RegistryType = MetaRegistry<OpBuilderEntry, StageBuilder, EnrichmentBuilder>; ///< Type of the builders meta-registry.

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_HPP
