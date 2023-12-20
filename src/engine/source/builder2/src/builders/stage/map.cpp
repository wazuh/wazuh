#include "map.hpp"

#include <algorithm>

#include <json/json.hpp>

#include "builders/baseHelper.hpp"
#include "syntax.hpp"

namespace builder::builders
{
base::Expression mapBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isArray())
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects an array but got '{}'", syntax::asset::MAP_KEY, definition.typeName()));
    }

    if (definition.isEmpty())
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects a non-empty array but got an empty array", syntax::asset::MAP_KEY));
    }

    auto list = definition.getArray().value();
    std::vector<base::Expression> mapExpressions;
    std::transform(list.begin(),
                   list.end(),
                   std::back_inserter(mapExpressions),
                   [buildCtx](const auto& mapDef)
                   {
                       auto opExpr = baseHelperBuilder(mapDef, buildCtx, builders::HelperType::MAP);
                       return opExpr;
                   });

    auto expression = base::Chain::create("stage.map", mapExpressions);
    return expression;
}

} // namespace builder::builders
