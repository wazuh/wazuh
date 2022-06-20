#include "stageBuilderCheck.hpp"

#include <algorithm>
#include <any>

#include "baseTypes.hpp"
#include "builder/expression.hpp"
#include "builder/registry.hpp"
#include "json.hpp"

namespace builder::internals::builders
{
Expression stageCheckBuilder(std::any definition)
{
    // TODO: add check conditional expression case

    json::Json jsonDefinition;
    try
    {
        jsonDefinition = std::any_cast<json::Json>(definition);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(
            "[builders::stageCheckBuilder(json)] Received unexpected argument type");
    }

    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(
            fmt::format("[builders::stageCheckBuilder(json)] Invalid json definition "
                        "type: expected [array] but got [{}]",
                        jsonDefinition.typeName()));
    }

    auto conditions = jsonDefinition.getArray();
    std::vector<Expression> conditionExpressions;
    std::transform(
        conditions.begin(),
        conditions.end(),
        std::back_inserter(conditionExpressions),
        [](auto condition)
        {
            if (!condition.isObject())
            {
                throw std::runtime_error(
                    fmt::format("[builders::stageCheckBuilder(json)] "
                                "Invalid array item type: expected [object] but got [{}]",
                                condition.typeName()));
            }
            if (condition.size() != 1)
            {
                throw std::runtime_error(fmt::format(
                    "[builders::stageCheckBuilder(json)] "
                    "Invalid array item object size: expected [1] but got [{}]",
                    condition.size()));
            }
            return Registry::getBuilder("operation.condition")(condition.getObject()[0]);
        });

    auto expression = And::create("stage.check", conditionExpressions);

    return expression;
}

} // namespace builder::internals::builders
