#include "stageBuilder.hpp"

#include <algorithm>
#include <any>

#include "_builder/expression.hpp"
#include "_builder/json.hpp"
#include "_builder/registry.hpp"

namespace builder::internals::builders
{

Expression stageCheckBuilder(std::any definition)
{
    auto jsonDefinition = std::any_cast<Json>(definition);

    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(fmt::format(
            "Invalid check definition: expected [array] but got [{}]",
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
                throw std::runtime_error(fmt::format(
                    "Expected [object] but got [{}]", condition.typeName()));
            }
            if (condition.size() != 1)
            {
                throw std::runtime_error("Expected [object] with one key");
            }
            return Registry::getBuilder("operation.condition")(
                condition.getObject()[0]);
        });

    auto expression = And::create("stage.check", conditionExpressions);

    return expression;
}

Expression stageMapBuilder(std::any definition)
{
    auto jsonDefinition = std::any_cast<Json>(definition);

    if (!jsonDefinition.isObject())
    {
        throw std::runtime_error(fmt::format(
            "Invalid map definition: expected [object] but got [{}]",
            jsonDefinition.typeName()));
    }

    auto mappings = jsonDefinition.getObject();
    std::vector<Expression> mappingExpressions;
    std::transform(mappings.begin(),
                   mappings.end(),
                   std::back_inserter(mappingExpressions),
                   [](auto tuple)
                   { return Registry::getBuilder("operation.map")(tuple); });

    auto expression = Chain::create("stage.map", mappingExpressions);
    return expression;
}

Expression stageNormalizeBuilder(std::any definition)
{
    auto jsonDefinition = std::any_cast<Json>(definition);

    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(fmt::format(
            "Invalid normalize definition: expected [array] but got [{}]",
            jsonDefinition.typeName()));
    }

    auto blocks = jsonDefinition.getArray();
    std::vector<Expression> blockExpressions;
    std::transform(
        blocks.begin(),
        blocks.end(),
        std::back_inserter(blockExpressions),
        [](auto block)
        {
            auto blockObj = block.getObject();
            std::vector<Expression> subBlocksExpressions;
            std::transform(blockObj.begin(),
                           blockObj.end(),
                           std::back_inserter(subBlocksExpressions),
                           [](auto& tuple)
                           {
                               auto& [key, value] = tuple;
                               return Registry::getBuilder("stage." +
                                                           key)(value);
                           });
            auto expression = And::create("subblock", subBlocksExpressions);
            return expression;
        });
    auto expression = Chain::create("stage.normalize", blockExpressions);
    return expression;
}

} // namespace builder::internals::builders
