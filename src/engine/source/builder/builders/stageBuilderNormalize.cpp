#include "stageBuilderNormalize.hpp"

#include <algorithm>
#include <any>
#include <unordered_map>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "registry.hpp"
#include "syntax.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

namespace
{
const std::unordered_map<std::string, std::string> allowedBlocks = {
    {"map", "stage.map"}, {"check", "stage.check"}, {"logpar", "parser.logpar"}};
}

Builder getStageNormalizeBuilder(std::shared_ptr<Registry> registry)
{
    return [registry](const std::any& definition)
    {
        json::Json jsonDefinition;

        try
        {
            jsonDefinition = std::any_cast<json::Json>(definition);
        }
        catch (std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Definition could not be converted to json: {}", e.what()));
        }

        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(fmt::format(
                R"(Invalid json definition type: expected "array" but got "{}")",
                jsonDefinition.typeName()));
        }

        auto blocks = jsonDefinition.getArray().value();
        std::vector<base::Expression> blockExpressions;
        std::transform(
            blocks.begin(),
            blocks.end(),
            std::back_inserter(blockExpressions),
            [registry](auto block)
            {
                if (!block.isObject())
                {
                    throw std::runtime_error(fmt::format(
                        R"(Invalid array item type, expected "object" but got "{}")",
                        block.typeName()));
                }
                auto blockObj = block.getObject().value();
                std::vector<base::Expression> subBlocksExpressions;

                std::transform(
                    blockObj.begin(),
                    blockObj.end(),
                    std::back_inserter(subBlocksExpressions),
                    [registry](auto& tuple)
                    {
                        auto& [key, value] = tuple;
                        if (allowedBlocks.count(key) == 0)
                        {
                            throw std::runtime_error(
                                fmt::format("[builders::stageNormalizeBuilder(json)] "
                                            "Invalid block name: [{}]",
                                            key));
                        }

                        try
                        {
                            return registry->getBuilder(allowedBlocks.at(key))(value);
                        }
                        catch (const std::exception& e)
                        {
                            throw std::runtime_error(fmt::format(
                                "Stage block \"{}\" building failed: {}", key, e.what()));
                        }
                    });
                auto expression = base::And::create("subblock", subBlocksExpressions);
                return expression;
            });
        auto expression = base::Chain::create("stage.normalize", blockExpressions);
        return expression;
    };
}

} // namespace builder::internals::builders
