#include "outputs.hpp"

#include <algorithm>

#include <expression.hpp>
#include <json/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

base::Expression outputsBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Check json is as expected
    if (!definition.isArray())
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects an array but got '{}'", syntax::asset::OUTPUTS_KEY, definition.typeName()));
    }
    if (definition.size() == 0)
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects a non-empty array", syntax::asset::OUTPUTS_KEY));
    }

    // All output expressions
    std::vector<base::Expression> outputExpressions;

    // Obtain array and call appropriate builder for each item, adding the expression
    // to the outputExpressions vector
    auto outputObjects = definition.getArray().value();
    std::transform(
        outputObjects.begin(),
        outputObjects.end(),
        std::back_inserter(outputExpressions),
        [buildCtx](const auto& outputDefinition)
        {
            if (!outputDefinition.isObject())
            {
                throw std::runtime_error(
                    fmt::format("Stage '{}' expects an array of objects but got an item of type '{}'",
                                syntax::asset::OUTPUTS_KEY,
                                outputDefinition.typeName()));
            }

            if (outputDefinition.size() != 1)
            {
                throw std::runtime_error(fmt::format("Stage '{}' expects an array of objects with a single key-value "
                                                     "pair but got an item with {} key-value pairs",
                                                     syntax::asset::OUTPUTS_KEY,
                                                     outputDefinition.size()));
            }

            auto outputObject = outputDefinition.getObject().value();
            const auto& [outputName, outputValue] = outputObject.front();

            // Get builder for output
            auto resp = buildCtx->registry().get<StageBuilder>(outputName);
            if (base::isError(resp))
            {
                throw std::runtime_error(
                    fmt::format("Stage '{}' unknown output '{}'", syntax::asset::OUTPUTS_KEY, outputName));
            }
            auto builder = base::getResponse<StageBuilder>(resp);

            // Build output
            base::Expression outputExpression;
            try
            {
                outputExpression = builder(outputValue, buildCtx);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format(
                    "Stage '{}' failed to build output '{}': {}", syntax::asset::OUTPUTS_KEY, outputName, e.what()));
            }

            return outputExpression;
        });

    // Create stage expression and return
    return base::Broadcast::create("outputs", outputExpressions);
}

} // namespace builder::builders
