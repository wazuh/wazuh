#include "stageBuilderOutputs.hpp"

#include <algorithm>
#include <any>
#include <stdexcept>
#include <string>
#include <vector>

#include <expression.hpp>
#include <json/json.hpp>
#include <logging/logging.hpp>

namespace builder::internals::builders
{

Builder getStageBuilderOutputs(std::shared_ptr<Registry> registry)
{
    return [registry](const std::any& definition)
    {
        json::Json jsonDefinition;

        // Get json and check is as expected
        try
        {
            jsonDefinition = std::any_cast<json::Json>(definition);
        }
        catch (const std::exception& e)
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
        if (jsonDefinition.size() == 0)
        {
            throw std::runtime_error(
                "Invalid json definition, expected one element at least");
        }

        // All output expressions
        std::vector<base::Expression> outputExpressions;

        // Obtain array and call appropriate builder for each item, adding the expression
        // to the outputExpressions vector
        auto outputObjects = jsonDefinition.getArray().value();
        std::transform(
            outputObjects.begin(),
            outputObjects.end(),
            std::back_inserter(outputExpressions),
            [registry](auto outputDefinition)
            {
                if (!outputDefinition.isObject())
                {
                    throw std::runtime_error(
                        fmt::format("Invalid array item type, expected "
                                    "\"object\" but got \"{}\"",
                                    outputDefinition.typeName()));
                }

                if (outputDefinition.size() != 1)
                {
                    throw std::runtime_error(
                        fmt::format("Invalid object item size, expected exactly one "
                                    "key/value pair but got \"{}\"",
                                    outputDefinition.size()));
                }

                auto outputObject = outputDefinition.getObject().value();
                auto outputName = std::get<0>(outputObject.front());
                auto outputValue = std::get<1>(outputObject.front());

                base::Expression outputExpression;
                try
                {
                    outputExpression =
                        registry->getBuilder("output." + outputName)(outputValue);
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error(fmt::format(
                        "Building output \"{}\" failed: {}", outputName, e.what()));
                }

                return outputExpression;
            });

        // Create stage expression and return
        return base::Broadcast::create("outputs", outputExpressions);
    };
}

} // namespace builder::internals::builders
