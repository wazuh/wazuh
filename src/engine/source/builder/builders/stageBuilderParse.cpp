#include "stageBuilderParse.hpp"

#include <algorithm>
#include <any>
#include <stdexcept>
#include <string>

#include "expression.hpp"
#include "registry.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

Builder getStageBuilderParse(std::shared_ptr<Registry> registry)
{
    return [registry](const std::any& definition)
    {
        // Assert value is as expected
        json::Json jsonDefinition;
        try
        {
            jsonDefinition = std::any_cast<json::Json>(definition);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                "[builder::stageBuilderParse(json)] Received unexpected argument type");
        }
        if (!jsonDefinition.isObject())
        {
            throw std::runtime_error(
                fmt::format("[builder::stageBuilderParse(json)] Invalid json definition "
                            "type: expected [object] but got [{}]",
                            jsonDefinition.typeName()));
        }

        std::vector<base::Expression> parserExpressions;
        auto parseObj = jsonDefinition.getObject().value();

        std::transform(parseObj.begin(),
                       parseObj.end(),
                       std::back_inserter(parserExpressions),
                       [registry](auto& tuple)
                       {
                           auto& parserName = std::get<0>(tuple);
                           auto& parserValue = std::get<1>(tuple);
                           base::Expression parserExpression;
                           try
                           {
                               parserExpression = registry->getBuilder(
                                   "parser." + parserName)(parserValue);
                           }
                           catch (const std::exception& e)
                           {
                               std::throw_with_nested(std::runtime_error(
                                   fmt::format("[builder::stageBuilderParse(json)] "
                                               "Error building parser [{}]: {}",
                                               parserName,
                                               e.what())));
                           }

                           return parserExpression;
                       });

        return base::Or::create("parse", parserExpressions);
    };
}

} // namespace builder::internals::builders
