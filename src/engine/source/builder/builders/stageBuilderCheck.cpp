#include "stageBuilderCheck.hpp"

#include <algorithm>
#include <any>

#include <json/json.hpp>
#include <regex>
#include <logicexpr/logicexpr.hpp>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "helperParser.hpp"
#include "registry.hpp"
#include "syntax.hpp"


namespace
{
using namespace builder::internals;

base::Expression stageBuilderCheckList(const std::any& definition,
                                       std::shared_ptr<defs::IDefinitions> definitions,
                                       std::shared_ptr<Registry<Builder>> registry)
{
    // TODO: add check conditional expression case

    json::Json jsonDefinition;
    try
    {
        jsonDefinition = std::any_cast<json::Json>(definition);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(fmt::format("Check stage: Definition could not be converted to json: {}", e.what()));
    }

    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(fmt::format("Check stage: Invalid json definition type: "
                                             "expected 'array' but got '{}'",
                                             jsonDefinition.typeName()));
    }

    auto conditions = jsonDefinition.getArray().value();
    std::vector<base::Expression> conditionExpressions;
    std::transform(
        conditions.begin(),
        conditions.end(),
        std::back_inserter(conditionExpressions),
        [registry, definitions](auto condition)
        {
            if (!condition.isObject())
            {
                throw std::runtime_error(fmt::format("Check stage: Invalid array item type, expected "
                                                     "'object' but got '{}'",
                                                     condition.typeName()));
            }
            if (condition.size() != 1)
            {
                throw std::runtime_error(fmt::format("Check stage: Invalid object item size, expected exactly "
                                                     "one key/value pair but got '{}'",
                                                     condition.size()));
            }
            return registry->getBuilder("operation.condition")(condition.getObject().value()[0], definitions);
        });

    auto expression = base::And::create("stage.check", conditionExpressions);

    return expression;
}

using TermBuilder = std::function<std::function<bool(base::Event)>(const BuildToken&)>;
TermBuilder getTermBuilder(std::shared_ptr<Registry<Builder>> registry, std::shared_ptr<defs::IDefinitions> definitions)
{
    return [registry, definitions](const BuildToken& token)
    {
        std::any opBuilderInput;

        if (std::holds_alternative<HelperToken>(token))
        {
            auto helperToken = std::get<HelperToken>(token);
            opBuilderInput = toBuilderInput(helperToken);
        }
        else
        {
            auto expressionToken = std::get<ExpressionToken>(token);
            opBuilderInput = toBuilderInput(expressionToken);
        }

        auto op = registry->getBuilder("operation.condition")(opBuilderInput, definitions);
        return op->getPtr<base::Term<base::EngineOp>>()->getFn();
    };
}

base::Expression stageBuilderCheckExpression(const std::any& definition,
                                             std::shared_ptr<defs::IDefinitions> definitions,
                                             std::shared_ptr<Registry<Builder>> registry)
{
    // Obtain expressionString
    auto expressionString = std::any_cast<json::Json>(definition).getString().value();
    expressionString = definitions->replace(expressionString);

    // Get expression evaluator
    auto evaluator = logicexpr::buildDijstraEvaluator<base::Event, BuildToken>(expressionString, getTermBuilder(registry, definitions), getTermParser());

    // Trace
    auto name = fmt::format("check: {}", expressionString);
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace = fmt::format("[{}] -> Failure", name);

    // Return expression
    return base::Term<base::EngineOp>::create("stage.check",
                                              [=](base::Event event)
                                              {
                                                  if (evaluator(event))
                                                  {
                                                      return base::result::makeSuccess(event, successTrace);
                                                  }
                                                  else
                                                  {
                                                      return base::result::makeFailure(event, failureTrace);
                                                  }
                                              });
}

} // namespace

namespace builder::internals::builders
{

Builder getStageBuilderCheck(std::weak_ptr<Registry<Builder>> weakRegistry)
{
    return [weakRegistry](std::any definition, std::shared_ptr<defs::IDefinitions> definitions)
    {
        if (weakRegistry.expired())
        {
            throw std::runtime_error("Check stage: Registry expired");
        }
        auto registry = weakRegistry.lock();

        json::Json jsonDefinition;
        try
        {
            jsonDefinition = std::any_cast<json::Json>(definition);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Check stage: Definition could not be converted to json: {}", e.what()));
        }

        if (jsonDefinition.isArray())
        {
            return stageBuilderCheckList(definition, definitions, registry);
        }
        else if (jsonDefinition.isString())
        {
            return stageBuilderCheckExpression(definition, definitions, registry);
        }
        else
        {
            throw std::runtime_error(fmt::format("Check stage: Invalid json definition type, \"string\" or "
                                                 "'array' were expected but got '{}'",
                                                 jsonDefinition.typeName()));
        }
    };
}

} // namespace builder::internals::builders
