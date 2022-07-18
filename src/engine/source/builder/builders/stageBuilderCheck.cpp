#include "stageBuilderCheck.hpp"

#include <algorithm>
#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "json.hpp"
#include "registry.hpp"
#include "syntax.hpp"
#include <logicExpression/logicExpression.hpp>

namespace
{
using namespace builder::internals;

base::Expression stageBuilderCheckList(const std::any& definition)
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
            "[builders::stageBuilderCheckList(json)] Received unexpected argument type");
    }

    if (!jsonDefinition.isArray())
    {
        throw std::runtime_error(
            fmt::format("[builders::stageBuilderCheckList(json)] Invalid json definition "
                        "type: expected [array] but got [{}]",
                        jsonDefinition.typeName()));
    }

    auto conditions = jsonDefinition.getArray().value();
    std::vector<base::Expression> conditionExpressions;
    std::transform(
        conditions.begin(),
        conditions.end(),
        std::back_inserter(conditionExpressions),
        [](auto condition)
        {
            if (!condition.isObject())
            {
                throw std::runtime_error(
                    fmt::format("[builders::stageBuilderCheckList(json)] "
                                "Invalid array item type: expected [object] but got [{}]",
                                condition.typeName()));
            }
            if (condition.size() != 1)
            {
                throw std::runtime_error(fmt::format(
                    "[builders::stageBuilderCheckList(json)] "
                    "Invalid array item object size: expected [1] but got [{}]",
                    condition.size()));
            }
            return Registry::getBuilder("operation.condition")(
                condition.getObject().value()[0]);
        });

    auto expression = base::And::create("stage.check", conditionExpressions);

    return expression;
}

base::Expression stageBuilderCheckExpression(const std::any& definition)
{
    // Obtain expressionString
    auto expressionString = std::any_cast<json::Json>(definition).getString().value();

    // Inject builder
    auto termBuilder = [=](std::string term) -> std::function<bool(base::Event)>
    {
        std::string field;
        std::string value;

        // Term to json def
        if (term.find("==") != std::string::npos)
        {
            auto pos = term.find("==");
            field = term.substr(0, pos);
            value = term.substr(pos + 2);
        }
        // TODO: handle rest of operators
        else if (syntax::FUNCTION_HELPER_ANCHOR == term[0])
        {
            auto pos1 = term.find("/");
            auto pos2 = [&]()
            {
                auto tmp = term.find("/", pos1 + 1);
                if (std::string::npos != tmp)
                {
                    return tmp;
                }
                return term.size();
            }();

            field = term.substr(pos1 + 1, pos2);
            value = term.substr(0, pos1) + term.substr(pos2, term.size());
        }

        json::Json valueJson;
        valueJson.setString(value);
        auto conditionDef = std::make_tuple(field, valueJson);
        auto opFn = Registry::getBuilder("operation.condition")(conditionDef)
                        ->getPtr<base::Term<base::EngineOp>>()
                        ->getFn();
        return opFn;
    };

    // Evaluator function
    auto evaluator = logicExpression::buildDijstraEvaluator<base::Event>(expressionString,
                                                                         termBuilder);

    // Trace
    auto name = fmt::format("check: {}", expressionString);
    auto successTrace = fmt::format("[{}] -> Success", name);
    auto failureTrace = fmt::format("[{}] -> Failure", name);

    // Return expression
    return base::Term<base::EngineOp>::create(
        "stage.check",
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

base::Expression stageBuilderCheck(std::any definition)
{
    json::Json jsonDefinition;
    try
    {
        jsonDefinition = std::any_cast<json::Json>(definition);
    }
    catch (const std::exception& e)
    {
        std::throw_with_nested(std::runtime_error(fmt::format(
            "[builder::stageBuilderCheck(json)] Received unexpected argument type")));
    }

    if (jsonDefinition.isArray())
    {
        return stageBuilderCheckList(definition);
    }
    else if (jsonDefinition.isString())
    {
        return stageBuilderCheckExpression(definition);
    }
    else
    {
        throw std::runtime_error(
            fmt::format("[builder::stageBuilderCheck(json)] Invalid json definition "
                        "type: expected [string] or [array] but got [{}]",
                        jsonDefinition.typeName()));
    }
}

} // namespace builder::internals::builders
