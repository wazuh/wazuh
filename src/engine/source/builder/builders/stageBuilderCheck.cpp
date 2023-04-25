#include "stageBuilderCheck.hpp"

#include <algorithm>
#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "registry.hpp"
#include "syntax.hpp"
#include <json/json.hpp>
#include <logicExpression/logicExpression.hpp>
#include <regex>

namespace
{
using namespace builder::internals;

base::Expression stageBuilderCheckList(const std::any& definition,
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
                                             "expected \"array\" but got \"{}\"",
                                             jsonDefinition.typeName()));
    }

    auto conditions = jsonDefinition.getArray().value();
    std::vector<base::Expression> conditionExpressions;
    std::transform(conditions.begin(),
                   conditions.end(),
                   std::back_inserter(conditionExpressions),
                   [registry](auto condition)
                   {
                       if (!condition.isObject())
                       {
                           throw std::runtime_error(fmt::format("Check stage: Invalid array item type, expected "
                                                                "\"object\" but got \"{}\"",
                                                                condition.typeName()));
                       }
                       if (condition.size() != 1)
                       {
                           throw std::runtime_error(
                               fmt::format("Check stage: Invalid object item size, expected exactly "
                                           "one key/value pair but got \"{}\"",
                                           condition.size()));
                       }
                       return registry->getBuilder("operation.condition")(condition.getObject().value()[0]);
                   });

    auto expression = base::And::create("stage.check", conditionExpressions);

    return expression;
}

base::Expression stageBuilderCheckExpression(const std::any& definition,
                                             std::shared_ptr<Registry<Builder>> registry)
{
    // Obtain expressionString
    auto expressionString = std::any_cast<json::Json>(definition).getString().value();

    // Inject builder
    auto termBuilder = [&](std::string term) -> std::function<bool(base::Event)>
    {
        std::string field;
        std::string value;
        json::Json valueJson;
        std::string operador;

        if (syntax::FUNCTION_HELPER_ANCHOR == term[0])
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

            field = term.substr(pos1 + 1, pos2 - pos1 - 1);
            value = term.substr(0, pos1) + term.substr(pos2);
        }
        else
        {
            // Pattern looking for '<', '>', '<=', '>=', '==' or '!='
            const std::string opPattern = R"(^[^=<>!]+([<>]=?|==|!=))";
            const std::regex opRegex(opPattern);

            std::smatch match;
            if (std::regex_search(term, match, opRegex))
            {
                operador = match[1];
                auto pos = term.find(operador);

                field = term.substr(0, pos);

                auto operando = term.substr(pos + operador.length());

                if (operador == "==" || operador == "!=")
                {
                    try
                    {
                        valueJson = json::Json(operando.c_str());
                    }
                    catch (std::runtime_error& e)
                    {
                        valueJson.setString(operando);
                    }
                }
                else
                {
                    try
                    {
                        valueJson = json::Json(operando.c_str());
                    }
                    catch (std::runtime_error& e)
                    {
                        valueJson.setString(operando);
                    }

                    if (!valueJson.isInt64() && !valueJson.isString())
                    {
                        throw std::runtime_error(fmt::format(
                            "Check stage: The \"{}\" operator only allows operate with numbers or string", operador));
                    }

                    const auto prefix = valueJson.isInt64() ? "+int_" : "+string_";
                    const auto suffix = ((operador == "<=")   ? "less_or_equal/"
                                         : (operador == ">=") ? "greater_or_equal/"
                                         : (operador == "<")  ? "less/"
                                                              : "greater/")
                                        + operando;
                    value = prefix + suffix;
                    valueJson.setString(value);
                }
            }
            else
            {
                throw std::runtime_error {fmt::format("Check stage: Invalid operator \"{}\"", term)};
            }
        }

        auto conditionDef = std::make_tuple(field, valueJson);
        auto opEx = registry->getBuilder("operation.condition")(conditionDef);

        if (opEx->isTerm())
        {
            if (operador != "==" && operador != "!=")
            {
                return opEx->getPtr<base::Term<base::EngineOp>>()->getFn();
            }

            return [opEx, operador](base::Event event) -> bool
            {
                auto result = opEx->getPtr<base::Term<base::EngineOp>>()->getFn()(event);
                if (!result)
                {
                    if (operador == "==")
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                return true && operador == "==";
            };
        }
        else
        {
            std::vector<base::EngineOp> fnVec;
            for (const auto& t : opEx->getPtr<base::Operation>()->getOperands())
            {
                if (t->isTerm())
                {
                    fnVec.push_back(t->getPtr<base::Term<base::EngineOp>>()->getFn());
                }
                else
                {
                    throw std::runtime_error {fmt::format("Check stage: Comparison of objects that have objects inside is not supported.")};
                }
            }

            return [fnVec, operador](base::Event event) -> bool
            {
                for (const auto& fn : fnVec)
                {
                    auto result = fn(event);
                    if (!result)
                    {
                        if (operador == "==")
                        {
                            return false;
                        }
                        else
                        {
                            return true;
                        }
                    }
                }
                return true && operador == "==";
            };
        }
    };

    // Evaluator function
    auto evaluator = logicExpression::buildDijstraEvaluator<base::Event>(expressionString, termBuilder);

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

Builder getStageBuilderCheck(std::shared_ptr<Registry<Builder>> registry)
{
    return [registry](std::any definition)
    {
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
            return stageBuilderCheckList(definition, registry);
        }
        else if (jsonDefinition.isString())
        {
            return stageBuilderCheckExpression(definition, registry);
        }
        else
        {
            throw std::runtime_error(fmt::format("Check stage: Invalid json definition type, \"string\" or "
                                                 "\"array\" were expected but got \"{}\"",
                                                 jsonDefinition.typeName()));
        }
    };
}

} // namespace builder::internals::builders
