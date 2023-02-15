#include "operationBuilder.hpp"

#include <any>
#include <vector>

#include <json/json.hpp>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "registry.hpp"
#include "result.hpp"
#include "syntax.hpp"
#include "utils/stringUtils.hpp"

namespace
{

using namespace builder::internals;
using namespace json;
using namespace base;

Expression conditionValueBuilder(std::string&& field, Json&& value)
{
    const auto name {fmt::format("condition.value[{}=={}]", field, value.str())};
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};
    return Term<EngineOp>::create(name,
                                  [=](Event event)
                                  {
                                      if (event->equals(field, value))
                                      {
                                          return result::makeSuccess(std::move(event), successTrace);
                                      }
                                      else
                                      {
                                          return result::makeFailure(std::move(event), failureTrace);
                                      }
                                  });
}

Expression conditionReferenceBuilder(std::string&& field, std::string&& reference)
{
    const auto name {fmt::format("condition.reference[{}=={}]", field, reference)};
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure", name)};
    return Term<EngineOp>::create(name,
                                  [=](Event event)
                                  {
                                      if (event->equals(field, reference))
                                      {

                                          return result::makeSuccess(std::move(event), successTrace);
                                      }
                                      else
                                      {

                                          return result::makeFailure(std::move(event), failureTrace);
                                      }
                                  });
}

Expression mapValueBuilder(std::string&& field, Json&& value)
{
    const auto name {fmt::format("map.value[{}={}]", field, value.prettyStr())};

    const auto successTrace {fmt::format("[{}] -> Success", name)};
    return Term<EngineOp>::create(name,
                                  [=](Event event)
                                  {
                                      event->set(field, value);

                                      return result::makeSuccess(std::move(event), successTrace);
                                  });
}

Expression mapReferenceBuilder(std::string&& field, std::string&& reference)
{
    const auto name {fmt::format("map.reference[{}={}]", field, reference)};
    const auto successTrace {fmt::format("[{}] -> Success", name)};

    const auto failureTrace {fmt::format("[{}] -> Failure: Parameter \"{}\" reference not found", name, reference)};
    return Term<EngineOp>::create(name,
                                  [=](Event event)
                                  {
                                      if (event->exists(reference))
                                      {
                                          event->set(field, reference);

                                          return result::makeSuccess(std::move(event), successTrace);
                                      }
                                      else
                                      {

                                          return result::makeFailure(std::move(event), failureTrace);
                                      }
                                  });
}

enum class OperationType
{
    MAP,
    FILTER
};

Expression operationBuilder(const std::any& definition, OperationType type, std::shared_ptr<Registry> registry)
{
    std::string field;
    Json value;
    try
    {
        auto tuple = std::any_cast<std::tuple<std::string, Json>>(definition);
        field = std::get<0>(tuple);
        value = std::get<1>(tuple);
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(std::string("Error trying to obtain the arguments: ") + e.what());
    }

    // Call apropiate builder based on value
    if (value.isString() && value.getString().value().front() == syntax::REFERENCE_ANCHOR)
    {
        field = Json::formatJsonPath(field);
        auto reference = Json::formatJsonPath(value.getString().value().substr(1));
        switch (type)
        {
            case OperationType::FILTER: return conditionReferenceBuilder(std::move(field), std::move(reference));
            case OperationType::MAP: return mapReferenceBuilder(std::move(field), std::move(reference));
            default: throw std::runtime_error(fmt::format("Unsupported operation type \"{}\"", static_cast<int>(type)));
        }
    }
    else if (value.isString() && value.getString().value().front() == syntax::FUNCTION_HELPER_ANCHOR)
    {
        field = Json::formatJsonPath(field);
        std::string helperName;
        std::vector<std::string> helperArgs;
        auto helperString = value.getString().value().substr(1);

        helperArgs = base::utils::string::splitEscaped(
            helperString, syntax::FUNCTION_HELPER_ARG_ANCHOR, syntax::FUNCTION_HELPER_DEFAULT_ESCAPE);

        helperName = helperArgs.at(0);
        helperArgs.erase(helperArgs.begin());

        try
        {
            return registry->getBuilder("helper." + helperName)(
                std::make_tuple(std::move(field), helperName, std::move(helperArgs)));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("An error occurred while building the helper function \"{}\": {}", helperName, e.what()));
        }
    }
    else if (value.isArray())
    {
        if (value.size() == 0)
        {
            throw std::runtime_error(fmt::format("[builders::operationBuilder(<definition, type>)] "
                                                 "Empty array not allowed"));
        }

        auto array = value.getArray().value();
        std::vector<base::Expression> expressions;
        for (auto i = 0; i < array.size(); i++)
        {
            auto path = field + syntax::JSON_PATH_SEPARATOR + std::to_string(i);
            expressions.push_back(operationBuilder(std::make_tuple(path, array[i]), type, registry));
        }

        switch (type)
        {
            case OperationType::FILTER: return base::And::create("array", std::move(expressions));
            case OperationType::MAP: return base::Chain::create("array", std::move(expressions));
            default:
                throw std::runtime_error(fmt::format("[builders::operationBuilder(<definition, type>)] "
                                                     "Unsupported operation type: {}",
                                                     static_cast<int>(type)));
        }
    }
    else if (value.isObject())
    {
        auto object = value.getObject().value();
        std::vector<base::Expression> expressions;
        for (auto& [key, value] : object)
        {
            auto path = field + syntax::JSON_PATH_SEPARATOR + key;
            expressions.push_back(operationBuilder(std::make_tuple(path, value), type, registry));
        }

        switch (type)
        {
            case OperationType::FILTER: return base::And::create("object", std::move(expressions));
            case OperationType::MAP: return base::Chain::create("object", std::move(expressions));
            default:
                throw std::runtime_error(fmt::format("[builders::operationBuilder(<definition, type>)] "
                                                     "Unsupported operation type: {}",
                                                     static_cast<int>(type)));
        }
    }
    else
    {
        field = Json::formatJsonPath(field);
        switch (type)
        {
            case OperationType::FILTER: return conditionValueBuilder(std::move(field), std::move(value));
            case OperationType::MAP: return mapValueBuilder(std::move(field), std::move(value));
            default: throw std::runtime_error(fmt::format("Unsupported operation type \"{}\"", static_cast<int>(type)));
        }
    }
}

} // namespace

namespace builder::internals::builders
{

Builder getOperationConditionBuilder(std::shared_ptr<Registry> registry)
{
    return [registry](std::any definition)
    {
        return operationBuilder(definition, OperationType::FILTER, registry);
    };
}

Builder getOperationMapBuilder(std::shared_ptr<Registry> registry)
{
    return [registry](std::any definition)
    {
        return operationBuilder(definition, OperationType::MAP, registry);
    };
}

} // namespace builder::internals::builders
