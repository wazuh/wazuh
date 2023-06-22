#include "operationBuilder.hpp"

#include <any>
#include <sstream>
#include <vector>

#include <defs/idefinitions.hpp>
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

void checkSchemaTypes(const std::string& target,
                      const json::Json& value,
                      std::shared_ptr<schemf::ISchema> schema,
                      const std::string& name)
{
    if (schema->hasField(target))
    {
        auto error = schema->validate(target, value);
        if (error)
        {
            throw std::runtime_error(fmt::format("Operation '{}' failed schema validation: {}", name, error->message));
        }
    }
}

void checkSchemaTypes(const std::string& target,
                      const std::string& reference,
                      std::shared_ptr<schemf::ISchema> schema,
                      const std::string& name)
{
    if (schema->hasField(target) && schema->hasField(reference))
    {
        auto error = schema->validate(target, reference);
        if (error)
        {
            throw std::runtime_error(fmt::format("Operation '{}' failed schema validation: {}", name, error->message));
        }
    }
}

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

Expression operationBuilder(const std::any& definition,
                            std::shared_ptr<defs::IDefinitions> definitions,
                            OperationType type,
                            std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                            std::shared_ptr<schemf::ISchema> schema,
                            bool forceFieldNaming)
{
    if (helperRegistry == nullptr)
    {
        throw std::runtime_error("operation builder needs a valid helper registry.");
    }

    if (schema == nullptr)
    {
        throw std::runtime_error("operation builder needs a valid schema.");
    }

    std::string targetField;
    std::string targetFieldPath;
    std::string operationName;
    Json value;
    try
    {
        auto tuple = std::any_cast<std::tuple<std::string, Json>>(definition);
        targetField = std::move(std::get<0>(tuple));
        targetFieldPath = Json::formatJsonPath(targetField);
        value = std::move(std::get<1>(tuple));
        operationName = fmt::format("{}: {}", targetField, value.str());
    }
    catch (std::exception& e)
    {
        throw std::runtime_error(std::string("Error trying to obtain the arguments: ") + e.what());
    }

    // Check target field is a schema field or a custom field
    if (forceFieldNaming && !schema->hasField(targetField) && targetField[0] != syntax::CUSTOM_FIELD_ANCHOR)
    {
        throw std::runtime_error(fmt::format(
            "Operation '{}' failed schema validation: target field '{}' is not a schema field nor a custom field",
            operationName,
            targetField));
    }

    // Call apropiate builder based on value
    if (value.isString() && value.getString().value().front() == syntax::REFERENCE_ANCHOR)
    {
        auto reference = value.getString().value().substr(1);
        auto referencePath = Json::formatJsonPath(reference);

        // Check reference is a schema field or a custom field
        if (forceFieldNaming && !schema->hasField(reference) && !definitions->contains(referencePath)
            && reference[0] != syntax::CUSTOM_FIELD_ANCHOR)
        {
            throw std::runtime_error(fmt::format(
                "Operation '{}' failed schema validation: reference '{}' is not a schema field nor a custom field",
                operationName,
                reference));
        }

        // If it is a definition call value builder
        if (definitions->contains(referencePath))
        {
            value = definitions->get(referencePath);
            checkSchemaTypes(targetField, value, schema, operationName);
            switch (type)
            {
                case OperationType::FILTER: return conditionValueBuilder(std::move(targetFieldPath), std::move(value));
                case OperationType::MAP: return mapValueBuilder(std::move(targetFieldPath), std::move(value));
                default:
                    throw std::runtime_error(fmt::format("Unsupported operation type \"{}\"", static_cast<int>(type)));
            }
        }

        // If it is not a definition call reference builder
        checkSchemaTypes(targetField, reference, schema, operationName);
        switch (type)
        {
            case OperationType::FILTER:
                return conditionReferenceBuilder(std::move(targetFieldPath), std::move(referencePath));
            case OperationType::MAP: return mapReferenceBuilder(std::move(targetFieldPath), std::move(referencePath));
            default: throw std::runtime_error(fmt::format("Unsupported operation type \"{}\"", static_cast<int>(type)));
        }
    }
    else if (value.isString() && value.getString().value().front() == syntax::FUNCTION_HELPER_ANCHOR)
    {
        std::string helperName;
        std::vector<std::string> helperArgs;
        auto helperString = value.getString().value().substr(1);

        helperArgs = base::utils::string::splitEscaped(
            helperString, syntax::FUNCTION_HELPER_ARG_ANCHOR, syntax::FUNCTION_HELPER_DEFAULT_ESCAPE);

        helperName = helperArgs.at(0);
        helperArgs.erase(helperArgs.begin());

        // Check if there are invalid references in the arguments
        for (const auto& arg : helperArgs)
        {
            if (forceFieldNaming && arg[0] == syntax::REFERENCE_ANCHOR)
            {
                auto argPath = Json::formatJsonPath(arg.substr(1));
                if (!schema->hasField(arg.substr(1)) && !definitions->contains(argPath)
                    && arg[1] != syntax::CUSTOM_FIELD_ANCHOR)
                {
                    throw std::runtime_error(fmt::format("Operation '{}' failed schema validation: argument '{}' is "
                                                         "not a schema field nor a custom field",
                                                         operationName,
                                                         arg));
                }
            }
        }

        try
        {
            return helperRegistry->getBuilder(helperName)(targetFieldPath, helperName, helperArgs, definitions);
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
            auto path = targetField + syntax::JSON_PATH_SEPARATOR + std::to_string(i);
            expressions.push_back(
                operationBuilder(std::make_tuple(path, array[i]), definitions, type, helperRegistry, schema, forceFieldNaming));
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
            auto path = targetField + syntax::JSON_PATH_SEPARATOR + key;
            expressions.push_back(
                operationBuilder(std::make_tuple(path, value), definitions, type, helperRegistry, schema, forceFieldNaming));
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
        checkSchemaTypes(targetField, value, schema, operationName);
        switch (type)
        {
            case OperationType::FILTER: return conditionValueBuilder(std::move(targetFieldPath), std::move(value));
            case OperationType::MAP: return mapValueBuilder(std::move(targetFieldPath), std::move(value));
            default: throw std::runtime_error(fmt::format("Unsupported operation type \"{}\"", static_cast<int>(type)));
        }
    }
}

} // namespace

namespace builder::internals::builders
{

Builder getOperationConditionBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                                     std::shared_ptr<schemf::ISchema> schema,
                                     bool forceFieldNaming)
{
    return
        [helperRegistry, schema, forceFieldNaming](std::any definition, std::shared_ptr<defs::IDefinitions> definitions)
    {
        return operationBuilder(
            definition, definitions, OperationType::FILTER, helperRegistry, schema, forceFieldNaming);
    };
}

Builder getOperationMapBuilder(std::shared_ptr<Registry<HelperBuilder>> helperRegistry,
                               std::shared_ptr<schemf::ISchema> schema,
                               bool forceFieldNaming)
{
    return
        [helperRegistry, schema, forceFieldNaming](std::any definition, std::shared_ptr<defs::IDefinitions> definitions)
    {
        return operationBuilder(definition, definitions, OperationType::MAP, helperRegistry, schema, forceFieldNaming);
    };
}

} // namespace builder::internals::builders
