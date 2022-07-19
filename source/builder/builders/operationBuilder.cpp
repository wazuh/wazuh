#include "operationBuilder.hpp"

#include <any>

#include "baseTypes.hpp"
#include "expression.hpp"
#include <json/json.hpp>
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
    const auto name = fmt::format("condition.value[{}=={}]", field, value.str());
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Failure", name);
    return Term<EngineOp>::create(
        name,
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
    const auto name = fmt::format("condition.reference[{}=={}]", field, reference);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Failure", name);
    return Term<EngineOp>::create(
        name,
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
    const auto name = fmt::format("map.value[{}={}]", field, value.prettyStr());
    const auto successTrace = fmt::format("{} -> Success", name);
    return Term<EngineOp>::create(name,
                                  [=](Event event)
                                  {
                                      event->set(field, value);

                                      return result::makeSuccess(std::move(event),
                                                                 successTrace);
                                  });
}

Expression mapReferenceBuilder(std::string&& field, std::string&& reference)
{
    const auto name = fmt::format("map.reference[{}={}]", field, reference);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace =
        fmt::format("{} -> Failure: [{}] not found", name, reference);
    return Term<EngineOp>::create(
        name,
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

Expression operationBuilder(const std::any& definition, OperationType type)
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
        std::throw_with_nested(
            std::runtime_error("[builders::operationBuilder(<definition, type>)] "
                               "Received unexpected arguments."));
    }
    field = Json::formatJsonPath(field);

    // Call apropiate builder based on value
    if (value.isString() && value.getString().value().front() == syntax::REFERENCE_ANCHOR)
    {
        auto reference = Json::formatJsonPath(value.getString().value().substr(1));
        switch (type)
        {
            case OperationType::FILTER:
                return conditionReferenceBuilder(std::move(field), std::move(reference));
            case OperationType::MAP:
                return mapReferenceBuilder(std::move(field), std::move(reference));
            default:
                throw std::runtime_error(
                    fmt::format("[builders::operationBuilder(<definition, type>)] "
                                "Unsupported operation type: {}",
                                static_cast<int>(type)));
        }
    }
    else if (value.isString()
             && value.getString().value().front() == syntax::FUNCTION_HELPER_ANCHOR)
    {
        std::string helperName;
        std::vector<std::string> helperArgs;
        auto helperString = value.getString().value().substr(1);

        helperArgs =
            utils::string::split(helperString, syntax::FUNCTION_HELPER_ARG_ANCHOR);
        helperName = helperArgs[0];
        helperArgs.erase(helperArgs.begin());

        try
        {
            return Registry::getBuilder("helper." + helperName)(
                std::make_tuple(std::move(field), helperName, std::move(helperArgs)));
        }
        catch (const std::exception& e)
        {
            std::throw_with_nested(std::runtime_error(
                fmt::format("[builders::operationBuilder(<definition, type>)] "
                            "Exception building helper [{}]",
                            helperName)));
        }
    }
    else
    {
        switch (type)
        {
            case OperationType::FILTER:
                return conditionValueBuilder(std::move(field), std::move(value));
            case OperationType::MAP:
                return mapValueBuilder(std::move(field), std::move(value));
            default:
                throw std::runtime_error(
                    fmt::format("[builders::operationBuilder(<definition, type>)] "
                                "Unsupported operation type: {}",
                                static_cast<int>(type)));
        }
    }
}

} // namespace

namespace builder::internals::builders
{

base::Expression operationConditionBuilder(std::any definition)
{
    return operationBuilder(definition, OperationType::FILTER);
}

base::Expression operationMapBuilder(std::any definition)
{
    return operationBuilder(definition, OperationType::MAP);
}

} // namespace builder::internals::builders
