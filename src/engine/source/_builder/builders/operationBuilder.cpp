#include "operationBuilder.hpp"

#include <any>

#include "_builder/event.hpp"
#include "_builder/expression.hpp"
#include "_builder/json.hpp"
#include "_builder/registry.hpp"
#include <utils/stringUtils.hpp>

namespace
{

using namespace builder::internals;

Expression conditionValueBuilder(std::string&& field, Json&& value)
{
    const auto name =
        fmt::format("condition.value[{}=={}]", field, value.prettyStr());
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Failure", name);
    return Term<EngineOp>::create(
        name,
        [=](Event&& event)
        {
            if (event.equals(field, value))
            {

                return makeSuccess(std::move(event), successTrace);
            }
            else
            {

                return makeFailure(std::move(event), failureTrace);
            }
        });
}

Expression conditionReferenceBuilder(std::string&& field,
                                     std::string&& reference)
{
    const auto name =
        fmt::format("condition.reference[{}=={}]", field, reference);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Failure", name);
    return Term<EngineOp>::create(
        name,
        [=](Event&& event)
        {
            if (event.equals(field, reference))
            {

                return makeSuccess(std::move(event), successTrace);
            }
            else
            {

                return makeFailure(std::move(event), failureTrace);
            }
        });
}

Expression mapValueBuilder(std::string&& field, Json&& value)
{
    const auto name = fmt::format("map.value[{}={}]", field, value.prettyStr());
    const auto successTrace = fmt::format("{} -> Success", name);
    return Term<EngineOp>::create(name,
                                  [=](Event&& event)
                                  {
                                      event.set(field, value);

                                      return makeSuccess(std::move(event),
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
        [=](Event&& event)
        {
            if (event.exists(reference))
            {
                event.set(field, reference);

                return makeSuccess(std::move(event), successTrace);
            }
            else
            {

                return makeFailure(std::move(event), failureTrace);
            }
        });
}

enum OperationType
{
    MAP = 0,
    FILTER
};

Expression operationBuilder(const std::any& definition, OperationType type)
{
    auto [field, value] =
        std::any_cast<std::tuple<std::string, Json>>(definition);
    field = Json::formatJsonPath(field);

    // Call apropiate builder based on value
    if (value.isString() && value.getString().front() == '$')
    {
        auto reference = Json::formatJsonPath(value.getString().substr(1));
        switch (type)
        {
            case FILTER:
                return conditionReferenceBuilder(std::move(field),
                                                 std::move(reference));
            case MAP:
                return mapReferenceBuilder(std::move(field),
                                           std::move(reference));
            default:
                throw std::runtime_error(fmt::format(
                    "Unknown operation type [{}] in operationBuilder",
                    static_cast<int>(type)));
        }
    }
    else if (value.isString() && value.getString().front() == '+')
    {
        auto helperName =
            value.getString().substr(1, value.getString().find('/'));
        auto helperArgsString =
            value.getString().substr(value.getString().find('/'));
        auto helperArgs = utils::string::split(helperArgsString, '/');
        return Registry::getBuilder(helperName)(
            std::make_tuple(std::move(field), std::move(helperArgs)));
    }
    else
    {
        switch (type)
        {
            case FILTER:
                return conditionValueBuilder(std::move(field),
                                             std::move(value));
            case MAP:
                return mapValueBuilder(std::move(field), std::move(value));
            default:
                throw std::runtime_error(fmt::format(
                    "Unknown operation type [{}] in operationBuilder",
                    static_cast<int>(type)));
        }
    }
}

} // namespace

namespace builder::internals::builders
{

Expression operationConditionBuilder(std::any definition)
{
    return operationBuilder(definition, FILTER);
}

Expression operationMapBuilder(std::any definition)
{
    return operationBuilder(definition, MAP);
}

} // namespace builder::internals::builders
