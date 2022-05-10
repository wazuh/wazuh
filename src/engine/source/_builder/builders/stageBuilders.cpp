#include <algorithm>
#include <any>
#include <string_view>

#include "_builder/connectable.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/operation.hpp"
#include "_builder/registry.hpp"

namespace
{
using namespace builder::internals;

RegisterBuilder stageCheckBuilder {
    "stage.check",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto jsonDefinition = std::any_cast<Json>(definition);

        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(fmt::format(
                "Invalid check definition: expected [array] but got [{}]",
                jsonDefinition.typeName()));
        }

        auto connectable =
            ConnectableGroup::create("stage.check", ConnectableGroup::CHAIN);
        auto conditions = jsonDefinition.getArray();
        std::transform(conditions.begin(),
                       conditions.end(),
                       std::back_inserter(connectable->m_connectables),
                       [](auto condition)
                       {
                           if (!condition.isObject())
                           {
                               throw std::runtime_error(
                                   fmt::format("Expected [object] but got [{}]",
                                               condition.typeName()));
                           }
                           if (condition.size() != 1)
                           {
                               throw std::runtime_error(
                                   "Expected [object] with one key");
                           }
                           return Registry::getBuilder("operation.condition")(
                               condition.getObject()[0]);
                       });

        return connectable;
    }};

RegisterBuilder stageMapBuilder {
    "stage.map",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto jsonDefinition = std::any_cast<Json>(definition);

        if (!jsonDefinition.isObject())
        {
            throw std::runtime_error(fmt::format(
                "Invalid map definition: expected [object] but got [{}]",
                jsonDefinition.typeName()));
        }

        auto mappings = jsonDefinition.getObject();
        auto connectable = ConnectableGroup::create(
            "stage.map", ConnectableGroup::FALLIBLE_CHAIN);
        std::transform(mappings.begin(),
                       mappings.end(),
                       std::back_inserter(connectable->m_connectables),
                       [](auto tuple) {
                           return Registry::getBuilder("operation.map")(tuple);
                       });

        return connectable;
    }};

RegisterBuilder stageNormalizeBuilder {
    "stage.normalize",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto jsonDefinition = std::any_cast<Json>(definition);

        if (!jsonDefinition.isArray())
        {
            throw std::runtime_error(fmt::format(
                "Invalid normalize definition: expected [array] but got [{}]",
                jsonDefinition.typeName()));
        }

        auto connectable = ConnectableGroup::create(
            "stage.normalize", ConnectableGroup::FALLIBLE_CHAIN);
        auto blocks = jsonDefinition.getArray();
        std::transform(
            blocks.begin(),
            blocks.end(),
            std::back_inserter(connectable->m_connectables),
            [](auto block)
            {
                auto blockObj = block.getObject();
                auto connectableGroup =
                    ConnectableGroup::create("block", ConnectableGroup::CHAIN);
                std::transform(
                    blockObj.begin(),
                    blockObj.end(),
                    std::back_inserter(connectableGroup->m_connectables),
                    [](auto& tuple)
                    {
                        auto& [key, value] = tuple;
                        return Registry::getBuilder("stage." + key)(value);
                    });
                return connectableGroup;
            });

        return connectable;
    }};
} // namespace
