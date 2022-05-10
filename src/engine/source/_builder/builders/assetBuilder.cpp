#include <algorithm>
#include <any>
#include <unordered_map>
#include <vector>

#include "_builder/connectable.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/operation.hpp"
#include "_builder/registry.hpp"

namespace
{
using namespace builder::internals;

RegisterBuilder assetBuilder {
    "asset",
    [](const std::any& definition) -> std::shared_ptr<Connectable>
    {
        auto jsonDefinition = std::any_cast<Json>(definition);

        if (!jsonDefinition.isObject())
        {
            throw std::runtime_error(fmt::format(
                "Invalid asset definition: expected [object] but got [{}]",
                jsonDefinition.typeName()));
        }

        auto asset = jsonDefinition.getObject();

        // Get and pop name and non-stage attributes

        // Name is mandatory
        auto namePos = std::find_if(asset.begin(),
                                    asset.end(),
                                    [](auto& tuple)
                                    { return std::get<0>(tuple) == "name"; });
        auto name = std::get<1>(*namePos).getString();
        asset.erase(namePos);

        // Rest is optional
        auto parentsPos = std::find_if(
            asset.begin(),
            asset.end(),
            [](auto& tuple) { return std::get<0>(tuple) == "parents"; });

        auto parents = [&]()
        {
            std::vector<std::string> tmp {};
            if (parentsPos != asset.end())
            {
                auto tmp2 = std::get<1>(*parentsPos).getArray();
                std::transform(tmp2.begin(),
                               tmp2.end(),
                               std::back_inserter(tmp),
                               [](auto& parent) { return parent.getString(); });
                asset.erase(parentsPos);
            }
            return tmp;
        }();

        auto metadataPos = std::find_if(
            asset.begin(),
            asset.end(),
            [](auto& tuple) { return std::get<0>(tuple) == "metadata"; });

        auto metadata = [&]()
        {
            std::unordered_map<std::string, std::any> tmp {};
            if (metadataPos != asset.end())
            {
                auto tmp2 = std::get<1>(*metadataPos).getObject();
                std::transform(tmp2.begin(),
                               tmp2.end(),
                               std::inserter(tmp, tmp.begin()),
                               [](auto& tuple) {
                                   return std::make_pair(std::get<0>(tuple),
                                                         std::get<1>(tuple));
                               });
                asset.erase(metadataPos);
            }
            return tmp;
        }();

        // Build stages
        auto connectable =
            ConnectableAsset::create(ConnectableGroup::GroupType::CHAIN,
                                     std::move(name),
                                     {}, // Connectables
                                     std::move(parents),
                                     std::move(metadata));
        std::transform(asset.begin(),
                       asset.end(),
                       std::back_inserter(connectable->m_connectables),
                       [](auto tuple)
                       {
                           auto& [key, value] = tuple;
                           return Registry::getBuilder("stage." + key)(value);
                       });

        return connectable;
    }};

} // namespace
