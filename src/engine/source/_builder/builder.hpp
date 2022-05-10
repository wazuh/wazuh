#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <fmt/format.h>

#include "_builder/connectable.hpp"
#include "_builder/json.hpp"
#include "_builder/registry.hpp"

namespace builder
{

template<typename Catalog>
class Builder
{
private:
    // Assert Catalog has a getAsset method
    static_assert(
        std::is_member_function_pointer_v<decltype(&Catalog::getAsset)>,
        "Catalog::getAsset must be a member function");
    // Assert getAsset has expected signature
    // TODO: find a way
    // static_assert(std::is_invocable_r_v<Json,
    //                                     decltype(&Catalog::getAsset),
    //                                     int
    //                                     std::string>,
    //               "Catalog::getAsset must has signature Json(int, string)");

    const Catalog& m_catalog;

public:
    enum AssetType
    {
        Decoder = 0,
        Rule,
        Output,
        Filter,
        Environment
    };

    Builder(const Catalog& catalog)
        : m_catalog {catalog}
    {
    }

    std::shared_ptr<internals::Connectable>
    buildEnvironment(const std::string& name) const
    {
        // Get environment definition from catalog
        auto jsonDefinition = m_catalog.getAsset(AssetType::Environment, name);

        auto objectDefinition = jsonDefinition.getObject();

        // Each event must traverse each subgraph in order, decoders being first
        // and output being last, an event must not be dropped, so environment
        // connectable is modeled as FALLIBLE_CHAIN

        auto environment = internals::ConnectableGroup::create(
            std::string(name), internals::ConnectableGroup::FALLIBLE_CHAIN);

        // Decoders
        auto decodersPos = std::find_if(
            objectDefinition.begin(),
            objectDefinition.end(),
            [](auto& tuple) { return std::get<0>(tuple) == "decoders"; });
        if (decodersPos == objectDefinition.end())
        {
            throw std::runtime_error(
                "Invalid environment definition: must have [decoders] ");
        }

        std::vector<std::string> decodersNames = [&]()
        {
            std::vector<std::string> tmp {};
            auto tmp2 = std::get<1>(*decodersPos).getArray();
            std::transform(tmp2.begin(),
                           tmp2.end(),
                           std::back_inserter(tmp),
                           [](auto& decoder) { return decoder.getString(); });
            return tmp;
        }();

        std::unordered_map<std::string,
                           std::shared_ptr<internals::ConnectableGroup>>
            decoders {};

        for (auto& decoderName : decodersNames)
        {
            std::shared_ptr<internals::Connectable> conn = Registry::getBuilder(
                "asset")(m_catalog.getAsset(AssetType::Decoder, decoderName));
            decoders[decoderName] = internals::ConnectableGroup::create(
                decoderName + "Node",
                internals::ConnectableGroup::CHAIN,
                {conn});
        }

        // We have parent relationships, but we need child relationships
        // Nor efficient, nor elegant, but simple
        std::unordered_map<std::string, std::unordered_set<std::string>>
            childrenRel {};
        childrenRel["decoderGraph"] = {};
        for (auto& [name, connectable] : decoders)
        {
            std::shared_ptr<internals::Connectable> conn =
                connectable->m_connectables[0];
            auto asset = conn->getPtr<internals::ConnectableAsset>();

            if (asset->m_parents.empty())
            {
                childrenRel["decoderGraph"].insert(name);
            }
            else
            {
                for (auto& parent : asset->m_parents)
                {
                    if (childrenRel.find(parent) == childrenRel.end())
                    {
                        childrenRel[parent] = {};
                    }
                    childrenRel[parent].insert(name);
                }
            }
        }

        // Make subgraph
        auto decoderSubgraph = Registry::getBuilder("firstSuccessGraph")(
            std::make_tuple(std::string("decoderGraph"), decoders, childrenRel));

        // Rules

        // Filters

        // Outputs

        environment->m_connectables.push_back(decoderSubgraph);
        return environment;
    }
};

} // namespace builder

#endif // _BUILDER_H
