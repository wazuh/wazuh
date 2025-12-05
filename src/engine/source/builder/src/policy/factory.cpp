#include "policy/factory.hpp"

#include <numeric> // std::accumulate
#include <stdexcept>

#include <fmt/format.h>

#include <store/utils.hpp>

#include "asset.hpp"
#include "syntax.hpp"

namespace
{
auto constexpr GRAPH_INPUT_SUFFIX = "Input";
} // namespace

namespace builder::policy::factory
{

BuiltAssets buildAssets(const cm::store::dataType::Policy& policy,
                        const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder,
                        const bool sandbox)
{
    BuiltAssets builtAssets;

    for (const auto& integUUID : policy.getIntegrationsUUIDs())
    {
        const auto integration = cmStoreNsReader->getIntegrationByUUID(integUUID);
        if (!integration.isEnabled())
        {
            continue;
        }

        assetBuilder->getContext().integrationName = integration.getName();
        assetBuilder->getContext().integrationCategory = integration.getCategory();

        for (const auto& decUUID : integration.getDecodersByUUID())
        {
            const auto decoder = cmStoreNsReader->getAssetByUUID(decUUID);
            if (!decoder.getBool(json::Json::formatJsonPath(builder::syntax::asset::ENABLED_KEY)).value_or(false))
            {
                continue;
            }

            Asset asset = (*assetBuilder)(decoder);

            const auto isRootDefault =
                (asset.name() == std::get<0>(cmStoreNsReader->resolveNameFromUUID(policy.getRootDecoder())));

            if (isRootDefault && !asset.parents().empty())
            {
                throw std::runtime_error(
                    fmt::format("Root default decoder '{}' must not have parents", asset.name().toStr()));
            }

            if (asset.parents().empty() && !isRootDefault)
            {
                const auto integrationDefaultParent = integration.getDefaultParent();
                std::string defaultParentName;
                if (integrationDefaultParent.has_value())
                {
                    defaultParentName = integrationDefaultParent.value();
                }
                else
                {
                    defaultParentName = policy.getDefaultParent();
                }

                asset.parents().emplace_back(
                    std::move(std::get<0>(cmStoreNsReader->resolveNameFromUUID(defaultParentName))));
            }

            auto& decodersData = builtAssets[cm::store::ResourceType::DECODER];
            if (decodersData.assets.find(asset.name()) == decodersData.assets.end())
            {
                decodersData.orderedAssets.push_back(asset.name());
            }

            decodersData.assets.emplace(asset.name(), std::move(asset));
        }
    }

    // Only available for produccion
    if (!sandbox)
    {
        const auto defaultOutputs = cmStoreNsReader->getDefaultOutputs();
        auto& outputsData = builtAssets[cm::store::ResourceType::OUTPUT];

        for (const auto& output : defaultOutputs)
        {
            Asset asset = (*assetBuilder)(output);

            if (outputsData.assets.find(asset.name()) == outputsData.assets.end())
            {
                outputsData.orderedAssets.push_back(asset.name());
            }

            outputsData.assets.emplace(asset.name(), std::move(asset));
        }
    }

    return builtAssets;
}

Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName,
                                       const SubgraphData& assetsData,
                                       const std::unordered_map<base::Name, Asset>& filters)
{
    // 1. Add input node of the subgraph
    Graph<base::Name, Asset> subgraph {subgraphName, Asset {}};

    // 2. For each asset in the subgraph:
    for (const auto& name : assetsData.orderedAssets)
    {
        const auto it = assetsData.assets.find(name);
        const auto& asset = it->second;

        // 2.1. Add asset node
        subgraph.addNode(name, asset);

        // 2.2. If no parents, connect to input node
        if (asset.parents().empty())
        {
            subgraph.addEdge(subgraphName, name);
        }
        else
        {
            // 2.3. If parents, connect to each parent
            for (const auto& parent : asset.parents())
            {
                subgraph.addEdge(parent, name);
            }
        }
    }

    // 3. Add filters
    // 3.1. For each filter in the policy:
    for (const auto& [fName, fAsset] : filters)
    {
        for (const auto& parent : fAsset.parents())
        {
            // 3.1.1. If the parent is present in the subgraph, inject the filter between the asset and the
            // children
            if (subgraph.hasNode(parent))
            {
                subgraph.injectNode(fName, fAsset, parent);
            }
        }
    }

    // 4. Check integrity
    for (auto& [parent, children] : subgraph.edges())
    {
        if (!subgraph.hasNode(parent))
        {
            std::string childrenNames = "[";
            childrenNames +=
                std::accumulate(children.begin() + 1,
                                children.end(),
                                children.front().toStr(),
                                [](std::string acc, const auto& c) { return std::move(acc) + ", " + c.toStr(); });
            childrenNames += "]";
            throw std::runtime_error(fmt::format("Parent '{}' does not exist, required by {}", parent, childrenNames));
        }
        for (auto& child : children)
        {
            // TODO: this code is unreachable??
            // We declare always the child with the parent relationship
            // so the child should always exist
            if (!subgraph.hasNode(child))
            {
                throw std::runtime_error(fmt::format("Child '{}' does not exist, required by {}", child, parent));
            }
        }
    }

    return subgraph;
}

PolicyGraph buildGraph(const BuiltAssets& assets)
{
    PolicyGraph graph;

    // 1) Get filters
    const auto itFilters = assets.find(cm::store::ResourceType::FILTER);
    const auto filters =
        (itFilters == assets.end()) ? std::unordered_map<base::Name, Asset> {} : itFilters->second.assets;

    // 2) Build subgraphs for each type (except Filter)
    for (const auto& [rtype, data] : assets)
    {
        if ((rtype == cm::store::ResourceType::FILTER) || data.assets.empty())
        {
            continue;
        }

        const auto subgraphName = std::string(resourceTypeToString(rtype)) + GRAPH_INPUT_SUFFIX;
        auto subgraph = buildSubgraph(subgraphName, data, filters);
        graph.subgraphs.emplace(rtype, std::move(subgraph));
    }

    return graph;
}

base::Expression buildExpression(const PolicyGraph& graph, const std::string& name)
{
    // Expression of the policy, expression to be returned.
    // All subgraphs are added to this expression.
    std::shared_ptr<base::Operation> policy = base::Chain::create(name, {});

    // Generate the graph in the specified order
    for (const auto& [assetType, subgraph] : graph.subgraphs)
    {
        // Create subgraph expression
        base::Expression subgraphExpr;

        // Child operator depends on the asset type
        switch (assetType)
        {
            case cm::store::ResourceType::DECODER: subgraphExpr = buildSubgraphExpression<base::Or>(subgraph); break;
            case cm::store::ResourceType::RULE:
            case cm::store::ResourceType::OUTPUT:
                subgraphExpr = buildSubgraphExpression<base::Broadcast>(subgraph);
                break;
            default:
                // TODO: QoL
                throw std::runtime_error("Invalid asset type");
        }

        // Add subgraph expression to the policy expression
        policy->getOperands().emplace_back(subgraphExpr);
    }

    return policy;
}

} // namespace builder::policy::factory
