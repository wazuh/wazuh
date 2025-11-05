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
const base::Name G_FILTER_NAME {"filter/allow-all/0"}; ///< Filter that allows all events
} // namespace

namespace builder::policy::factory
{

BuiltAssets buildAssets(const cm::store::dataType::Policy& policy,
                        const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder)
{
    BuiltAssets builtAssets;

    // Build assets for decoder type
    for (const auto& integUUID : policy.getIntegrationsUUIDs())
    {
        const auto integration = cmStoreNsReader->getIntegrationByUUID(integUUID);
        // TODO: We would need to check the asset's JSON file to see if it's enabled.
        if (!integration.isEnabled())
        {
            continue;
        }

        assetBuilder->getContext().integrationName = integration.getName();
        assetBuilder->getContext().integrationCategory = integration.getCategory();

        for (const auto& decUUID : integration.getDecodersByUUID())
        {
            const auto decoder = cmStoreNsReader->getAssetByUUID(decUUID);
            Asset asset = (*assetBuilder)(decoder);
            const auto [name, resource] = cmStoreNsReader->resolveNameFromUUID(decUUID);
            const auto assetName = base::Name {name};

            //  If it is the RDD, do not assign any default parent.
            const auto isRootDefault = (assetName == policy.getRootDecoder());

            if (isRootDefault && !asset.parents().empty())
            {
                throw std::runtime_error(
                    fmt::format("Root default decoder '{}' must not have parents", assetName.toStr()));
            }

            // Add parents
            if (asset.parents().empty() && !isRootDefault)
            {
                const auto integrationDefaultParent = integration.getDefaultParent();
                if (integrationDefaultParent.has_value())
                {
                    asset.parents().emplace_back(integrationDefaultParent.value());
                }
                else
                {
                    asset.parents().emplace_back(policy.getDefaultParent());
                }
            }

            // Add built asset to the subgraph
            if (builtAssets.find(resource) == builtAssets.end())
            {
                builtAssets.emplace(resource, std::unordered_map<base::Name, Asset> {});
            }

            builtAssets[resource].emplace(assetName, asset);
        }
    }

    // filters
    {
        const auto& jsonAsset = cmStoreNsReader->getAssetByName(G_FILTER_NAME);
        Asset asset = (*assetBuilder)(jsonAsset);
        builtAssets[cm::store::ResourceType::FILTER].emplace(G_FILTER_NAME, asset);
    }

    return builtAssets;
}

Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName,
                                       const std::unordered_map<base::Name, Asset>& assets,
                                       const std::unordered_map<base::Name, Asset>& filters)
{
    // 1. Add input node of the subgraph
    Graph<base::Name, Asset> subgraph {subgraphName, Asset {}};

    // 2. For each asset in the subgraph:
    for (const auto& [name, asset] : assets)
    {
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
    const auto filters = (itFilters == assets.end()) ? std::unordered_map<base::Name, Asset> {} : itFilters->second;

    // 2) Build subgraphs for each type (except Filter)
    for (const auto& [rtype, typedAssets] : assets)
    {
        if ((rtype == cm::store::ResourceType::FILTER) || (typedAssets.empty()))
        {
            continue;
        }

        const auto subgraphName = std::string(resourceTypeToString(rtype)) + GRAPH_INPUT_SUFFIX;
        auto subgraph = buildSubgraph(subgraphName, typedAssets, filters);
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
