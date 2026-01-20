#include "policy/factory.hpp"

#include <numeric> // std::accumulate
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include <store/utils.hpp>

#include "asset.hpp"
#include "syntax.hpp"

namespace
{
auto constexpr GRAPH_INPUT_SUFFIX = "/Input";

/**
 * @brief Build a map of KVDB names to their enabled status for the given integration.
 *
 * @param integration Integration where the aviable KVDBs are defined
 * @param cmStoreNsReader CMStore namespace reader to load the KVDBs status and ensure they exist
 * @param integUUID Integration UUID (for error messages)
 * @return std::unordered_map<std::string, bool> Map of KVDB names to their enabled status
 * @throw std::runtime_error if any KVDB UUID does not exist or if there are duplicate KVDB names
 */
std::unordered_map<std::string, bool> buildKvdbsMap(const cm::store::dataType::Integration& integration,
                                                    const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                                                    const std::string& integUUID)
{
    const auto& kvdbUUIDs = integration.getKVDBsByUUID();

    return [&]() -> std::unordered_map<std::string, bool>
    {
        std::unordered_map<std::string, bool> result;
        result.reserve(kvdbUUIDs.size());

        for (const auto& kvdbUUID : kvdbUUIDs)
        {
            try
            {
                const auto kvdb = cmStoreNsReader->getKVDBByUUID(kvdbUUID);
                const auto& kvdbName = kvdb.getName();
                const bool kvdbEnabled = kvdb.isEnabled();

                const auto [it, inserted] = result.emplace(kvdbName, kvdbEnabled);
                if (!inserted)
                {
                    throw std::runtime_error(
                        fmt::format("Duplicate KVDB title '{}' in integration '{}'. KVDB titles must be unique within "
                                    "an integration.",
                                    kvdbName,
                                    integration.getName()));
                }
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format(
                    "Failed to load KVDB with UUID '{}' from integration '{}': {}", kvdbUUID, integUUID, e.what()));
            }
        }

        return result;
    }();
}

} // namespace

namespace builder::policy::factory
{

BuiltAssets buildAssets(const cm::store::dataType::Policy& policy,
                        const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder,
                        const bool sandbox)
{
    BuiltAssets builtAssets;

    const auto rootDecoderName =
        base::Name {std::get<0>(cmStoreNsReader->resolveNameFromUUID(policy.getRootDecoder()))};

    // NOTE: The order of integrations and their decoders defines the final evaluation order for
    // sibling decoders in the expression. We preserve insertion order via orderedAssets.
    for (const auto& integUUID : policy.getIntegrationsUUIDs())
    {
        const auto integration = cmStoreNsReader->getIntegrationByUUID(integUUID);
        if (!integration.isEnabled())
        {
            continue;
        }

        // Configure partial build context for the integration.
        assetBuilder->getContext().integrationName = integration.getName();
        assetBuilder->getContext().integrationCategory = integration.getCategory();
        // Set availability map in the build context (integration-scoped).
        assetBuilder->setAvailableKvdbs(buildKvdbsMap(integration, cmStoreNsReader, integUUID));

        // Decoder order inside the integration is preserved to keep deterministic evaluation.
        for (const auto& decUUID : integration.getDecodersByUUID())
        {
            const auto decoder = cmStoreNsReader->getAssetByUUID(decUUID);
            auto assetName = decoder.getString(json::Json::formatJsonPath(builder::syntax::asset::NAME_KEY));
            if (!decoder.getBool(json::Json::formatJsonPath(builder::syntax::asset::ENABLED_KEY)).value_or(false))
            {
                continue;
            }

            Asset asset;
            try
            {
                asset = (*assetBuilder)(decoder);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("Error building decoder {} from integration '{}': {}",
                                                     assetName.value(),
                                                     integration.getName(),
                                                     e.what()));
            }

            // The root decoder cannot have parents (Avoid cycles)
            const auto isRootDecoder = (asset.name() == rootDecoderName);
            const auto hasParents = !asset.parents().empty();

            if (isRootDecoder && hasParents)
            {
                throw std::runtime_error(
                    fmt::format("The root decoder '{}' cannot have parents", rootDecoderName.toStr()));
            }

            // Add parent if no parents defined, the priority order is:
            // local asset parent > integration default parent > policy root decoder
            if (!isRootDecoder && !hasParents)
            {
                auto defaultParentUUID = [&]() -> std::string
                {
                    if (integration.hasDefaultParent())

                    {
                        return integration.getDefaultParent().value_or("Error getting default parent");
                    }

                    return policy.getRootDecoder();
                }();

                asset.parents().emplace_back(
                    std::move(std::get<0>(cmStoreNsReader->resolveNameFromUUID(defaultParentUUID))));
            }

            // Store built asset
            auto& decodersData = builtAssets[cm::store::ResourceType::DECODER];
            if (decodersData.assets.find(asset.name()) == decodersData.assets.end())
            {
                // orderedAssets preserves the first-seen order across integrations.
                decodersData.orderedAssets.push_back(asset.name());
            }

            decodersData.assets.emplace(asset.name(), std::move(asset));
        }

        for (const auto& outUUID : integration.getOutputsByUUID())
        {
            const auto output = cmStoreNsReader->getAssetByUUID(outUUID);
            auto assetName = output.getString(json::Json::formatJsonPath(builder::syntax::asset::NAME_KEY));
            if (!output.getBool(json::Json::formatJsonPath(builder::syntax::asset::ENABLED_KEY)).value_or(false))
            {
                continue;
            }

            Asset asset;
            try
            {
                asset = (*assetBuilder)(output);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("Error building output {} from integration '{}': {}",
                                                     assetName.value(),
                                                     integration.getName(),
                                                     e.what()));
            }

            auto& outputsData = builtAssets[cm::store::ResourceType::OUTPUT];
            if (outputsData.assets.find(asset.name()) == outputsData.assets.end())
            {
                outputsData.orderedAssets.push_back(asset.name());
            }

            outputsData.assets.emplace(asset.name(), std::move(asset));
        }
    }

    // Only available for production
    if (!sandbox)
    {
        // Default outputs are not associated with an integration; clear KVDB validation.
        assetBuilder->clearAvailableKvdbs();

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

Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName, const SubgraphData& assetsData)
{
    // 1. Add input node of the subgraph
    Graph<base::Name, Asset> subgraph {subgraphName, Asset {}};

    // 2. For each asset in the subgraph:
    // orderedAssets preserves the insertion order that defines sibling evaluation.
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
                // Edge insertion order is preserved in Graph children vectors.
                subgraph.addEdge(parent, name);
            }
        }
    }

    // 3. Check integrity
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

    // Build subgraphs for each type (except Filter)
    for (const auto& [rtype, data] : assets)
    {
        if ((rtype == cm::store::ResourceType::FILTER) || data.assets.empty())
        {
            continue;
        }

        const auto subgraphName = std::string(resourceTypeToString(rtype)) + GRAPH_INPUT_SUFFIX;
        auto subgraph = buildSubgraph(subgraphName, data);
        subgraph.validateAcyclic(std::string(resourceTypeToString(rtype)));
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
