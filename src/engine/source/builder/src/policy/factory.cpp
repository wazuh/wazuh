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

    // Helper to check if an asset is already built in that graph
    const auto isAlreadyBuilt = [&](const std::string& name, AssetPipelineStage stage) -> bool
    {
        const auto& subgraphData = builtAssets.find(stage);
        if (subgraphData == builtAssets.end())
        {
            return false;
        }
        return subgraphData->second.assets.find(base::Name(name)) != subgraphData->second.assets.end();
    };

    // Helper to build and store an asset in the pipeline
    const auto buildAndStoreAsset = [&](const auto& assetData,
                                        const std::string& assetUUID,
                                        AssetPipelineStage stage,
                                        const std::string& assetType,
                                        const std::string& contextInfo = "") -> void
    {
        auto assetName = syntax::asset::getAssetName(assetData);

        if (!syntax::asset::isEnabledResource(assetData))
        {
            return;
        }

        // Check for duplicates
        if (isAlreadyBuilt(assetName, stage))
        {
            throw std::runtime_error(
                fmt::format("{} '{}' [id: '{}'] is duplicated{}", assetType, assetName, assetUUID, contextInfo));
        }

        // Build asset
        Asset asset;
        try
        {
            asset = (*assetBuilder)(assetData);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Error building {} {}{}: {}", assetType, assetName, contextInfo, e.what()));
        }

        // Store asset
        auto& stageData = builtAssets[stage];
        stageData.orderedAssets.push_back(asset.name());
        stageData.assets.emplace(asset.name(), std::move(asset));
    };

    const base::Name rootDecoderName {std::get<0>(cmStoreNsReader->resolveNameFromUUID(policy.getRootDecoderUUID()))};

    // NOTE: The order of integrations and their decoders defines the final evaluation order for
    // sibling decoders in the expression. We preserve insertion order via orderedAssets.
    for (const auto& integUUID : policy.getIntegrationsUUIDs())
    {
        const auto integration = cmStoreNsReader->getIntegrationByUUID(integUUID);
        if (!integration.isEnabled())
        {
            continue;
        }

        // TODO: Only decoder should have the integration context
        // TODO: The context integration should has the aviable KVDBs for validation
        // Configure partial build context for the integration.
        assetBuilder->getContext().integrationName = integration.getName();
        assetBuilder->getContext().integrationCategory = integration.getCategory();
        // Set availability map in the build context (integration-scoped).
        assetBuilder->setAvailableKvdbs(buildKvdbsMap(integration, cmStoreNsReader, integUUID));

        // Decoder order inside the integration is preserved to keep deterministic evaluation.
        for (const auto& decUUID : integration.getDecodersByUUID())
        {
            const auto decoder = cmStoreNsReader->getAssetByUUID(decUUID);
            auto assetName = syntax::asset::getAssetName(decoder);

            if (!syntax::asset::isEnabledResource(decoder))
            {
                continue;
            }

            // Check if asset was already built (by previous integration)
            if (isAlreadyBuilt(assetName, AssetPipelineStage::DECODERS_TREE))
            {
                throw std::runtime_error(fmt::format("Decoder '{}' [id: '{}'] from integration '{}' [id: '{}'] was "
                                                     "already defined by another integration",
                                                     assetName,
                                                     decUUID,
                                                     integration.getName(),
                                                     integUUID));
            }

            Asset asset;
            try
            {
                asset = (*assetBuilder)(decoder);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format(
                    "Error building decoder {} from integration '{}': {}", assetName, integration.getName(), e.what()));
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
                    return policy.getRootDecoderUUID();
                }();

                asset.parents().emplace_back(
                    std::move(std::get<0>(cmStoreNsReader->resolveNameFromUUID(defaultParentUUID))));
            }

            // Store built asset
            auto& decodersData = builtAssets[AssetPipelineStage::DECODERS_TREE];
            decodersData.orderedAssets.push_back(asset.name());
            decodersData.assets.emplace(asset.name(), std::move(asset));
        }
    }

    // TODO: Should clear all integration related context
    assetBuilder->clearAvailableKvdbs();

    // Filters
    for (const auto& filterUUID : policy.getFiltersUUIDs())
    {
        const auto filter = cmStoreNsReader->getAssetByUUID(filterUUID);

        const auto pipelineStage = [&]() -> AssetPipelineStage
        {
            auto filterType = syntax::asset::filter::getFilterType(filter);
            return (filterType == syntax::asset::filter::FilterType::PRE_FILTER)
                       ? AssetPipelineStage::PRE_FILTERS_TREE
                       : AssetPipelineStage::POST_FILTERS_TREE;
        }();

        buildAndStoreAsset(filter, filterUUID, pipelineStage, "Filter");
    }

    // Outputs
    for (const auto& outUUID : policy.getOutputsUUIDs())
    {
        const auto output = cmStoreNsReader->getAssetByUUID(outUUID);
        buildAndStoreAsset(output, outUUID, AssetPipelineStage::OUTPUTS_TREE, "Output");
    }

    // TODO: Only available for production -->> Remove this, outputs should always be associated with a policy
    if (!sandbox)
    {
        // Default outputs are not associated with an integration; clear KVDB validation.
        assetBuilder->clearAvailableKvdbs();

        const auto defaultOutputs = cmStoreNsReader->getDefaultOutputs();
        for (const auto& output : defaultOutputs)
        {
            buildAndStoreAsset(output, "", AssetPipelineStage::OUTPUTS_TREE, "Output");
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
    graph.subgraphs.reserve(assets.size());

    // Build subgraphs for each type (except Filter)
    for (const auto& [rtype, data] : assets)
    {
        if (data.assets.empty())
        {
            continue;
        }

        const auto subgraphName = std::string(AssetPipelineStageToStr(rtype)) + GRAPH_INPUT_SUFFIX;
        auto subgraph = buildSubgraph(subgraphName, data);
        subgraph.validateAcyclic(std::string(AssetPipelineStageToStr(rtype)));
        graph.subgraphs.emplace(rtype, std::move(subgraph));
    }

    return graph;
}

base::Expression buildExpression(const PolicyGraph& graph,
                                 const base::Expression& preEnrichmentExpression,
                                 const base::Expression& enrichmentExpression)
{

    // Phase 1: Pre filters implies Decoders tree
    // This phase only fails on runtime if there are filter stage and this phase fails.
    // If not, decodes are executed successfully and passed to the next phase.
    auto phase1 = [&]() -> std::shared_ptr<base::Operation>
    {
        auto decodersExpr = [&]() -> base::Expression
        {
            // Build decoders stage first
            if (graph.subgraphs.find(AssetPipelineStage::DECODERS_TREE) == graph.subgraphs.end())
            {
                throw std::runtime_error("Policy must have at least a decoders");
            }
            const auto& decodersTree = graph.subgraphs.at(AssetPipelineStage::DECODERS_TREE);
            // The decoders are 'OR' between siblings
            return buildSubgraphExpression<base::Or>(decodersTree);
        }();

        auto preFiltersExpr = [&]() -> std::optional<base::Expression>
        {
            // If pre-filters are present, build them
            if (graph.subgraphs.find(AssetPipelineStage::PRE_FILTERS_TREE) != graph.subgraphs.end())
            {
                const auto& preFiltersTree = graph.subgraphs.at(AssetPipelineStage::PRE_FILTERS_TREE);
                // The pre-filters are 'OR' between siblings
                return buildSubgraphExpression<base::Or>(preFiltersTree);
            }
            return std::nullopt;
        }();

        // If pre-filters are present, they imply decoders, if not, just decoders
        if (preFiltersExpr.has_value())
        {
            return base::Implication::create("Phase1_PreFilters", preFiltersExpr.value(), decodersExpr);
        }
        return base::Chain::create("Phase1_Decoders", {decodersExpr});
    }();

    // Phase 3: Post filters implies Outputs tree (Outpus and filters and optionals)
    auto phase3 = [&]() -> std::optional<base::Expression>
    {
        auto outputsExpr = [&]() -> std::optional<base::Expression>
        {
            // If no outputs, skip phase 3
            if (graph.subgraphs.find(AssetPipelineStage::OUTPUTS_TREE) == graph.subgraphs.end())
            {
                return std::nullopt;
            }
            // Build outputs stage
            const auto& outputsTree = graph.subgraphs.at(AssetPipelineStage::OUTPUTS_TREE);
            // The outputs are 'Broadcast' between siblings
            return buildSubgraphExpression<base::Broadcast>(outputsTree);
        }();

        auto postFiltersExpr = [&]() -> std::optional<base::Expression>
        {
            // If post-filters are present, build them
            if (graph.subgraphs.find(AssetPipelineStage::POST_FILTERS_TREE) != graph.subgraphs.end())
            {
                const auto& postFiltersTree = graph.subgraphs.at(AssetPipelineStage::POST_FILTERS_TREE);
                // The post-filters are 'OR' between siblings
                return buildSubgraphExpression<base::Or>(postFiltersTree);
            }
            return std::nullopt;
        }();

        // If post-filters are present, they imply outputs, if not, just outputs
        if (postFiltersExpr.has_value() && outputsExpr.has_value())
        {
            return base::Implication::create("Phase3_PostFilters", postFiltersExpr.value(), outputsExpr.value());
        }
        else if (outputsExpr.has_value())
        {
            return outputsExpr;
        }
        else if (postFiltersExpr.has_value())
        {
            // Only for checking trace in Tester module (logetst)
            return postFiltersExpr;
        }
        return std::nullopt;
    }();

    // Phase 1 only fails if pre-filters fail, phase 3 only fails if post-filters fail.
    if (phase3.has_value())
    {
        return base::And::create(graph.graphName,
                                 {phase1, preEnrichmentExpression, enrichmentExpression, phase3.value()});
    }
    return base::And::create(graph.graphName, {phase1, preEnrichmentExpression, enrichmentExpression});
}

} // namespace builder::policy::factory
