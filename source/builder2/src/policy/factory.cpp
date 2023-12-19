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
}

namespace builder::policy::factory
{

void addIntegrationSubgraph(PolicyData::AssetType assetType,
                            const std::string& path,
                            const store::Doc& integrationDoc,
                            const std::shared_ptr<store::IStoreReader>& store,
                            const base::Name& integrationName,
                            const store::NamespaceId& integrationNs,
                            PolicyData& data)
{
    // Get list of assets
    auto resp = integrationDoc.getArray(path);
    if (resp)
    {
        auto array = resp.value();
        for (const auto& jName : array)
        {
            // Get and validate the asset name
            auto assetNameStr = jName.getString();
            if (!assetNameStr)
            {
                throw std::runtime_error(fmt::format("Invalid not string entry in '{}' array for integration '{}'",
                                                     path,
                                                     integrationName));
            }

            base::Name assetName;
            try
            {
                assetName = base::Name(assetNameStr.value());
            }
            catch (const std::runtime_error& e)
            {
                throw std::runtime_error(fmt::format("Invalid asset name '{}' in integration '{}': {}",
                                                     assetNameStr.value(),
                                                     integrationName,
                                                     e.what()));
            }

            // Assert the asset name is the same type as the subgraph
            switch (assetType)
            {
                case PolicyData::AssetType::DECODER:
                    if (!syntax::name::isDecoder(assetName))
                    {
                        throw std::runtime_error(fmt::format("Asset '{}' in integration '{}' is not of type '{}'",
                                                             assetName.toStr(),
                                                             integrationName,
                                                             syntax::name::DECODER_PART));
                    }
                    break;
                case PolicyData::AssetType::RULE:
                    if (!syntax::name::isRule(assetName))
                    {
                        throw std::runtime_error(fmt::format("Asset '{}' in integration '{}' is not of type '{}'",
                                                             assetName.toStr(),
                                                             integrationName,
                                                             syntax::name::RULE_PART));
                    }
                    break;
                case PolicyData::AssetType::OUTPUT:
                    if (!syntax::name::isOutput(assetName))
                    {
                        throw std::runtime_error(fmt::format("Asset '{}' in integration '{}' is not of type '{}'",
                                                             assetName.toStr(),
                                                             integrationName,
                                                             syntax::name::OUTPUT_PART));
                    }
                    break;
                case PolicyData::AssetType::FILTER:
                    if (!syntax::name::isFilter(assetName))
                    {
                        throw std::runtime_error(fmt::format("Asset '{}' in integration '{}' is not of type '{}'",
                                                             assetName.toStr(),
                                                             integrationName,
                                                             syntax::name::FILTER_PART));
                    }
                    break;
            }

            // Get the asset namespace
            {
                auto resp = store->getNamespace(assetName);
                if (!resp)
                {
                    throw std::runtime_error(fmt::format("Could not find namespace for asset '{}'", assetName));
                }

                auto decoderNs = resp.value();
                if (decoderNs != integrationNs)
                {
                    throw std::runtime_error(fmt::format(
                        "Asset '{}' in integration '{}' is not in the same namespace", assetName, integrationName));
                }

                // Finally add the asset to the policy data
                bool added = data.add(assetType, decoderNs, assetName);
                if (!added)
                {
                    throw std::runtime_error(
                        fmt::format("Asset '{}' in integration '{}' is duplicated", assetName, integrationName));
                }
            }
        }
    }
}

void addIntegrationAssets(const store::NamespaceId& integrationNs,
                          const base::Name& name,
                          PolicyData& data,
                          const std::shared_ptr<store::IStoreReader>& store)
{
    // Get the integration assets
    store::Doc integrationDoc;
    {
        auto resp = store::utils::get(store, name);
        if (base::isError(resp))
        {
            throw std::runtime_error(fmt::format("Could not read document for integration '{}'", name));
        }

        integrationDoc = base::getResponse<store::Doc>(std::move(resp));
    }

    // Add the assets to the policy data
    if (!integrationDoc.isObject())
    {
        throw std::runtime_error(fmt::format("Integration '{}' document is not an object", name));
    }

    addIntegrationSubgraph(PolicyData::AssetType::DECODER,
                           syntax::integration::DECODER_PATH,
                           integrationDoc,
                           store,
                           name,
                           integrationNs,
                           data);
    addIntegrationSubgraph(
        PolicyData::AssetType::RULE, syntax::integration::RULE_PATH, integrationDoc, store, name, integrationNs, data);
    addIntegrationSubgraph(PolicyData::AssetType::OUTPUT,
                           syntax::integration::OUTPUT_PATH,
                           integrationDoc,
                           store,
                           name,
                           integrationNs,
                           data);
}

PolicyData readData(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store)
{
    PolicyData data;

    // Get name
    auto name = doc.getString(syntax::policy::PATH_NAME);
    if (!name)
    {
        throw std::runtime_error(
            fmt::format("Could not find policy name string attribute at '{}'", syntax::policy::PATH_NAME));
    }
    data.name() = base::Name(name.value());

    // Get hash
    auto hash = doc.getString(syntax::policy::PATH_HASH);
    if (!hash)
    {
        throw std::runtime_error(
            fmt::format("Could not find policy hash string attribute at '{}'", syntax::policy::PATH_HASH));
    }
    data.hash() = hash.value();
    if (data.hash().empty())
    {
        throw std::runtime_error(
            fmt::format("Policy hash string attribute at '{}' is empty", syntax::policy::PATH_HASH));
    }

    // Get default decoder parents
    auto defaultParents = doc.getObject(syntax::policy::PATH_PARENTS);
    if (defaultParents)
    {
        for (const auto& [ns, name] : defaultParents.value())
        {
            auto decoderStr = name.getString();
            if (!decoderStr)
            {
                throw std::runtime_error(fmt::format("Default parent decoder in namespace '{}' is not a string", ns));
            }
            base::Name decoderName;
            try
            {
                decoderName = base::Name(decoderStr.value());
            }
            catch (const std::runtime_error& e)
            {
                throw std::runtime_error(
                    fmt::format("Invalid default parent decoder name '{}': {}", decoderStr.value(), e.what()));
            }
            if (!syntax::name::isDecoder(decoderName))
            {
                throw std::runtime_error(
                    fmt::format("Default parent decoder '{}' in namespace '{}' is not a decoder", ns, decoderName));
            }

            auto added = data.addDefaultParent(PolicyData::AssetType::DECODER, ns, decoderName);
            if (!added)
            {
                throw std::runtime_error(fmt::format("Default parent decoder '{}' in namespace '{}' is duplicated",
                                                     ns,
                                                     decoderName));
            }
        }
    }

    // Get the assets
    auto assets = doc.getArray(syntax::policy::PATH_ASSETS);
    if (assets)
    {
        for (const auto& asset : assets.value())
        {
            auto assetNameStr = asset.getString();
            if (!assetNameStr)
            {
                throw std::runtime_error(
                    fmt::format("Invalid not string entry in '{}' array", syntax::policy::PATH_ASSETS));
            }

            base::Name assetName;
            try
            {
                assetName = base::Name(assetNameStr.value());
            }
            catch (const std::runtime_error& e)
            {
                throw std::runtime_error(fmt::format("Invalid asset name '{}': {}", assetNameStr.value(), e.what()));
            }

            // Obtain the namespace
            auto ns = store->getNamespace(assetName);
            if (!ns)
            {
                throw std::runtime_error(fmt::format("Could not find namespace for asset '{}'", assetName));
            }

            // Add the asset to the policy data of the correct type
            bool added;
            if (syntax::name::isDecoder(assetName))
            {
                added = data.add(PolicyData::AssetType::DECODER, ns.value(), assetName);
            }
            else if (syntax::name::isRule(assetName))
            {
                added = data.add(PolicyData::AssetType::RULE, ns.value(), assetName);
            }
            else if (syntax::name::isOutput(assetName))
            {
                added = data.add(PolicyData::AssetType::OUTPUT, ns.value(), assetName);
            }
            else if (syntax::name::isIntegration(assetName))
            {
                addIntegrationAssets(ns.value(), assetName, data, store);
                added = true;
            }
            else if (syntax::name::isFilter(assetName))
            {
                added = data.add(PolicyData::AssetType::FILTER, ns.value(), assetName);
            }
            else
            {
                throw std::runtime_error(fmt::format("Asset '{}' is not a {}, {} or {}",
                                                     assetName,
                                                     syntax::name::DECODER_PART,
                                                     syntax::name::RULE_PART,
                                                     syntax::name::OUTPUT_PART));
            }

            if (!added)
            {
                throw std::runtime_error(fmt::format("Asset '{}' is duplicated", assetName));
            }
        }
    }

    return data;
}

BuiltAssets buildAssets(const PolicyData& data,
                        const std::shared_ptr<store::IStoreReader> store,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder)
{
    BuiltAssets builtAssets;

    // Build assets for each type
    for (const auto& [assetType, subgraphData] : data.subgraphs())
    {
        for (const auto& [assetNs, assetNames] : subgraphData.assets)
        {
            for (const auto& assetName : assetNames)
            {
                // Get document
                auto resp = store::utils::get(store, assetName);
                if (base::isError(resp))
                {
                    throw std::runtime_error(fmt::format("Asset '{}' not found", assetName));
                }

                Asset asset = (*assetBuilder)(base::getResponse<store::Doc>(resp));

                // Add parents
                if (asset.parents().empty())
                {
                    auto defParentIt = subgraphData.defaultParents.find(assetNs);
                    if (defParentIt != subgraphData.defaultParents.end())
                    {
                        asset.parents().emplace_back(defParentIt->second);
                    }
                }

                // Add built asset to the subgraph
                if (builtAssets.find(assetType) == builtAssets.end())
                {
                    builtAssets.emplace(assetType, std::unordered_map<base::Name, Asset> {});
                }

                builtAssets[assetType].emplace(assetName, asset);
            }
        }
    }

    return builtAssets;
}

Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName,
                                       const SubgraphData& subgraphData,
                                       const SubgraphData& filtersData,
                                       const std::unordered_map<base::Name, Asset>& assets,
                                       const std::unordered_map<base::Name, Asset>& filters)
{
    // 1. Add input node of the subgraph
    Graph<base::Name, Asset> subgraph {subgraphName, Asset {}};

    // 2. For each asset in the subgraph:
    for (const auto& [ns, assetNames] : subgraphData.assets)
    {
        for (const auto& assetName : assetNames)
        {
            const auto& asset = assets.at(assetName);
            // 2.1. Add asset node
            subgraph.addNode(assetName, asset);

            // 2.2. If no parents, connect to input node
            if (asset.parents().empty())
            {
                subgraph.addEdge(subgraphName, assetName);
            }
            else
            {
                // 2.3. If parents, connect to each parent
                for (const auto& parent : asset.parents())
                {
                    subgraph.addEdge(parent, assetName);
                }
            }
        }

        // 3. Add filters
        // 3.1. For each filter in the policy:
        for (const auto& [ns, filterNames] : filtersData.assets)
        {
            for (const auto& filterName : filterNames)
            {
                for (const auto& parent : filters.at(filterName).parents())
                {
                    // 3.1.1. If the parent is present in the subgraph, inject the filter between the asset and the
                    // children
                    if (subgraph.hasNode(parent))
                    {
                        subgraph.injectNode(filterName, filters.at(filterName), parent);
                    }
                }
            }
        }

    }

    // 4. Check integrity
    for (auto& [parent, children] : subgraph.edges())
    {
        if (!subgraph.hasNode(parent))
        {
            auto childrenNames = std::string("[");
            childrenNames += std::accumulate(children.cbegin() + 1,
                                             children.cend(),
                                             children.front(),
                                             [](auto& acc, auto& child) { return acc.toStr() + ", " + child.toStr(); });
            childrenNames += "]";
            throw std::runtime_error(fmt::format("Parent '{}' does not exist, required by {}", parent, childrenNames));
        }
        // TODO: this code is unreachable??
        // We declare always the child with the parent relationship
        // so the child should always exist
        for (auto& child : children)
        {
            if (!subgraph.hasNode(child))
            {
                throw std::runtime_error(fmt::format("Child '{}' does not exist, required by {}", child, parent));
            }
        }
    }

    return subgraph;
}

PolicyGraph buildGraph(const BuiltAssets& assets, const PolicyData& data)
{
    PolicyGraph graph;
    // Filters are injected instead of added as subgraph
    auto filterIt = data.subgraphs().find(PolicyData::AssetType::FILTER);
    const auto& filtersData = filterIt == data.subgraphs().end() ? SubgraphData {} : filterIt->second;
    const auto& filtersAssets = assets.find(PolicyData::AssetType::FILTER) == assets.end()
                                    ? std::unordered_map<base::Name, Asset> {}
                                    : assets.at(PolicyData::AssetType::FILTER);

    // Build subgraph for each type
    for (const auto& [assetType, subgraphData] : data.subgraphs())
    {
        if (assetType == PolicyData::AssetType::FILTER || assets.empty())
        {
            continue;
        }
        auto subgraphName = base::Name(PolicyData::assetTypeStr(assetType)) + GRAPH_INPUT_SUFFIX;
        auto subgraph = buildSubgraph(subgraphName, subgraphData, filtersData, assets.at(assetType), filtersAssets);
        graph.subgraphs.emplace(assetType, std::move(subgraph));
    }

    return graph;
}

base::Expression buildExpression(const PolicyGraph& graph, const PolicyData& data)
{
    // Expression of the policy, expression to be returned.
    // All subgraphs are added to this expression.
    std::shared_ptr<base::Operation> policy = base::Chain::create(data.name(), {});

    // Generate the graph in the specified order
    for (const auto& [assetType, subgraph] : graph.subgraphs)
    {
        // Create subgraph expression
        base::Expression subgraphExpr;

        // Child operator depends on the asset type
        switch (assetType)
        {
            case PolicyData::AssetType::DECODER: subgraphExpr = buildSubgraphExpression<base::Or>(subgraph); break;
            case PolicyData::AssetType::RULE:
            case PolicyData::AssetType::OUTPUT:
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
