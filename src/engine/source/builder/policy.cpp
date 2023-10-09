#include "policy.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <store/utils.hpp>

#include "syntax.hpp"

namespace
{
using namespace builder;

Asset::Type getAssetType(const std::string& name)
{
    if (internals::syntax::INTEGRATION_DECODERS == name)
    {
        return Asset::Type::DECODER;
    }
    else if (internals::syntax::INTEGRATION_RULES == name)
    {
        return Asset::Type::RULE;
    }
    else if (internals::syntax::INTEGRATION_OUTPUTS == name)
    {
        return Asset::Type::OUTPUT;
    }
    else if (internals::syntax::INTEGRATION_FILTERS == name)
    {
        return Asset::Type::FILTER;
    }
    else
    {
        throw std::runtime_error(fmt::format("Engine policy: Unknown type of asset \"{}\".", name));
    }
}
} // namespace

std::unordered_map<Asset::Type, std::vector<std::shared_ptr<Asset>>>
Policy::getManifestAssets(const json::Json& jsonDefinition,
                          std::shared_ptr<const store::IStoreReader> storeRead,
                          std::shared_ptr<internals::Registry<internals::Builder>> registry)
{
    if (!jsonDefinition.isObject())
    {
        throw std::runtime_error("Manifest is not an object");
    }

    auto manifestObj = jsonDefinition.getObject().value();

    // Get name
    auto nameIt = std::find_if(
        manifestObj.begin(), manifestObj.end(), [](const auto& tuple) { return std::get<0>(tuple) == "name"; });
    if (nameIt == manifestObj.end())
    {
        throw std::runtime_error("Manifest name is missing");
    }
    auto nameOpt = std::get<1>(*nameIt).getString();
    if (!nameOpt)
    {
        throw std::runtime_error("Manifest name is not a string");
    }

    manifestObj.erase(nameIt);

    std::unordered_map<Asset::Type, std::vector<std::shared_ptr<Asset>>> assets;

    for (auto& [key, value] : manifestObj)
    {
        if (key == internals::syntax::INTEGRATION_DECODERS || key == internals::syntax::INTEGRATION_RULES
            || key == internals::syntax::INTEGRATION_OUTPUTS || key == internals::syntax::INTEGRATION_FILTERS)
        {
            if (!value.isArray())
            {
                throw std::runtime_error(fmt::format(R"(Manifest "{}" is not an array)", key));
            }

            auto assetNames = value.getArray().value();
            std::vector<std::shared_ptr<Asset>> assetList;
            auto assetType = getAssetType(key);

            std::transform(assetNames.begin(),
                           assetNames.end(),
                           std::back_inserter(assetList),
                           [&](const auto& assetName)
                           {
                               auto name = assetName.getString();
                               if (!name)
                               {
                                   throw std::runtime_error("Asset name is not a string");
                               }

                               auto assetDef = store::utils::get(storeRead, name.value());
                               if (std::holds_alternative<base::Error>(assetDef))
                               {
                                   throw std::runtime_error(std::get<base::Error>(assetDef).message);
                               }

                               auto asset =
                                   std::make_shared<Asset>(std::get<json::Json>(assetDef), assetType, registry);

                               return asset;
                           });

            assets[assetType] = assetList;
        }
    }

    return assets;
}

namespace builder
{

void Policy::buildGraph(const std::string& graphName, const std::unordered_set<base::Name>& assets, Asset::Type type)
{
    // 1. Add input node of the subgraph
    auto inputName = graphName + "Input";
    // Creates a dummy Asset with the name of the input node, to be transformed later into a expression
    Subgraph graph {inputName, std::make_shared<Asset>(inputName, type)};

    // 2. For each asset in the set:
    for (auto& asset : assets)
    {
        // 2.1. Add asset node
        auto assetPtr = m_assets.at(asset);
        graph.addNode(asset, assetPtr);

        // 2.2. If no parents, connect to input node
        if (assetPtr->m_parents.empty())
        {
            graph.addEdge(inputName, asset);
        }
        else
        {
            // 2.3. If parents, connect to each parent
            for (auto& parent : assetPtr->m_parents)
            {
                graph.addEdge(parent, asset);
            }
        }
    }

    // 3. Add filters
    // 3.1. For each filter in the policy:
    for (auto& [name, asset] : m_assets)
    {
        if (asset->m_type == Asset::Type::FILTER)
        {
            // 3.1.1. If the parent is present in the subgraph, inject the filter between the asset and the children
            for (auto& parent : asset->m_parents)
            {
                if (graph.hasNode(parent))
                {
                    graph.injectNode(name, asset, parent);
                }
            }
        }
    }

    // 4. Check integrity
    for (auto& [parent, children] : graph.edges())
    {
        if (!graph.hasNode(parent))
        {
            auto childrenNames = std::string("[");
            childrenNames += std::accumulate(children.cbegin() + 1,
                                             children.cend(),
                                             children.front().toStr(),
                                             [](auto& acc, auto& child) { return acc + ", " + child.toStr(); });
            childrenNames += "]";
            throw std::runtime_error(
                fmt::format("Parent '{}' does not exist, required by {}", parent.toStr(), childrenNames));
        }
        for (auto& child : children)
        {
            if (!graph.hasNode(child))
            {
                throw std::runtime_error(
                    fmt::format("Child '{}' does not exist, required by {}", child.toStr(), parent.toStr()));
            }
        }
    }

    // Finally, add the subgraph to the policy
    insertGraph(graphName, std::move(graph));
}

std::unordered_set<base::Name> Policy::assets() const
{
    std::unordered_set<base::Name> assets;
    std::transform(m_assets.cbegin(),
                   m_assets.cend(),
                   std::inserter(assets, assets.begin()),
                   [](const auto& pair) { return pair.first; });
    return assets;
}

base::Expression Policy::expression() const
{
    // Expression of the policy, expression to be returned.
    // All subgraphs are added to this expression.
    std::shared_ptr<base::Operation> policy = base::Chain::create(m_name, {});

    // Generate the graph in order decoders->rules->outputs
    for (auto& [graphName, graph] : m_graphs)
    {
        // Create root subgraph expression
        std::shared_ptr<base::Operation> inputExpression;
        switch (graph.node(graph.rootId())->m_type)
        {
            case Asset::Type::DECODER:
                inputExpression = base::Or::create(graph.node(graph.rootId())->m_name, {});
                break;
            case Asset::Type::RULE:
            case Asset::Type::OUTPUT:
                inputExpression = base::Broadcast::create(graph.node(graph.rootId())->m_name, {});
                break;
            default:
                throw std::runtime_error(fmt::format("Building policy \"{}\" failed as the type of the "
                                                     "asset \"{}\" is not supported",
                                                     graphName,
                                                     graph.node(graph.rootId())->m_name));
        }
        // Add input Expression to policy expression
        policy->getOperands().push_back(inputExpression);

        // Build rest of the graph

        // Avoid duplicating nodes when multiple
        // parents has the same child node
        std::map<std::string, base::Expression> builtNodes;

        // parentNode Expression is passed as filters need it.
        auto visit = [&](const std::string& current, const std::string& parent, auto& visitRef) -> base::Expression
        {
            // If node is already built, return it
            if (builtNodes.find(current) != builtNodes.end())
            {
                return builtNodes[current];
            }
            else
            {
                // Create node
                // If node has children, create an auxiliary Implication node, with
                // asset as condition and children as consequence, otherwise create an
                // asset node.
                auto asset = graph.node(current);
                std::shared_ptr<base::Operation> assetNode;

                if (graph.hasChildren(current))
                {
                    std::shared_ptr<base::Operation> assetChildren;

                    // Children expression depends on the type of the asset
                    auto type = asset->m_type;

                    // If Filter type is the same as the parent
                    if (type == Asset::Type::FILTER)
                    {
                        type = m_assets.at(parent)->m_type;
                    }

                    switch (type)
                    {
                        case Asset::Type::DECODER: assetChildren = base::Or::create("children", {}); break;
                        case Asset::Type::RULE:
                        case Asset::Type::OUTPUT: assetChildren = base::Broadcast::create("children", {}); break;

                        default:
                            throw std::runtime_error(
                                fmt::format("Asset type not supported from asset \"{}\"", current));
                    }

                    assetNode =
                        base::Implication::create(asset->m_name + "Node", asset->getExpression(), assetChildren);

                    // Visit children and add them to the children node
                    for (auto& child : graph.children(current))
                    {
                        assetChildren->getOperands().push_back(visitRef(child, current, visitRef));
                    }
                }
                else
                {
                    // No children
                    assetNode = asset->getExpression()->getPtr<base::Operation>();
                }

                // Add it to builtNodes
                if (asset->m_parents.size() > 1)
                {
                    builtNodes.insert(std::make_pair(current, assetNode));
                }

                return assetNode;
            }
        };

        // Visit root childs and add them to the root expression
        for (auto& child : graph.children(graph.rootId()))
        {
            inputExpression->getOperands().push_back(visit(child, graph.rootId(), visit));
        }
    }

    return policy;
}

Policy::Policy(const json::Json& jsonDefinition,
               std::shared_ptr<const store::IStore> store,
               std::shared_ptr<internals::Registry<internals::Builder>> registry)
{
    // Get name
    auto nameOpt = jsonDefinition.getString("/name");
    if (!nameOpt)
    {
        if (jsonDefinition.exists("/name"))
        {
            throw std::runtime_error("Policy /name is not a string");
        }
        else
        {
            throw std::runtime_error("Policy /name is not defined");
        }
    }
    m_name = nameOpt.value();

    // Get hash
    auto hashOpt = jsonDefinition.getString("/hash");
    if (hashOpt)
    {
        m_hash = hashOpt.value();
    }
    else
    {
        throw std::runtime_error("Policy /hash not defined or not a string");
    }

    // Get default parents
    auto defaultParentsOpt = jsonDefinition.getObject("/default_parents");
    std::unordered_map<store::NamespaceId, base::Name> defaultParents;
    if (defaultParentsOpt)
    {
        for (const auto& [nsId, asset] : defaultParentsOpt.value())
        {
            defaultParents.emplace(store::NamespaceId {nsId}, base::Name {asset.getString().value()});
        }
    }

    // Load assets
    std::unordered_map<Asset::Type, std::unordered_set<base::Name>> assetsByType;
    std::unordered_set<base::Name> integrations;

    auto assetsOpt = jsonDefinition.getArray("/assets");
    if (assetsOpt)
    {
        for (auto& jAssetName : assetsOpt.value())
        {
            if (!jAssetName.isString())
            {
                throw std::runtime_error("Asset name is not a string");
            }

            auto assetDef = store::utils::get(store, jAssetName.getString().value());
            if (base::isError(assetDef))
            {
                throw std::runtime_error(base::getError(assetDef).message);
            }

            auto assetName = base::Name {jAssetName.getString().value()};
            if (internals::syntax::isIntegration(assetName))
            {
                integrations.insert(assetName);
            }
            else
            {
                auto type = [&]()
                {
                    if (internals::syntax::isDecoder(assetName))
                    {
                        return Asset::Type::DECODER;
                    }
                    else if (internals::syntax::isRule(assetName))
                    {
                        return Asset::Type::RULE;
                    }
                    else if (internals::syntax::isOutput(assetName))
                    {
                        return Asset::Type::OUTPUT;
                    }
                    else if (internals::syntax::isFilter(assetName))
                    {
                        return Asset::Type::FILTER;
                    }
                    else
                    {
                        throw std::runtime_error(fmt::format("Asset type '{}' unknown", assetName.parts().front()));
                    }
                }();

                auto asset = std::make_shared<Asset>(base::getResponse<store::Doc>(assetDef), type, registry);
                // Add default parent only for decoders
                if (type == Asset::Type::DECODER && asset->m_parents.empty())
                {
                    auto nsId = store->getNamespace(assetName);
                    if (nsId && defaultParents.find(nsId.value()) != defaultParents.end())
                    {
                        asset->m_parents.emplace(defaultParents.at(nsId.value()));
                    }
                }
                else if (type == Asset::Type::FILTER && asset->m_parents.empty())
                {
                    throw std::runtime_error(fmt::format("Filter '{}' does not have any parent", assetName));
                }

                auto key = internals::syntax::getIntegrationSection(assetName);

                // Keep track of the assets by type, to build the graphs
                assetsByType[type].insert(assetName);

                // Add asset to the policy
                m_assets.insert(std::make_pair(assetName, asset));
            }
        }
    }

    // Merge all assets of the integrations if any
    for (auto& name : integrations)
    {
        auto integrationDef = store::utils::get(store, name);
        if (base::isError(integrationDef))
        {
            throw std::runtime_error(base::getError(integrationDef).message);
        }
        auto integrationAssets = getManifestAssets(base::getResponse<store::Doc>(integrationDef), store, registry);
        for (auto& [itype, iassets] : integrationAssets)
        {
            for (auto& iasset : iassets)
            {
                // Add default parent only for decoders
                if (itype == Asset::Type::DECODER && iasset->m_parents.empty())
                {
                    auto nsId = store->getNamespace(iasset->m_name);
                    if (nsId && defaultParents.find(nsId.value()) != defaultParents.end())
                    {
                        iasset->m_parents.emplace(defaultParents.at(nsId.value()));
                    }
                }
                else if (itype == Asset::Type::FILTER && iasset->m_parents.empty())
                {
                    throw std::runtime_error(fmt::format("Filter '{}' does not have any parent", iasset->m_name));
                }

                m_assets.insert(std::make_pair(iasset->m_name, iasset));
                assetsByType[itype].insert(iasset->m_name);
            }
        }
    }

    // Check orphan filters
    for (auto& [name, asset] : m_assets)
    {
        if (asset->m_type == Asset::Type::FILTER)
        {
            for (auto& parent : asset->m_parents)
            {
                if (m_assets.find(parent) == m_assets.end())
                {
                    throw std::runtime_error(fmt::format("Parent '{}' of filter '{}' does not exist", parent, name));
                }
            }
        }
    }

    // Build graphs in order
    // Decoders -> Rules -> Outputs
    if (assetsByType.find(Asset::Type::DECODER) != assetsByType.end())
    {
        buildGraph(
            Asset::typeToString(Asset::Type::DECODER), assetsByType.at(Asset::Type::DECODER), Asset::Type::DECODER);
    }
    if (assetsByType.find(Asset::Type::RULE) != assetsByType.end())
    {
        buildGraph(Asset::typeToString(Asset::Type::RULE), assetsByType.at(Asset::Type::RULE), Asset::Type::RULE);
    }
    if (assetsByType.find(Asset::Type::OUTPUT) != assetsByType.end())
    {
        buildGraph(Asset::typeToString(Asset::Type::OUTPUT), assetsByType.at(Asset::Type::OUTPUT), Asset::Type::OUTPUT);
    }
}

std::string Policy::getGraphivzStr() const
{
    std::stringstream ss;
    ss << "digraph G {" << std::endl;
    ss << "compound=true;" << std::endl;
    ss << fmt::format("fontname=\"Helvetica,Arial,sans-serif\";") << std::endl;
    ss << fmt::format("fontsize=12;") << std::endl;
    ss << fmt::format("node [fontname=\"Helvetica,Arial,sans-serif\", "
                      "fontsize=10];")
       << std::endl;
    ss << fmt::format("edge [fontname=\"Helvetica,Arial,sans-serif\", "
                      "fontsize=8];")
       << std::endl;
    ss << "environment [label=\"" << m_name << "\", shape=Mdiamond];" << std::endl;

    auto removeHyphen = [](const std::string& text)
    {
        auto ret = text;
        auto pos = ret.find("-");
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find("-");
        }

        pos = ret.find("/");
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find("/");
        }

        return ret;
    };

    for (auto& [name, graph] : m_graphs)
    {
        ss << std::endl;
        ss << "subgraph cluster_" << name << " {" << std::endl;
        ss << "label=\"" << name << "\";" << std::endl;
        ss << "style=filled;" << std::endl;
        ss << "color=lightgrey;" << std::endl;
        ss << fmt::format("node [style=filled,color=white];") << std::endl;
        for (auto& [name, asset] : graph.nodes())
        {
            ss << removeHyphen(name) << " [label=\"" << name << "\"];" << std::endl;
        }
        for (auto& [parent, children] : graph.edges())
        {
            for (auto& child : children)
            {
                ss << removeHyphen(parent) << " -> " << removeHyphen(child) << ";" << std::endl;
            }
        }
        ss << "}" << std::endl;
        ss << "environment -> " << name << "Input;" << std::endl;
    }
    ss << "}\n";
    return ss.str();
}

const std::string& Policy::hash() const
{
    return m_hash;
}
} // namespace builder
