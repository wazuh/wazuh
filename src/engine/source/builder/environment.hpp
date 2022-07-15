#ifndef _ENVIRONMENT_H
#define _ENVIRONMENT_H

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include "asset.hpp"
#include "expression.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "registry.hpp"

namespace builder
{

constexpr const char* const DECODERS = "decoders";
constexpr const char* const RULES = "rules";
constexpr const char* const OUTPUTS = "outputs";
constexpr const char* const FILTERS = "filters";

/**
 * @brief Get the Asset Type object from the string
 *
 * @param name
 * @return Asset::Type
 * @throws std::runtime_error if the name is not supported
 */
static Asset::Type getAssetType(const std::string& name)
{
    if (name == DECODERS)
    {
        return Asset::Type::DECODER;
    }
    else if (name == RULES)
    {
        return Asset::Type::RULE;
    }
    else if (name == OUTPUTS)
    {
        return Asset::Type::OUTPUT;
    }
    else if (name == FILTERS)
    {
        return Asset::Type::FILTER;
    }
    else
    {
        throw std::runtime_error(fmt::format("Unknown asset type: {}", name));
    }
}

/**
 * @brief Intermediate representation of the environment.
 *
 * The environment contains the following information:
 * - The name of the environment.
 * - All assests (decoders, rules, outputs, filters) of the environment stored in a map.
 * - Each asset subgraph (decoders, rules, outputs) stored in a map of graphs.
 */
class Environment
{
private:
    std::string m_name;
    std::unordered_map<std::string, std::shared_ptr<Asset>> m_assets;
    std::map<std::string, Graph<std::string, std::shared_ptr<Asset>>> m_graphs;

    /**
     * @brief Build specific subgraph from the provided map of jsons.
     *
     * Build each asset and add it to the graph.
     *
     * @param assetsDefinitons Map of jsons for each asset.
     * @param graphName Name of the subgraph.
     * @param type Type of the assets in the subgraph.
     * @throws std::runtime_error if the asset cannot be built.
     */
    void buildGraph(const std::unordered_map<std::string, json::Json>& assetsDefinitons,
                    const std::string& graphName,
                    Asset::Type type)
    {
        auto& graph = m_graphs[graphName];
        for (auto& [name, json] : assetsDefinitons)
        {
            // Build Asset object and insert
            std::shared_ptr<Asset> asset;
            try
            {
                asset = std::make_shared<Asset>(json, type);
            }
            catch (const std::exception& e)
            {
                std::throw_with_nested(
                    std::runtime_error(fmt::format("Failed to build asset: {}", name)));
            }
            m_assets.insert(std::make_pair(name, asset));
            graph.addNode(name, asset);
            if (asset->m_parents.empty())
            {
                graph.addEdge(graph.rootId(), name);
            }
            else
            {
                for (auto& parent : asset->m_parents)
                {
                    graph.addEdge(parent, name);
                }
            }
        }
    }

    /**
     * @brief Inject Filters into specific subgraph.
     *
     * If a filter references an asset, it is added as child of the asset, and the asset's
     * children are added as children of the filter.
     * Otherwise nohting is done.
     *
     * @param graphName Name of the subgraph.
     */
    void addFilters(const std::string& graphName)
    {
        auto& graph = m_graphs[graphName];
        for (auto& [name, asset] : m_assets)
        {
            if (asset->m_type == Asset::Type::FILTER)
            {
                for (auto& parent : asset->m_parents)
                {
                    if (graph.hasNode(parent))
                    {
                        graph.injectNode(name, asset, parent);
                    }
                }
            }
        }
    }

public:
    Environment() = default;

    // TODO: Remove injected catalog dependencies ?
    /**
     * @brief Construct a new Environment object
     *
     * @tparam T Injected catalog type.
     * @param name Name of the environment.
     * @param jsonDefinition Json definition of the environment.
     * @param catalog Injected catalog.
     * @throws std::runtime_error if the environment cannot be built.
     */
    template<typename T>
    Environment(std::string name, const json::Json& jsonDefinition, T catalog)
        : m_name {name}
    {
        auto envObj = jsonDefinition.getObject().value();

        // Filters are not graphs, its treated as a special case.
        // We just add them to the asset map and then inject them into each
        // graph.
        auto filtersPos =
            std::find_if(envObj.begin(),
                         envObj.end(),
                         [](auto& tuple) { return std::get<0>(tuple) == FILTERS; });
        if (filtersPos != envObj.end())
        {
            auto filtersList = std::get<1>(*filtersPos).getArray().value();
            std::transform(filtersList.begin(),
                           filtersList.end(),
                           std::inserter(m_assets, m_assets.begin()),
                           [&](auto& json)
                           {
                               auto assetType = Asset::Type::FILTER;
                               auto assetName = json.getString().value();
                               return std::make_pair(
                                   assetName,
                                   std::make_shared<Asset>(
                                       json::Json(catalog.getAsset(
                                           Asset::typeToString(assetType), assetName)),
                                       assetType));
                           });
            envObj.erase(filtersPos);
        }

        // Build graphs
        // We need atleast one graph to build the environment.
        if (envObj.empty())
        {
            throw std::runtime_error(
                fmt::format("[Environment(name, json, catalog)] environment [{}] needs "
                            "atleast one graph",
                            name));
        }
        for (auto& [name, json] : envObj)
        {
            auto assetNames = json.getArray().value();

            m_graphs.insert(
                std::make_pair<std::string, Graph<std::string, std::shared_ptr<Asset>>>(
                    std::string {name},
                    {std::string(name + "Input"),
                     std::make_shared<Asset>(name + "Input", getAssetType(name))}));

            // Obtain assets jsons
            auto assetsDefinitions = std::unordered_map<std::string, json::Json>();
            std::transform(assetNames.begin(),
                           assetNames.end(),
                           std::inserter(assetsDefinitions, assetsDefinitions.begin()),
                           [&](auto& json)
                           {
                               auto assetType = getAssetType(name);
                               auto assetName = json.getString().value();
                               return std::make_pair(
                                   assetName,
                                   json::Json(catalog.getAsset(
                                       Asset::typeToString(assetType), assetName)));
                           });

            // Build graph
            buildGraph(assetsDefinitions, name, getAssetType(name));

            // Add filters
            addFilters(name);

            // Check integrity
            for (auto& [parent, children] : m_graphs[name].edges())
            {
                if (!m_graphs[name].hasNode(parent))
                {
                    std::string childrenNames;
                    for (auto& child : children)
                    {
                        childrenNames += child + " ";
                    }
                    throw std::runtime_error(
                        fmt::format("Error building [{}] graph: parent [{}] not found, "
                                    "for children [{}]",
                                    name,
                                    parent,
                                    childrenNames));
                }
                for (auto& child : children)
                {
                    if (!m_graphs[name].hasNode(child))
                    {
                        throw std::runtime_error(
                            fmt::format("Missing child asset: {}", child));
                    }
                }
            }
        }
    }

    /**
     * @brief Get the name of the environment.
     *
     * @return const std::string& Name of the environment.
     */
    std::string name() const
    {
        return m_name;
    }

    /**
     * @brief Get the map of assets.
     *
     * @return std::unordered_map<std::string, std::shared_ptr<Asset>>&
     */
    std::unordered_map<std::string, std::shared_ptr<Asset>>& assets()
    {
        return m_assets;
    }

    /**
     * @brief Get the map of assets.
     *
     * @return std::unordered_map<std::string, std::shared_ptr<Asset>>&
     */
    const std::unordered_map<std::string, std::shared_ptr<Asset>>& assets() const
    {
        return m_assets;
    }

    /**
     * @brief Get the Graphivz Str object
     *
     * @return std::string
     */
    std::string getGraphivzStr()
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
                ss << name << " [label=\"" << name << "\"];" << std::endl;
            }
            for (auto& [parent, children] : graph.edges())
            {
                for (auto& child : children)
                {
                    ss << parent << " -> " << child << ";" << std::endl;
                }
            }
            ss << "}" << std::endl;
            ss << "environment -> " << name << "Input;" << std::endl;
        }
        ss << "}\n";
        return ss.str();
    }

    /**
     * @brief Build and Get the Expression from the environment.
     *
     * @return base::Expression Root expression of the environment.
     * @throws std::runtime_error If the expression cannot be built.
     */
    base::Expression getExpression() const
    {
        // Expression of the environment, expression to be returned.
        // All subgraphs are added to this expression.
        std::shared_ptr<base::Operation> environment = base::Chain::create(m_name, {});

        // Iterate over subgraphs
        for (auto& [graphName, graph] : m_graphs)
        {
            // Create root subgraph expression
            std::shared_ptr<base::Operation> inputExpression;
            switch (graph.node(graph.rootId())->m_type)
            {
                case Asset::Type::DECODER:
                    inputExpression =
                        base::Or::create(graph.node(graph.rootId())->m_name, {});
                    break;
                case Asset::Type::RULE:
                case Asset::Type::OUTPUT:
                    inputExpression =
                        base::Broadcast::create(graph.node(graph.rootId())->m_name, {});
                    break;
                default:
                    throw std::runtime_error("Unsupported root asset type in "
                                             "Environment::getExpression");
            }
            // Add input Expression to environment expression
            environment->getOperands().push_back(inputExpression);

            // Build rest of the graph

            // Avoid duplicating nodes when multiple
            // parents has the same child node
            std::map<std::string, base::Expression> builtNodes;

            // parentNode Expression is passed as filters need it.
            auto visit = [&](const std::string& current,
                             const std::string& parent,
                             auto& visitRef) -> base::Expression
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
                            case Asset::Type::DECODER:
                                assetChildren = base::Or::create("children", {});
                                break;
                            case Asset::Type::RULE:
                            case Asset::Type::OUTPUT:
                                assetChildren = base::Broadcast::create("children", {});
                                break;

                            default:
                                throw std::runtime_error(fmt::format(
                                    "Unsupported asset type in "
                                    "Environment::getExpression for asset [{}]",
                                    current));
                        }

                        assetNode = base::Implication::create(asset->m_name + "Node",
                                                              asset->getExpression(),
                                                              assetChildren);

                        // Visit children and add them to the children node
                        for (auto& child : graph.children(current))
                        {
                            assetChildren->getOperands().push_back(
                                visitRef(child, current, visitRef));
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
                inputExpression->getOperands().push_back(
                    visit(child, graph.rootId(), visit));
            }
        }

        return environment;
    }
};

} // namespace builder

#endif // _ENVIRONMENT_H
