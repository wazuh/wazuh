#ifndef _ENVIRONMENT_H
#define _ENVIRONMENT_H

#include <memory>
#include <set>
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

class Environment
{
private:
    std::string m_name;
    std::unordered_map<std::string, std::shared_ptr<Asset>> m_assets;
    std::map<std::string, Graph<std::string, std::shared_ptr<Asset>>> m_graphs;

    void buildGraph(const std::unordered_map<std::string, json::Json>& assetsDefinitons,
                    const std::string& graphName,
                    Asset::Type type)
    {
        auto& graph = m_graphs[graphName];
        for (auto& [name, json] : assetsDefinitons)
        {
            // Build Asset object and insert
            auto asset = std::make_shared<Asset>(json, type);
            m_assets.insert(std::make_pair(name, asset));
            graph.addNode(name, asset);
            if (asset->m_parents.empty())
            {
                graph.addEdge(graph.root(), name);
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
    template<typename T>
    Environment(std::string name, const json::Json& jsonDefinition, T catalog)
        : m_name {name}
    {
        auto envObj = jsonDefinition.getObject();

        // Filters are not graphs, its treated as a special case.
        // We just add them to the asset map and then inject them into each
        // graph.
        auto filtersPos =
            std::find_if(envObj.begin(),
                         envObj.end(),
                         [](auto& tuple) { return std::get<0>(tuple) == FILTERS; });
        if (filtersPos != envObj.end())
        {
            auto filtersList = std::get<1>(*filtersPos).getArray();
            std::transform(filtersList.begin(),
                           filtersList.end(),
                           std::inserter(m_assets, m_assets.begin()),
                           [&](auto& json)
                           {
                               auto assetType = Asset::Type::FILTER;
                               auto assetName = json.getString();
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
        for (auto& [name, json] : envObj)
        {
            auto assetNames = json.getArray();

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
                               auto assetName = json.getString();
                               return std::make_pair(
                                   assetName,
                                   json::Json(catalog.getAsset(
                                       Asset::typeToString(assetType), assetName)));
                           });

            // Build graph
            buildGraph(assetsDefinitions, name, getAssetType(name));

            // Add filters
            addFilters(name);
        }
    }

    std::string name() const
    {
        return m_name;
    }

    std::unordered_map<std::string, std::shared_ptr<Asset>>& assets()
    {
        return m_assets;
    }

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
            for (auto& [name, asset] : graph.m_nodes)
            {
                ss << name << " [label=\"" << name << "\"];" << std::endl;
            }
            for (auto& [parent, children] : graph.m_edges)
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
            switch (graph.node(graph.root())->m_type)
            {
                case Asset::Type::DECODER:
                    inputExpression =
                        base::Or::create(graph.node(graph.root())->m_name, {});
                    break;
                case Asset::Type::RULE:
                case Asset::Type::OUTPUT:
                    inputExpression =
                        base::Broadcast::create(graph.node(graph.root())->m_name, {});
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
                    auto asset = graph.node(current);
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
                            throw std::runtime_error(
                                fmt::format("Unsupported asset type in "
                                            "Environment::getExpression for asset [{}]",
                                            current));
                    }

                    std::shared_ptr<base::Operation> assetNode;
                    assetNode = base::Implication::create(
                        asset->m_name + "Node", asset->getExpression(), assetChildren);

                    // Add it to builtNodes
                    if (asset->m_parents.size() > 1)
                    {
                        builtNodes.insert(std::make_pair(current, assetNode));
                    }

                    // Visit children and add them to the children node
                    for (auto& child : graph.m_edges.at(current))
                    {
                        assetChildren->getOperands().push_back(
                            visitRef(child, current, visitRef));
                    }

                    return assetNode;
                }
            };

            // Visit root childs and add them to the root expression
            for (auto& child : graph.m_edges.at(graph.root()))
            {
                inputExpression->getOperands().push_back(
                    visit(child, graph.root(), visit));
            }
        }

        return environment;
    }
};

} // namespace builder

#endif // _ENVIRONMENT_H
