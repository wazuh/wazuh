#include "environment.hpp"

#include "registry.hpp"
namespace builder
{

Asset::Type getAssetType(const std::string& name)
{
    if (DECODERS == name)
    {
        return Asset::Type::DECODER;
    }
    else if (RULES == name)
    {
        return Asset::Type::RULE;
    }
    else if (OUTPUTS == name)
    {
        return Asset::Type::OUTPUT;
    }
    else if (FILTERS == name)
    {
        return Asset::Type::FILTER;
    }
    else
    {
        // TODO: should this be a logic_error?
        throw std::runtime_error(
            fmt::format("Engine environment: Unknown type of asset \"{}\".", name));
    }
}

void Environment::buildGraph(
    const std::unordered_map<std::string, json::Json>& assetsDefinitons,
    const std::string& graphName,
    Asset::Type type,
    std::shared_ptr<internals::Registry> registry)
{
    auto graphPos = std::find_if(m_graphs.begin(),
                                 m_graphs.end(),
                                 [&graphName](const auto& graph)
                                 { return std::get<0>(graph) == graphName; });
    auto& graph = std::get<1>(*graphPos);
    for (auto& [name, json] : assetsDefinitons)
    {
        // Build Asset object and insert
        std::shared_ptr<Asset> asset;
        try
        {
            asset = std::make_shared<Asset>(json, type, registry);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Building asset \"{}\" failed: {}", name, e.what()));
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

void Environment::addFilters(const std::string& graphName)
{
    auto graphPos = std::find_if(m_graphs.begin(),
                                 m_graphs.end(),
                                 [&graphName](const auto& graph)
                                 { return std::get<0>(graph) == graphName; });
    auto& graph = std::get<1>(*graphPos);
    for (auto& [name, asset] : m_assets)
    {
        if (Asset::Type::FILTER == asset->m_type)
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

std::string Environment::name() const
{
    return m_name;
}

std::unordered_map<std::string, std::shared_ptr<Asset>>& Environment::assets()
{
    return m_assets;
}

const std::unordered_map<std::string, std::shared_ptr<Asset>>& Environment::assets() const
{
    return m_assets;
}

std::string Environment::getGraphivzStr()
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
        auto pos = ret.find('-');
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find('-');
        }

        pos = ret.find('/');
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find('/');
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
                ss << removeHyphen(parent) << " -> " << removeHyphen(child) << ";"
                   << std::endl;
            }
        }
        ss << "}" << std::endl;
        ss << "environment -> " << name << "Input;" << std::endl;
    }
    ss << "}\n";
    return ss.str();
}

base::Expression Environment::getExpression() const
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
                throw std::runtime_error(
                    fmt::format("Building environment \"{}\" failed as the type of the "
                                "asset \"{}\" is not supported",
                                graphName,
                                graph.node(graph.rootId())->m_name));
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
                                "Asset type not supported from asset \"{}\"", current));
                    }

                    assetNode = base::Implication::create(
                        asset->m_name + "Node", asset->getExpression(), assetChildren);

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
            inputExpression->getOperands().push_back(visit(child, graph.rootId(), visit));
        }
    }

    return environment;
}

} // namespace builder
