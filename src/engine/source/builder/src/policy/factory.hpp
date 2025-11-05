#ifndef _BUILDER_POLICY_FACTORY_HPP
#define _BUILDER_POLICY_FACTORY_HPP

#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>

#include <base/expression.hpp>
#include <base/graph.hpp>
#include <cmstore/icmstore.hpp>

#include "iassetBuilder.hpp"
#include "iregistry.hpp"

namespace builder::policy::factory
{

/**
 * @brief This struct contains the built assets of the policy by type.
 *
 */
using BuiltAssets = std::unordered_map<cm::store::ResourceType, std::unordered_map<base::Name, Asset>>;

/**
 * @brief Build the assets of the policy.
 *
 * @param data Policy data.
 * @param store The store interface to query assets and namespaces.
 * @param assetBuilder The asset builder instance to build each asset.
 *
 * @return BuiltAssets
 *
 * @throw std::runtime_error If any error occurs.
 */
BuiltAssets buildAssets(const cm::store::dataType::Policy& policyData,
                        const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder);

/**
 * @brief This struct contains the policy graphs by type.
 *
 */
struct PolicyGraph
{
    std::map<cm::store::ResourceType, Graph<base::Name, Asset>> subgraphs; ///< Subgraphs by type

    // TODO: Implement
    /**
     * @brief Get the Graphivz string of the policy graph.
     *
     * @return std::string
     */
    inline std::string getGraphivzStr() const { throw std::runtime_error("Not implemented"); }

    friend bool operator==(const PolicyGraph& lhs, const PolicyGraph& rhs) { return lhs.subgraphs == rhs.subgraphs; }
};

/**
 * @brief Build a subgraph of the policy.
 *
 * @param subgraphName Name of the subgraph.
 * @param subgraphData Asset names of the subgraph.
 * @param filtersData Filter names of the policy.
 * @param assets Assets of the subgraph.
 * @param filters Filters of the policy.
 *
 * @return Graph<base::Name, Asset>
 *
 * @throw std::runtime_error If any error occurs.
 */
Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName,
                                       const std::unordered_map<base::Name, Asset>& assets,
                                       const std::unordered_map<base::Name, Asset>& filters);

/**
 * @brief Build the policy graph from the built assets and the relations defined in the policy data.
 *
 * @param assets Assets of the policy.
 * @param data Policy data.
 *
 * @return PolicyGraph
 *
 * @throw std::runtime_error If any error occurs.
 */
PolicyGraph buildGraph(const BuiltAssets& assets);

/**
 * @brief Generates the expression of a subgraph.
 *
 * @tparam ChildOperator Expression type of the children nodes and the root node.
 * @param subgraph Subgraph to generate the expression from.
 *
 * @return base::Expression
 *
 * @throw std::runtime_error If any error occurs.
 */
template<typename ChildOperator>
base::Expression buildSubgraphExpression(const Graph<base::Name, Asset>& subgraph)
{
    // Assert T is a valid operation
    static_assert(std::is_base_of_v<base::Operation, ChildOperator>, "ChildOperator must be a valid operation");

    auto root = ChildOperator::create(subgraph.rootId(), {});

    // Avoid duplicating nodes when multiple parents has the same child node
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
            auto asset = subgraph.node(current);
            std::shared_ptr<base::Operation> assetNode;

            if (subgraph.hasChildren(current))
            {
                auto assetChildren = ChildOperator::create(asset.name() + "Children", {});

                assetNode = base::Implication::create(asset.name() + "Node", asset.expression(), assetChildren);

                // Visit children and add them to the children node
                for (auto& child : subgraph.children(current))
                {
                    assetChildren->getOperands().push_back(visitRef(child, current, visitRef));
                }

#ifdef ENGINE_ENABLE_REVERSE_ORDER_DECODERS_FEATURE
                if constexpr (std::is_same_v<ChildOperator, base::Or>)
                {
                    if (const auto env = std::getenv("WAZUH_REVERSE_ORDER_DECODERS");
                        env != nullptr && std::string(env) == "true")
                    {
                        auto& ops = assetChildren->getOperands();
                        std::reverse(ops.begin(), ops.end());
                    }
                }
#endif // !ENGINE_ENABLE_REVERSE_ORDER_DECODERS_FEATURE
            }
            else
            {
                // No children
                assetNode = asset.expression()->getPtr<base::Operation>();
            }

            // Add it to builtNodes
            if (asset.parents().size() > 1)
            {
                builtNodes.insert(std::make_pair(current, assetNode));
            }

            return assetNode;
        }
    };

    // Visit root childs and add them to the root expression
    for (auto& child : subgraph.children(subgraph.rootId()))
    {
        root->getOperands().push_back(visit(child, subgraph.rootId(), visit));
    }

    return root;
}

/**
 * @brief Generates the expression of the policy from the policy graph and the policy data.
 *
 * @param graph Policy graph.
 * @param data Policy data.
 *
 * @return base::Expression
 *
 * @throw std::runtime_error If any error occurs.
 */
base::Expression buildExpression(const PolicyGraph& graph, const std::string& name);

} // namespace builder::policy::factory

#endif // _BUILDER_POLICY_FACTORY_HPP
