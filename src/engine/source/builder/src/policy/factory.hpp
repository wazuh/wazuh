#ifndef _BUILDER_POLICY_FACTORY_HPP
#define _BUILDER_POLICY_FACTORY_HPP

#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>

#include <base/expression.hpp>
#include <base/graph.hpp>
#include <store/istore.hpp>

#include "iassetBuilder.hpp"
#include "iregistry.hpp"

namespace builder::policy::factory
{

/**
 * @brief Contains each of the assets for a given type and the default parents.
 *
 */
struct SubgraphData
{
    std::unordered_map<store::NamespaceId, base::Name> defaultParents;
    std::unordered_map<store::NamespaceId, std::unordered_set<base::Name>> assets;

    friend bool operator==(const SubgraphData& lhs, const SubgraphData& rhs)
    {
        return lhs.defaultParents == rhs.defaultParents && lhs.assets == rhs.assets;
    }
};

/**
 * @brief Contains the policy data needed to build the policy.
 *
 */
class PolicyData
{
public:
    enum class AssetType // Defines order
    {
        DECODER = 0,
        RULE,
        OUTPUT,
        FILTER // TODO implement filters as a separate asset type
    };

    static constexpr auto assetTypeStr(AssetType type)
    {
        switch (type)
        {
            case AssetType::DECODER: return "decoder";
            case AssetType::RULE: return "rule";
            case AssetType::OUTPUT: return "output";
            case AssetType::FILTER: return "filter";
            default: throw std::runtime_error("Invalid asset type");
        }
    }

private:
    base::Name m_name;                                       ///< Policy name
    std::string m_hash;                                      ///< Policy hash
    std::unordered_map<AssetType, SubgraphData> m_subgraphs; ///< Subgraph data by type

public:
    struct Params
    {
        base::Name name;
        std::string hash;
        std::unordered_map<store::NamespaceId, base::Name> defaultParents;
        std::unordered_map<AssetType, std::unordered_map<store::NamespaceId, std::unordered_set<base::Name>>> assets;
    };

    PolicyData() = default;
    PolicyData(const Params& params)
    {
        m_name = params.name;
        m_hash = params.hash;

        for (const auto& [ns, name] : params.defaultParents)
        {
            auto asset = base::Name {name};

            if (asset.parts()[0] == assetTypeStr(AssetType::DECODER))
            {
                addDefaultParent(AssetType::DECODER, ns, name);
            }
            else if (asset.parts()[0] == assetTypeStr(AssetType::RULE))
            {
                addDefaultParent(AssetType::RULE, ns, name);
            }
            else
            {
                throw std::runtime_error(fmt::format("name {} is not a valid type", asset.parts()[0]));
            }
        }

        for (const auto& [assetType, subgraph] : params.assets)
        {
            for (const auto& [ns, assets] : subgraph)
            {
                for (const auto& name : assets)
                {
                    add(assetType, ns, name);
                }
            }
        }
    }

    /**
     * @brief Add asset to the policy data.
     *
     * @param assetType Type of the asset.
     * @param ns Namespace of the asset.
     * @param name Name of the asset.
     *
     * @return true if the asset was added.
     * @return false if the asset was already present.
     */
    inline bool add(AssetType assetType, const store::NamespaceId& ns, const base::Name& name)
    {
        auto subgraphIt = m_subgraphs.find(assetType);
        if (subgraphIt == m_subgraphs.end())
        {
            m_subgraphs.emplace(assetType, SubgraphData {});
            subgraphIt = m_subgraphs.find(assetType);
        }
        auto& subgraph = subgraphIt->second;
        auto nsIt = subgraph.assets.find(ns);
        if (nsIt == subgraph.assets.end())
        {
            subgraph.assets.emplace(ns, std::unordered_set<base::Name> {name});
        }
        else
        {
            if (nsIt->second.find(name) != nsIt->second.end())
            {
                return false;
            }
            nsIt->second.emplace(name);
        }

        return true;
    }

    /**
     * @brief Add default parent to the policy data.
     *
     * @param assetType Type of the asset.
     * @param ns Namespace of the asset.
     * @param name Name of the asset.
     *
     * @return true if the default parent was added.
     * @return false if the default parent was already present.
     *
     */
    bool addDefaultParent(AssetType assetType, const store::NamespaceId& ns, const base::Name& name)
    {
        auto subgraphIt = m_subgraphs.find(assetType);
        if (subgraphIt == m_subgraphs.end())
        {
            m_subgraphs.emplace(assetType, SubgraphData {});
            subgraphIt = m_subgraphs.find(assetType);
        }
        auto& subgraph = subgraphIt->second;
        auto nsIt = subgraph.defaultParents.find(ns);
        if (nsIt == subgraph.defaultParents.end())
        {
            subgraph.defaultParents.emplace(ns, name);
            return true;
        }
        return false;
    }

    const base::Name& name() const { return m_name; }
    base::Name& name() { return m_name; }

    const std::string& hash() const { return m_hash; }
    std::string& hash() { return m_hash; }

    const std::unordered_map<AssetType, SubgraphData>& subgraphs() const { return m_subgraphs; }
};

/**
 * @brief Add the subgraph of the integration to the policy data.
 *
 * @param assetType Asset type of the subgraph.
 * @param path Path to the asset list in the integration document.
 * @param integrationDoc Integration document.
 * @param store The store interface to query namespaces.
 * @param integrationName Name of the integration.
 * @param integrationNs Namespace of the integration.
 * @param data Policy data to add the subgraph.
 *
 * @throw std::runtime_error If any error occurs.
 */
void addIntegrationSubgraph(PolicyData::AssetType assetType,
                            const std::string& path,
                            const store::Doc& integrationDoc,
                            const std::shared_ptr<store::IStoreReader>& store,
                            const base::Name& integrationName,
                            const store::NamespaceId& integrationNs,
                            PolicyData& data);

/**
 * @brief Query the store to add the assets of the integration to the policy data.
 *
 * @param integrationNs Namespace of the integration.
 * @param name Name of the integration.
 * @param data Policy data to add the assets.
 * @param store The store interface to query assets and namespaces.
 *
 * @throw std::runtime_error If any error occurs.
 */
void addIntegrationAssets(const store::NamespaceId& integrationNs,
                          const base::Name& name,
                          PolicyData& data,
                          const std::shared_ptr<store::IStoreReader>& store);

/**
 * @brief Read the policy data from the policy document
 *
 * @param doc The policy document.
 * @param store The store interface to query asset namespace.
 *
 * @return PolicyData The policy data.
 *
 * @throw std::runtime_error If the policy data is invalid.
 */
PolicyData readData(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store);

/**
 * @brief This struct contains the built assets of the policy by type.
 *
 */
using BuiltAssets = std::unordered_map<PolicyData::AssetType, std::unordered_map<base::Name, Asset>>;

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
BuiltAssets buildAssets(const PolicyData& data,
                        const std::shared_ptr<store::IStoreReader> store,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder);

/**
 * @brief This struct contains the policy graphs by type.
 *
 */
struct PolicyGraph
{
    std::map<PolicyData::AssetType, Graph<base::Name, Asset>> subgraphs; ///< Subgraphs by type

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
                                       const SubgraphData& subgraphData,
                                       const SubgraphData& filtersData,
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
PolicyGraph buildGraph(const BuiltAssets& assets, const PolicyData& data);

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

                if constexpr (std::is_same_v<ChildOperator, base::Or>)
                {
                    if (const auto env = std::getenv("WAZUH_REVERSE_ORDER_DECODERS");
                        env != nullptr && std::string(env) == "true")
                    {
                        auto& ops = assetChildren->getOperands();
                        std::reverse(ops.begin(), ops.end());
                    }
                }
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
base::Expression buildExpression(const PolicyGraph& graph, const PolicyData& data);

} // namespace builder::policy::factory

#endif // _BUILDER_POLICY_FACTORY_HPP
