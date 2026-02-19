#ifndef _BUILDER_POLICY_FACTORY_HPP
#define _BUILDER_POLICY_FACTORY_HPP

#include <map>
#include <memory>
#include <unordered_map>

#include <fmt/format.h>

#include <base/expression.hpp>
#include <base/graph.hpp>
#include <cmstore/icmstore.hpp>

#include "iassetBuilder.hpp"

namespace builder::policy::factory
{

/**
 * @brief Stages for an asset in the pipeline
 *
 * Assets can only be in one tree, and each tree will have its own properties and locations in the pipeline.
 */
enum class AssetPipelineStage
{
    PRE_FILTERS_TREE = 0,  ///< Pre-filters tree, before IOCs (AND|OR between siblings).
    DECODERS_TREE = 1,     ///< Decoders tree, the first stage in the pipeline (OR between siblings).
    POST_FILTERS_TREE = 2, ///< Post-filters tree, after IOCs (AND|OR between siblings).
    OUTPUTS_TREE = 3,      ///< Outputs tree, after filters (Brodcast between siblings and childs).
    // End of valid values
    END_VALUES = 4 ///< Sentinel value for the end of the enum. (MAX VALUE)
};

/**
 * @brief String representations of AssetPipelineStage values.
 */
constexpr const std::string_view AssetPipelineStageStrs[] = {
    "PreFiltersTree", "DecodersTree", "PostFiltersTree", "OutputsTree"};

/**
 * @brief Convert AssetPipelineStage to string.
 * @param stage AssetPipelineStage value.
 * @return constexpr std::string_view String representation.
 * @throw std::runtime_error If the stage value is invalid.
 */
constexpr std::string_view AssetPipelineStageToStr(const AssetPipelineStage stage)
{
    if (static_cast<std::size_t>(stage) >= static_cast<std::size_t>(AssetPipelineStage::END_VALUES))
    {
        throw std::runtime_error("Invalid AssetPipelineStage value");
    }
    return AssetPipelineStageStrs[static_cast<std::size_t>(stage)];
}

/**
 * @brief This struct contains the built assets of the policy by type.
 *
 */
struct SubgraphData
{
    // Order in which the assets were read / built
    std::vector<base::Name> orderedAssets;
    // Quick access by name (for filters, checks, etc.)
    std::unordered_map<base::Name, Asset> assets;
};

using BuiltAssets = std::unordered_map<AssetPipelineStage, SubgraphData>;

/**
 * @brief Build the assets of the policy.
 *
 * @param data Policy data.
 * @param store The store interface to query assets and namespaces.
 * @param assetBuilder The asset builder instance to build each asset.
 * @param sandbox Flag indicating sandbox mode.
 *
 * @return BuiltAssets
 *
 * @throw std::runtime_error If any error occurs.
 */
BuiltAssets buildAssets(const cm::store::dataType::Policy& policyData,
                        const std::shared_ptr<cm::store::ICMStoreNSReader>& cmStoreNsReader,
                        const std::shared_ptr<IAssetBuilder>& assetBuilder,
                        const bool sandbox = false);

/**
 * @brief This struct contains the policy graphs by type.
 *
 */
struct PolicyGraph
{
    // TODO Rename to policy tree or similar, now is not full policy graph, only the subgraphs
    std::unordered_map<AssetPipelineStage, Graph<base::Name, Asset>> subgraphs; ///< Subgraphs by type
    std::string graphName;                                                      ///< Name of the graph

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
 * @param assetsData Assets of the subgraph (ordered and indexed).
 *
 * @return Graph<base::Name, Asset>
 *
 * @throw std::runtime_error If any error occurs.
 */
Graph<base::Name, Asset> buildSubgraph(const std::string& subgraphName, const SubgraphData& assetsData);

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
 * @note Child evaluation order follows the insertion order of edges in the graph.
 * For decoders this means siblings are evaluated in the same order they were declared
 * across integrations (see buildAssets/buildSubgraph).
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
                auto assetChildren = ChildOperator::create(asset.name() + "/Children", {});

                assetNode = base::Implication::create(asset.name() + "/Node", asset.expression(), assetChildren);

                // Visit children and add them to the children node
                for (auto& child : subgraph.children(current))
                {
                    assetChildren->getOperands().push_back(visitRef(child, current, visitRef));
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

    // Visit root children and add them to the root expression in graph insertion order.
    for (auto& child : subgraph.children(subgraph.rootId()))
    {
        root->getOperands().push_back(visit(child, subgraph.rootId(), visit));
    }

    return root;
}

/**
 * @brief Generates the expression of the policy from the policy graph and the enrichment stages
 *
 * The event is processed through a sequence of optional and mandatory stages
 * that together form the processing pipeline.
 *
 * 1. Pre-Filter Tree (optional):
 *    - If present, the event is evaluated against the pre-filter tree.
 *    - If the pre-filter fails, the event is immediately discarded.
 *    - If the pre-filter succeeds, or if this stage is not configured,
 *      the event continues to the Decoder Tree.
 *
 * 2. Decoder Tree:
 *    - The event is evaluated by the decoder tree.
 *    - Regardless of whether decoding succeeds or fails, the event
 *      always continues to the next stage.
 *
 * 3. Pre-Enrichment:
 *    - This stage performs initial enrichment operations before IOCs:
 *      a) Origin Space Mapping: Maps the event to its origin space based on policy configuration.
 *      b) Unclassified Events Filter: Evaluates events with "unclassified" category:
 *         - If policy.index_unclassified_events is true, the event continues normally.
 *         - If policy.index_unclassified_events is false, the event is dropped and pipeline stops.
 *    - If this stage fails, the event is discarded and subsequent stages are not executed.
 *
 * 4. Enrichment (optional):
 *    - Enrichment plugins (e.g., geo, IOCs) are applied to the event.
 *    - The result of this stage does not affect pipeline continuity.
 *      The event always proceeds to the next stage.
 *
 * 5. Post-Filter Tree (optional):
 *    - If present, the event is evaluated against the post-filter tree.
 *    - If no post-filter is configured, the event proceeds directly
 *      to the output stage.
 *    - If this stage is the last configured one, the final event result
 *      is determined by the post-filter evaluation.
 *
 * 6. Output Tree (optional):
 *    - If present, the event is forwarded to the configured outputs.
 *    - The output stage always succeeds and never blocks or discards events.
 *    - If no outputs are configured, the pipeline ends after the last filter.
 *
 * @param graph Policy graph containing decoder, filter, and output trees.
 * @param preEnrichmentExpression Expression for pre-enrichment stage (space mapping + unclassified filter).
 * @param enrichmentExpression Expression for enrichment stage (geo, IOCs, etc.).
 *
 * @return base::Expression Complete policy expression with all pipeline stages.
 *
 * @throw std::runtime_error If any error occurs during expression building.
 */
base::Expression buildExpression(const PolicyGraph& graph,
                                 const base::Expression& preEnrichmentExpression,
                                 const base::Expression& enrichmentExpression);

} // namespace builder::policy::factory

#endif // _BUILDER_POLICY_FACTORY_HPP
