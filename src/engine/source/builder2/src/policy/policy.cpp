#include "policy.hpp"

#include <fmt/format.h>

#include "assetBuilder.hpp"
#include "builders/buildState.hpp"
#include "factory.hpp"

namespace builder::policy
{

Policy::Policy(const store::Doc& doc,
               const std::shared_ptr<store::IStoreReader>& store,
               const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder)
{
    // Read the policy data
    auto policyData = factory::readData(doc, store);

    // Assign metadata
    m_name = policyData.name();
    m_hash = policyData.hash();

    // Build the assets
    // We need to build the assets before the graph because the parents are defined in the assets
    // TODO: set registry and state
    auto buildState = std::make_shared<builders::BuildState>();
    auto assetBuilder = std::make_shared<AssetBuilder>(buildState, definitionsBuilder);
    auto builtAssets = factory::buildAssets(policyData, store, assetBuilder);

    // Build the policy graph
    // Exposing this step here is only needed for gathering the graphivz string
    auto policyGraph = factory::buildGraph(builtAssets, policyData);
    // TODO: Assign graphiv string

    // Build the expression
    m_expression = factory::buildExpression(policyGraph, policyData);
}

} // namespace builder::policy
