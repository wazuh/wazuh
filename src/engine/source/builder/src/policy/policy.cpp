#include "policy.hpp"

#include <fmt/format.h>

#include "assetBuilder.hpp"
#include "builders/buildCtx.hpp"
#include "factory.hpp"

namespace builder::policy
{

Policy::Policy(const cm::store::NamespaceId& namespaceId,
               const std::shared_ptr<cm::store::ICMStore>& cmStore,
               const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
               const std::shared_ptr<builders::RegistryType>& registry,
               const std::shared_ptr<schemf::IValidator>& schema,
               const std::shared_ptr<IAllowedFields>& allowedFields,
               const bool trace,
               const bool sandbox)
{
    const auto& cmStoreNsReader = cmStore->getNSReader(namespaceId);
    const auto& policyData = cmStoreNsReader->getPolicy();

    // Assign metadata
    m_hash = policyData.getHash();
    m_name = namespaceId.toStr();

    // Build the assets
    // We need to build the assets before the graph because the parents are defined in the assets
    // TODO: expose state of buildCtx to the user of the policy
    // TODO: abstract this buildCtx code as it is needed by builder::Builder
    auto buildCtx = std::make_shared<builders::BuildCtx>();
    buildCtx->setRegistry(registry);
    buildCtx->setValidator(schema);
    buildCtx->context().policyName = m_name;
    buildCtx->runState().trace = trace;
    buildCtx->runState().sandbox = sandbox;
    buildCtx->setAllowedFields(allowedFields);
    buildCtx->setStoreNSReader(cmStoreNsReader);

    // Build assets of policy
    auto assetBuilder = std::make_shared<AssetBuilder>(buildCtx, definitionsBuilder);
    auto builtAssets = factory::buildAssets(policyData, cmStoreNsReader, assetBuilder, sandbox);


    // Assign the assets
    // TODO: Build a single unordered_set in factory::buildAssets to avoid this loop
    for (const auto& [type, subgraph] : builtAssets)
    {
        for (const auto& asset : subgraph.orderedAssets)
        {
            m_assets.insert(asset);
        }
    }

    // Build the policy graph
    // Exposing this step here is only needed for gathering the graphivz string
    auto policyGraph = factory::buildGraph(builtAssets);
    // TODO: Assign graphiv string

    // Build the expression
    m_expression = factory::buildExpression(policyGraph, policyData);
}

} // namespace builder::policy
