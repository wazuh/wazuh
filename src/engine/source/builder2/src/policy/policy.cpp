#include "policy.hpp"

#include <fmt/format.h>

#include "assetBuilder.hpp"
#include "builders/buildCtx.hpp"
#include "factory.hpp"

namespace builder::policy
{

Policy::Policy(const store::Doc& doc,
               const std::shared_ptr<store::IStoreReader>& store,
               const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
               const std::shared_ptr<builders::RegistryType>& registry,
               const std::shared_ptr<schemval::IValidator>& validator,
               const std::shared_ptr<schemf::ISchema>& schema)
{
    // Read the policy data
    auto policyData = factory::readData(doc, store);

    // Assign metadata
    m_name = policyData.name();
    m_hash = policyData.hash();

    // Build the assets
    // We need to build the assets before the graph because the parents are defined in the assets
    // TODO: expose state of buildCtx to the user of the policy
    // TODO: abstract this buildCtx code as it is needed by builder::Builder
    auto buildCtx = std::make_shared<builders::BuildCtx>();
    buildCtx->setRegistry(registry);
    buildCtx->setValidator(validator);
    buildCtx->context().policyName = m_name;
    buildCtx->runState().trace = true;
    buildCtx->setSchema(schema);


    auto assetBuilder = std::make_shared<AssetBuilder>(buildCtx, definitionsBuilder);
    auto builtAssets = factory::buildAssets(policyData, store, assetBuilder);

    // Assign the assets
    for (const auto& [type, assets] : builtAssets)
    {
        for (const auto& [name, asset] : assets)
        {
            m_assets.insert(name);
        }
    }

    // Build the policy graph
    // Exposing this step here is only needed for gathering the graphivz string
    auto policyGraph = factory::buildGraph(builtAssets, policyData);
    // TODO: Assign graphiv string

    // Build the expression
    m_expression = factory::buildExpression(policyGraph, policyData);
}

} // namespace builder::policy
