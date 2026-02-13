#include "policy.hpp"

#include <fmt/format.h>

#include "assetBuilder.hpp"
#include "builders/buildCtx.hpp"
#include "builders/enrichment/enrichment.hpp"
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
    buildCtx->context().indexDiscardedEvents = policyData.shouldIndexDiscardedEvents();
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
    policyGraph.graphName = m_name;

    // TODO: Assign graphiv string
    auto preEnrichmentExp = [&]() -> base::Expression
    {
        std::vector<base::Expression> preEnrichmentOps;

        // Mapping space name (disable trace)
        {
            auto [exp, traceable] = builders::enrichment::getSpaceEnrichment(policyData, false);
            preEnrichmentOps.push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        // Discarded events filter (based on policy configuration)
        {
            auto [exp, traceable] = builders::enrichment::getDiscardedEventsFilter(policyData, trace);
            preEnrichmentOps.push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        // Unclassified events filter (based on policy configuration)
        {
            auto [exp, traceable] = builders::enrichment::getUnclassifiedFilter(policyData, trace);
            preEnrichmentOps.push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        // Use And instead of Chain to ensure failure propagates correctly
        return base::And::create("preEnrichment", std::move(preEnrichmentOps));
    }();

    // Enrichment stage
    auto enrichmentExp = [&]() -> base::Expression
    {
        auto enrichmentExp = base::Chain::create("enrichment", {});

        for (const auto& enrichPlugin : policyData.getEnrichments())
        {
            auto builderIt = registry->get<builders::EnrichmentBuilder>(enrichPlugin);
            if (base::isError(builderIt))
            {
                continue; // TODO: Remove this line to make it throw when all enrichment plugins are available
                throw std::runtime_error(fmt::format(
                    "Enrichment plugin '{}' not found: {}", enrichPlugin, base::getError(builderIt).message));
            }
            auto builder = base::getResponse<builders::EnrichmentBuilder>(builderIt);
            auto [exp, traceable] = builder(trace);
            enrichmentExp->getOperands().push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        return enrichmentExp;
    }();

    // Build the expression
    m_expression = factory::buildExpression(policyGraph, preEnrichmentExp, enrichmentExp);
}

} // namespace builder::policy
