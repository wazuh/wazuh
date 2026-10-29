// SPDX-License-Identifier: AGPL-3.0-or-later
#include "policy.hpp"

#include <fmt/format.h>

#include <fastmetrics/registry.hpp>

#include "assetBuilder.hpp"
#include "builders/buildCtx.hpp"
#include "builders/enrichment/enrichment.hpp"
#include "factory.hpp"

namespace builder::policy
{

namespace
{
/**
 * @brief Counter that is never registered in the metrics manager.
 *
 * Test-mode policies (tester sessions, logtest, policy validation) run sample events through a copy of
 * a space's pipeline. Their per-space counters must neither move the production counters of the space
 * they were copied from nor register metrics for temporary spaces that nothing can remove later.
 */
class DetachedCounter final : public fastmetrics::ICounter
{
public:
    const std::string& name() const override
    {
        static const std::string empty;
        return empty;
    }
    fastmetrics::MetricType type() const override { return fastmetrics::MetricType::COUNTER; }
    bool isEnabled() const override { return false; }
    void enable() override {}
    void disable() override {}
    void reset() override {}
    double value() const override { return 0.0; }
    void add(uint64_t /*delta*/) override {}
    uint64_t get() const override { return 0; }
};

/**
 * @brief Get the per-space counter for a policy: the registered one in production, a detached one in test mode.
 */
std::shared_ptr<fastmetrics::ICounter> spaceCounter(const std::string& metricName, bool isTestMode)
{
    if (isTestMode)
    {
        return std::make_shared<DetachedCounter>();
    }
    return fastmetrics::manager().getOrCreateCounter(metricName);
}
} // namespace

Policy::Policy(const cm::store::NamespaceId& namespaceId,
               const std::shared_ptr<cm::store::ICMStore>& cmStore,
               const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
               const std::shared_ptr<builders::RegistryType>& registry,
               const std::shared_ptr<schemf::IValidator>& schema,
               const std::shared_ptr<IAllowedFields>& allowedFields,
               const bool isTestMode)
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
    buildCtx->context().originSpace = policyData.getOriginSpace();
    buildCtx->context().indexDiscardedEvents = policyData.shouldIndexDiscardedEvents();
    buildCtx->context().indexUnclassifiedEvents = policyData.shouldIndexUnclassifiedEvents();
    buildCtx->setTestMode(isTestMode);
    buildCtx->setAllowedFields(allowedFields);
    buildCtx->setStoreNSReader(cmStoreNsReader);

    // Build assets of policy
    auto assetBuilder = std::make_shared<AssetBuilder>(buildCtx, definitionsBuilder);
    auto builtAssets = factory::buildAssets(policyData, cmStoreNsReader, assetBuilder, isTestMode);

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
            auto discardedCounter =
                spaceCounter(fastmetrics::names::space_events_discarded(policyData.getOriginSpace()), isTestMode);
            auto [exp, traceable] =
                builders::enrichment::getDiscardedEventsFilter(policyData, isTestMode, discardedCounter);
            preEnrichmentOps.push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        // Cleanup decoder temporary variables (enabled/disabled according to policy)
        {
            auto [cleanupVars, traceable] = builders::enrichment::getCleanupDecoderVariables(
                policyData.shouldCleanupDecoderVariables(), isTestMode);
            preEnrichmentOps.push_back(cleanupVars);
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
            auto [exp, traceable] = builder(isTestMode);
            enrichmentExp->getOperands().push_back(exp);
            m_assets.insert(base::Name(traceable));
        }

        return enrichmentExp;
    }();

    // Build the expression with per-space pre/post filter discard counters (detached in test mode)
    const auto spaceName = policyData.getOriginSpace();
    auto preFilterDiscardCounter =
        spaceCounter(fastmetrics::names::space_events_discarded_prefilter(spaceName), isTestMode);
    auto postFilterDiscardCounter =
        spaceCounter(fastmetrics::names::space_events_discarded_postfilter(spaceName), isTestMode);
    auto unclassifiedCounter = spaceCounter(fastmetrics::names::space_events_unclassified(spaceName), isTestMode);

    auto expr = factory::buildExpression(
        policyGraph, preEnrichmentExp, enrichmentExp, preFilterDiscardCounter, postFilterDiscardCounter);

    auto postUnclassified = builders::enrichment::postOutputUnclassifiedCounter(spaceName, unclassifiedCounter);
    m_expression = base::Chain::create("policy_with_post_unclassified", {expr, postUnclassified});
}

} // namespace builder::policy
