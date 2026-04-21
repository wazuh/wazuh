#ifndef BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <utility>

#include <cmstore/datapolicy.hpp>
#include <fastmetrics/iMetric.hpp>
#include <geo/imanager.hpp>
#include <iockvdb/iManager.hpp>

#include "builders/types.hpp"

namespace builder::builders::enrichment
{

/**
 * @brief Make a traceable success expression.
 *
 * @param expr The expression to make traceable.
 * @param isTestMode Enable tracing.
 * @return base::Expression The traceable expression, or the original expression if tracing is disabled.
 */
inline base::Expression makeTraceableSuccessExpression(const base::Expression& expr, bool isTestMode)
{
    if (!isTestMode)
    {
        return expr;
    }
    static const auto successTraceable =
        base::Term<base::EngineOp>::create("AcceptAll", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
    return base::Implication::create("TraceableSuccess", expr, successTraceable);
}

/**
 * @brief Create an expression that increments the unclassified events metric after output.
 *
 * @param spaceName space's name, used to create a space-specific metric.
 * @param unclassifiedCounter Counter to increment for unclassified events.
 * @return base::Expression The post-output expression.
 */
base::Expression postOutputUnclassifiedCounter(const std::string& spaceName,
                                               std::shared_ptr<fastmetrics::ICounter> unclassifiedCounter);

/**
 * @brief Get the enrichment expression and traceable name for the space defined in the policy.
 *
 * @param policy Policy data.
 * @param isTestMode Enable tracing in the enrichment expression.
 * @return std::pair<base::Expression, std::string> The built enrichment expression and its traceable name.
 */
std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool isTestMode);

/**
 * @brief Get the filter expression to handle unclassified events according to policy configuration.
 *
 * This filter checks if wazuh.integration.category is "unclassified" and drops the event
 * if the policy's index_unclassified_events flag is false.
 *
 * @param policy Policy data.
 * @param isTestMode Enable tracing in the filter expression.
 * @return std::pair<base::Expression, std::string> The built filter expression and its traceable name.
 */
std::pair<base::Expression, std::string> getUnclassifiedFilter(const cm::store::dataType::Policy& policy, bool isTestMode);

/**
 * @brief Get the Geo Enrichment Builder
 *
 * @param geoManager Geo manager instance, used to create 1 locator per enrichment.
 * @param configDoc Configuration document to load mapping configurations.
 * @return EnrichmentBuilder
 */
EnrichmentBuilder getGeoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager,
                                          const json::Json& configDoc);

/**
 * @brief Get the IOC Enrichment Builder for a specific IOC DB type.
 *
 * @param kvdbIocManager IOC KVDB manager instance.
 * @param configDoc Configuration document with IOC field mappings.
 * @param iocType IOC DB type (e.g. ipv4-addr, file, url, domain-name).
 * @return EnrichmentBuilder
 */
EnrichmentBuilder getIocEnrichmentBuilder(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbIocManager,
                                          const json::Json& configDoc,
                                          std::string_view iocType);

/**
 * @brief Get the filter expression to handle discarded events according to policy configuration.
 *
 * This filter checks if an event should be discarded based on the policy's configuration.
 *
 * @param policy Policy data.
 * @param isTestMode Enable tracing in the filter expression.
 * @return std::pair<base::Expression, std::string> The built filter expression and its traceable name.
 */
std::pair<base::Expression, std::string>
getDiscardedEventsFilter(const cm::store::dataType::Policy& policy,
                         bool isTestMode,
                         const std::shared_ptr<fastmetrics::ICounter>& discardedCounter);

/**
 * @brief Get the cleanup expression to remove temporary decoder variables.
 *
 * This cleanup removes root keys prefixed with "_".
 *
 * @param enabled Enable cleanup behavior.
 * @param isTestMode Enable tracing in the cleanup expression.
 * @return std::pair<base::Expression, std::string> The built cleanup expression and its traceable name.
 */
std::pair<base::Expression, std::string> getCleanupDecoderVariables(bool enabled, bool isTestMode);

/**
 * @brief Create an expression that counts events when a phase expression fails.
 *
 * Wraps a phase expression so that when it returns failure (event is discarded by the phase),
 * the provided counter is incremented.
 *
 * @param phaseExpr The phase expression to wrap.
 * @param counter Counter to increment on phase failure.
 * @param name Traceable name for the wrapper expression.
 * @return base::Expression The wrapped expression.
 */
base::Expression makeFilterDiscardCounter(const base::Expression& phaseExpr,
                                          const std::shared_ptr<fastmetrics::ICounter>& counter,
                                          const std::string& name);

} // namespace builder::builders::enrichment

#endif // BUILDER_ENRICHMENT_ENRICHMENT_HPP
