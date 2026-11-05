// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
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
    // Named like the wrapped expression so the SUCCESS term is built inside the traceable node and publishes to its
    // tracer (bk restores the inherited publisher when it leaves a node).
    return base::Implication::create(expr->getName(), expr, successTraceable);
}

/**
 * @brief Throttled report of the unclassified events a space drops (policy `index_unclassified_events=false`).
 *
 * Every router worker builds its own copy of a space's policy, so the reporter of a space is shared by all of
 * them (see forSpace()): the warning is logged at most once per interval for the whole engine, and it carries
 * the number of events dropped since the previous one and the sources (`wazuh.protocol.location`) they came from.
 */
class UnclassifiedDropReporter
{
public:
    using Clock = std::chrono::steady_clock;

    static constexpr std::chrono::seconds DEFAULT_INTERVAL {300}; ///< Minimum time between two warnings
    static constexpr std::size_t MAX_SOURCES {10};                ///< Sources listed per warning
    static constexpr std::size_t MAX_SOURCE_LENGTH {128};         ///< Characters kept per source

    UnclassifiedDropReporter(std::string spaceName, std::chrono::seconds interval = DEFAULT_INTERVAL);

    /**
     * @brief Get the reporter of a space, shared by every policy of that space alive at the same time.
     */
    static std::shared_ptr<UnclassifiedDropReporter> forSpace(const std::string& spaceName);

    /**
     * @brief Record a dropped unclassified event.
     *
     * @param location Source of the event (`wazuh.protocol.location`), empty if unknown.
     * @param now Current time.
     * @return std::optional<std::string> The warning to log, when the interval since the previous one elapsed.
     */
    std::optional<std::string> record(std::string_view location, Clock::time_point now);

private:
    const std::string m_spaceName;
    const Clock::duration m_interval;
    std::atomic<uint64_t> m_dropped {0};
    std::atomic<Clock::rep> m_nextReport {std::numeric_limits<Clock::rep>::min()};
    std::atomic<bool> m_sourcesFull {false};
    std::mutex m_sourcesMutex;
    std::set<std::string> m_sources;
};

/**
 * @brief Create an expression that increments the unclassified events metric after output.
 *
 * @param spaceName space's name, used to create a space-specific metric.
 * @param unclassifiedCounter Counter to increment for unclassified events.
 * @param dropReporter Reporter of the unclassified events the policy does not index; nullptr when the policy
 * indexes them or is built in test mode.
 * @return base::Expression The post-output expression.
 */
base::Expression postOutputUnclassifiedCounter(const std::string& spaceName,
                                               std::shared_ptr<fastmetrics::ICounter> unclassifiedCounter,
                                               std::shared_ptr<UnclassifiedDropReporter> dropReporter = nullptr);

/**
 * @brief Get the enrichment expression and traceable name for the space defined in the policy.
 *
 * @param policy Policy data.
 * @param isTestMode Enable tracing in the enrichment expression.
 * @return std::pair<base::Expression, std::string> The built enrichment expression and its traceable name.
 */
std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool isTestMode);

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
