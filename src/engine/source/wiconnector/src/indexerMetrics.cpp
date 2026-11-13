// SPDX-License-Identifier: AGPL-3.0-or-later
#include <wiconnector/indexerMetrics.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fastmetrics/metric_names.hpp>
#include <indexer_client/metrics.hpp>
#include <indexer_client/metricsSlot.hpp>

namespace wiconnector
{

namespace
{

/// The process-wide families of the catalog (metrics.hpp CATALOG), all from RuntimeRef::snapshot().
constexpr std::array<std::string_view, 4> RUNTIME_PREFIXES {
    "indexer_client.runtime.", "indexer_client.node.", "indexer_client.query.", "indexer_client.pit."};

bool isRuntimeName(std::string_view name)
{
    for (const auto prefix : RUNTIME_PREFIXES)
    {
        if (name.substr(0, prefix.size()) == prefix)
        {
            return true;
        }
    }
    return false;
}

void registerRuntimeMetrics(fastmetrics::IManager& manager, const indexer_client::RuntimeRef& runtime)
{
    // The runtime only (no Client): its values do not depend on one. One snapshot per TTL serves every name.
    auto slot = std::make_shared<indexer_client::MetricsSlot>(
        WIndexerConnector::METRICS_TTL, std::vector<std::string>(RUNTIME_PREFIXES.begin(), RUNTIME_PREFIXES.end()));
    slot->repoint(std::weak_ptr<indexer_client::IClient> {}, runtime);

    std::vector<std::pair<std::string, indexer_client::MetricKind>> names;
    indexer_client::forEachMetric(runtime.snapshot(),
                                  [&names](std::string_view name, indexer_client::MetricKind kind, double)
                                  {
                                      if (isRuntimeName(name))
                                      {
                                          names.emplace_back(std::string(name), kind);
                                      }
                                  });

    for (const auto& [metricName, kind] : names)
    {
        if (kind == indexer_client::MetricKind::Counter)
        {
            manager.registerPullMetric(
                metricName,
                [slot, name = metricName]() { return static_cast<std::uint64_t>(slot->value(name)); },
                "indexer_client counter of the engine's indexer runtime");
            continue;
        }
        // Gauges can be fractions (a node's breaker window, for one): no truncation to an integer.
        manager.registerPullMetricDouble(
            metricName,
            [slot, name = metricName]() { return slot->value(name); },
            "indexer_client gauge of the engine's indexer runtime");
    }
}

} // namespace

void registerIndexerMetrics(fastmetrics::IManager& manager,
                            const std::weak_ptr<WIndexerConnector>& connector,
                            const std::optional<indexer_client::RuntimeRef>& runtime)
{
    manager.registerPullMetric(fastmetrics::names::INDEXER_QUEUE_SIZE,
                               [connector]() -> std::uint64_t
                               {
                                   const auto live = connector.lock();
                                   return live ? live->getQueueSize() : 0;
                               });
    manager.registerPullMetric(fastmetrics::names::INDEXER_EVENTS_DROPPED,
                               [connector]() -> std::uint64_t
                               {
                                   const auto live = connector.lock();
                                   return live ? live->getDroppedEvents() : 0;
                               });
    manager.registerPullMetric(fastmetrics::names::INDEXER_EVENTS_DEDUPLICATED,
                               [connector]() -> std::uint64_t
                               {
                                   const auto live = connector.lock();
                                   return live ? live->getDeduplicatedEvents() : 0;
                               });
    manager.registerPullMetricDouble(fastmetrics::names::INDEXER_QUEUE_USAGE_PERCENT,
                                     [connector]() -> double
                                     {
                                         const auto live = connector.lock();
                                         return live ? live->getQueueUsagePercent() : 0.0;
                                     });

    for (const auto& [metricName, kind] : WIndexerConnector::bucketMetricNames())
    {
        manager.registerPullMetric(
            metricName,
            [connector, name = metricName]() -> std::uint64_t
            {
                const auto live = connector.lock();
                return live ? static_cast<std::uint64_t>(live->getBucketMetric(name)) : 0;
            },
            std::string("indexer_client ") + (kind == indexer_client::MetricKind::Counter ? "counter" : "gauge")
                + " of one of the engine's buckets (events, raw)");
    }

    if (runtime)
    {
        registerRuntimeMetrics(manager, *runtime);
    }
}

} // namespace wiconnector
