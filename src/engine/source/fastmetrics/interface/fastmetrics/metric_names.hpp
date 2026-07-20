#ifndef FASTMETRICS_METRIC_NAMES_HPP
#define FASTMETRICS_METRIC_NAMES_HPP

#include <fmt/format.h>
#include <string>

namespace fastmetrics
{
namespace names
{

// Indexer queue metrics
constexpr auto INDEXER_QUEUE_SIZE = "indexer.queue.size";
constexpr auto INDEXER_QUEUE_USAGE_PERCENT = "indexer.queue.usage.percent";

// Indexer event metrics
constexpr auto INDEXER_EVENTS_DROPPED = "indexer.events.dropped";

// Router queue metrics
constexpr auto ROUTER_QUEUE_SIZE = "router.queue.size";
constexpr auto ROUTER_QUEUE_USAGE_PERCENT = "router.queue.usage.percent";

// Router event metrics
constexpr auto ROUTER_EPS_1M = "router.eps.1m";
constexpr auto ROUTER_EPS_5M = "router.eps.5m";
constexpr auto ROUTER_EPS_30M = "router.eps.30m";
constexpr auto ROUTER_EVENTS_PROCESSED = "router.events.processed";
constexpr auto ROUTER_EVENTS_DROPPED = "router.events.dropped";

// Server metrics
constexpr auto SERVER_BYTES_RECEIVED = "server.bytes.received";
constexpr auto SERVER_EVENTS_RECEIVED = "server.events.received";

// Per-space metric name formatters
inline std::string space_events_unclassified(const std::string& space)
{
    return fmt::format("space.{}.events.unclassified", space);
}
inline std::string space_events_discarded(const std::string& space)
{
    return fmt::format("space.{}.events.discarded", space);
}
inline std::string space_events_discarded_prefilter(const std::string& space)
{
    return fmt::format("space.{}.events.discarded.prefilter", space);
}
inline std::string space_events_discarded_postfilter(const std::string& space)
{
    return fmt::format("space.{}.events.discarded.postfilter", space);
}

} // namespace names
} // namespace fastmetrics

#endif // FASTMETRICS_METRIC_NAMES_HPP
