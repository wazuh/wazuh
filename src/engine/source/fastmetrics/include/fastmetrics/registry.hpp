#ifndef FASTMETRICS_REGISTRY_HPP
#define FASTMETRICS_REGISTRY_HPP

/**
 * @file registry.hpp
 * @brief Public API for fastmetrics - singleton manager pattern
 *
 * Usage pattern (like engine's geo::Manager):
 *
 * 1. Register once at startup:
 *    fastmetrics::registerManager();
 *
 * 2. Use anywhere in code - ALWAYS CACHE FOR HOT PATHS:
 *
 *  BAD: Ad-hoc usage in hot paths (map lookup every time ~50ns)
 *    while (processing) {
 *        fastmetrics::manager().getOrCreateCounter("events")->add(1); // SLOW!
 *    }
 *
 * GOOD: Cache locally before loops (RECOMMENDED, zero overhead)
 *    auto counter = fastmetrics::manager().getOrCreateCounter("events");
 *    while (processing) {
 *        counter->add(1); // FAST: ~3ns, just atomic, no map lookup
 *    }
 *
 * Performance:
 * - First lookup (getOrCreateCounter): ~50ns (map + shared_lock)
 * - Cached access (counter->add): ~3ns (just atomic)
 * - Map lookup overhead only paid ONCE per metric per component
 *
 */

#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>

#include <fastmetrics/iManager.hpp>
#include <fastmetrics/manager.hpp>
#include <fastmetrics/metric_names.hpp>

namespace fastmetrics
{

/**
 * @brief Register the metrics manager as singleton
 *
 * Call this once at application startup, before using any metrics.
 */
void registerManager();

/**
 * @brief Get the singleton manager instance (fast, O(1))
 *
 * @return Reference to the concrete manager (Manager, not IManager)
 * @note Returns Manager& to provide access to registerPullMetric template
 */
Manager& manager();

} // namespace fastmetrics

// ============================================================================
// Helper macro for pull metrics (template function wrapper)
// ============================================================================

/**
 * @brief Register a pull metric (on-demand callback)
 *
 * Pull metrics execute a callback when read, avoiding state duplication.
 * Perfect for exposing existing data like queue sizes without maintaining
 * separate atomic counters.
 *
 * Usage: FASTMETRICS_PULL(size_t, "queue.size", [&queue]() { return queue.size(); });
 *
 * WARNING: Ensure captured references remain valid. Prefer shared_ptr captures.
 */
#define FASTMETRICS_PULL(type, name, getter) fastmetrics::manager().registerPullMetric<type>(name, getter)

#endif // FASTMETRICS_REGISTRY_HPP
