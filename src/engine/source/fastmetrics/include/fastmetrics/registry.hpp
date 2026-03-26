#ifndef _FASTMETRICS_REGISTRY_HPP
#define _FASTMETRICS_REGISTRY_HPP

/**
 * @file registry.hpp
 * @brief Public API for fastmetrics - singleton manager pattern
 *
 * Usage pattern (like engine's geo::Manager):
 *
 * 1. Register once at startup:
 *    fastmetrics::registerManager();
 *
 * 2. Use anywhere in code - TWO PATTERNS:
 *
 * PATTERN A: Ad-hoc usage (simple but has lookup overhead ~50ns)
 *    FASTMETRICS_COUNTER("events.received")->add(1);
 *
 * PATTERN B: Cache locally for hot paths (RECOMMENDED, zero overhead)
 *    class MyProcessor {
 *        std::shared_ptr<ICounter> m_eventsCounter;
 *    public:
 *        MyProcessor() {
 *            // Lookup ONCE in constructor (~50ns)
 *            m_eventsCounter = fastmetrics::manager().getOrCreateCounter("events.received");
 *        }
 *        void process() {
 *            // HOT PATH: Direct access, no lookup, no mutex, just atomics (~3ns)
 *            m_eventsCounter->add(1);
 *        }
 *    };
 *
 * Performance:
 * - First lookup (getOrCreateCounter): ~50ns (map + shared_lock)
 * - Cached access (m_counter->add): ~3ns (just atomic)
 * - Map lookup overhead only paid ONCE per metric
 */

#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>

#include <fastmetrics/iManager.hpp>

namespace fastmetrics
{

// Forward declaration
class Manager;

/**
 * @brief Register the metrics manager as singleton
 *
 * Call this once at application startup, before using any metrics.
 */
void registerManager();

/**
 * @brief Get the singleton manager instance (fast, O(1))
 *
 * @return Reference to the global metrics manager
 */
IManager& manager();

} // namespace fastmetrics

// ============================================================================
// Convenience macros for common operations
// ============================================================================

/**
 * @brief Get or create a counter (inline helper)
 * Usage: FASTMETRICS_COUNTER("events.received")->add(1);
 */
#define FASTMETRICS_COUNTER(name) fastmetrics::manager().getOrCreateCounter(name)

/**
 * @brief Get or create an int64 gauge (inline helper)
 * Usage: FASTMETRICS_GAUGE_INT("queue.size")->set(42);
 */
#define FASTMETRICS_GAUGE_INT(name) fastmetrics::manager().getOrCreateGaugeInt(name)

/**
 * @brief Get or create a double gauge (inline helper)
 * Usage: FASTMETRICS_GAUGE_DOUBLE("cpu.usage")->set(75.5);
 */
#define FASTMETRICS_GAUGE_DOUBLE(name) fastmetrics::manager().getOrCreateGaugeDouble(name)

/**
 * @brief Get or create a histogram (inline helper)
 * Usage: FASTMETRICS_HISTOGRAM("latency.processing")->record(duration);
 */
#define FASTMETRICS_HISTOGRAM(name) fastmetrics::manager().getOrCreateHistogram(name)

#endif // _FASTMETRICS_REGISTRY_HPP
