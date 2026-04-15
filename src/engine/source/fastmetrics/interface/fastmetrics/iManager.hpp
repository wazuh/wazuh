#ifndef FASTMETRICS_IMANAGER_HPP
#define FASTMETRICS_IMANAGER_HPP

/**
 * @file iManager.hpp
 * @brief Interface for metric manager
 *
 * Provides methods to create and access metrics programmatically.
 */

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "iMetric.hpp"

namespace fastmetrics
{

/**
 * @brief Metric manager interface
 *
 * Allows creating and accessing metrics from anywhere in the code.
 * Thread-safe for concurrent access.
 */
class IManager
{
public:
    virtual ~IManager() = default;

    /**
     * @brief Create or get an existing counter
     *
     * @param name Metric name (e.g., "module.component.events")
     * @param description Optional description
     * @param unit Optional unit (e.g., "count", "bytes")
     * @return Shared pointer to counter
     */
    virtual std::shared_ptr<ICounter>
    getOrCreateCounter(const std::string& name, const std::string& description = "", const std::string& unit = "") = 0;

    /**
     * @brief Create or get an existing int64 gauge
     *
     * @param name Metric name
     * @param description Optional description
     * @param unit Optional unit (e.g., "items", "connections")
     * @return Shared pointer to gauge
     */
    virtual std::shared_ptr<IGaugeInt>
    getOrCreateGaugeInt(const std::string& name, const std::string& description = "", const std::string& unit = "") = 0;

    /**
     * @brief Get an existing metric by name
     *
     * @param name Metric name
     * @return Shared pointer to metric, or nullptr if not found
     */
    virtual std::shared_ptr<IMetric> get(const std::string& name) const = 0;

    /**
     * @brief Check if a metric exists
     *
     * @param name Metric name
     * @return true if metric exists
     */
    virtual bool exists(const std::string& name) const = 0;

    /**
     * @brief Get all registered metric names
     *
     * @return Vector of metric names
     */
    virtual std::vector<std::string> getAllNames() const = 0;

    /**
     * @brief Get number of registered metrics
     *
     * @return Count of metrics
     */
    virtual size_t count() const = 0;

    /**
     * @brief Enable all metrics
     */
    virtual void enableAll() = 0;

    /**
     * @brief Disable all metrics
     */
    virtual void disableAll() = 0;

    /**
     * @brief Check if metrics are globally enabled
     */
    virtual bool isEnabled() const = 0;

    /**
     * @brief Clear all metrics (for testing)
     */
    virtual void clear() = 0;
};

} // namespace fastmetrics

#endif // FASTMETRICS_IMANAGER_HPP
