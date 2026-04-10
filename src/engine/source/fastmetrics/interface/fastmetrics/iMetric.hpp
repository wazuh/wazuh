#ifndef FASTMETRICS_IMETRIC_HPP
#define FASTMETRICS_IMETRIC_HPP

/**
 * @file iMetric.hpp
 * @brief Simple interface for fast lock-free metrics
 *
 * Metrics are registered as singletons for ultra-fast access without map lookups.
 * All operations are lock-free using std::atomic with memory_order_relaxed.
 */

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace fastmetrics
{

/**
 * @brief Metric type enumeration
 */
enum class MetricType
{
    COUNTER,   ///< Monotonically increasing counter (uint64_t) - PUSH
    GAUGE_INT, ///< Gauge that can go up/down (int64_t) - PUSH
    GAUGE_DBL, ///< Gauge with floating point (double) - PUSH
    PULL       ///< On-demand callback metric (any type) - PULL
};

/**
 * @brief Base interface for all metrics
 */
class IMetric
{
public:
    virtual ~IMetric() = default;

    /**
     * @brief Get metric name
     */
    virtual const std::string& name() const = 0;

    /**
     * @brief Get metric type
     */
    virtual MetricType type() const = 0;

    /**
     * @brief Check if metric is enabled
     */
    virtual bool isEnabled() const = 0;

    /**
     * @brief Enable metric updates
     */
    virtual void enable() = 0;

    /**
     * @brief Disable metric updates (updates become no-ops)
     */
    virtual void disable() = 0;

    /**
     * @brief Reset metric to initial value
     */
    virtual void reset() = 0;

    /**
     * @brief Get current value as double (generic representation)
     *
     * For counters and gauges: returns the current value
     */
    virtual double value() const = 0;
};

/**
 * @brief Counter interface (monotonically increasing)
 */
class ICounter : public IMetric
{
public:
    ~ICounter() override = default;

    /**
     * @brief Increment counter by delta
     * @param delta Amount to add (default: 1)
     */
    virtual void add(uint64_t delta = 1) = 0;

    /**
     * @brief Get current value
     */
    virtual uint64_t get() const = 0;
};

/**
 * @brief Integer gauge interface (can increase or decrease)
 */
class IGaugeInt : public IMetric
{
public:
    ~IGaugeInt() override = default;

    /**
     * @brief Set gauge to specific value
     */
    virtual void set(int64_t value) = 0;

    /**
     * @brief Add to gauge value
     */
    virtual void add(int64_t delta) = 0;

    /**
     * @brief Subtract from gauge value
     */
    virtual void sub(int64_t delta) = 0;

    /**
     * @brief Get current value
     */
    virtual int64_t get() const = 0;
};

/**
 * @brief Double gauge interface (floating point values)
 */
class IGaugeDouble : public IMetric
{
public:
    ~IGaugeDouble() override = default;

    /**
     * @brief Set gauge to specific value
     */
    virtual void set(double value) = 0;

    /**
     * @brief Get current value
     */
    virtual double get() const = 0;
};

} // namespace fastmetrics

#endif // FASTMETRICS_IMETRIC_HPP
