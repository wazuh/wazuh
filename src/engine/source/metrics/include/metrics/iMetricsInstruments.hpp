#ifndef _I_METRICS_INSTRUMENTS_H
#define _I_METRICS_INSTRUMENTS_H

#include <cstdint>

namespace metricsManager
{

/**
 * @brief Interface class Counter
 *
 * @tparam T Internal OpenTelemetry value type.
 */
template<typename T>
class iCounter
{
public:
    /**
     * @brief Adds a Value to the Counter
     *
     * @param value The value itself.
     */
    virtual void addValue(const T& value) = 0;
};

/**
 * @brief Interface class Histogram
 *
 * @tparam T Internal OpenTelemetry value type.
 */
template<typename T>
class iHistogram
{
public:
    /**
     * @brief Records a value into the histogram.
     *
     * @param value The value itself.
     */
    virtual void recordValue(const T& value) = 0;
};

/**
 * @brief Interface class Gauge.
 *
 * @tparam T Internal OpenTelemetry value type.
 */
template<typename T>
class iGauge
{
public:
    /**
     * @brief Set the Value that will be observed.
     *
     * @param value The value itself
     */
    virtual void setValue(const T& value) = 0;
};

} // namespace metricsManager

#endif // _I_METRICS_INSTRUMENTS_H
