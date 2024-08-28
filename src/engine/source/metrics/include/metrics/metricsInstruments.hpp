#ifndef _METRICS_INSTRUMENTS_H
#define _METRICS_INSTRUMENTS_H

#include <mutex>

#include "opentelemetry/metrics/async_instruments.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"

#include <metrics/iMetricsInstruments.hpp>

namespace metricsManager
{

using OTCallBack = opentelemetry::metrics::ObservableCallbackPtr;
namespace OTstd = opentelemetry::nostd;
namespace OTMetrics = opentelemetry::metrics;

/**
 * @brief Base class for Instruments created in scopes. This holds the enabled status.
 *
 */
class Instrument
{
public:
    /**
     * @brief Sets the enabled status of the instrument.
     *
     * @param newStatus The new enabled status.
     */
    virtual void setEnabledStatus(bool newStatus) { m_status = newStatus; }

    /**
     * @brief Gets the enabled status of the instrument.
     *
     * @param instrumentName The name of the instrument.
     * @return The enabled status of the instrument.
     */
    virtual bool getEnabledStatus() { return m_status; }

private:
    /**
     * @brief Holds the enabled status
     */
    bool m_status {true};
};

/**
 * @brief Template class to build Counter Class. Instrument
 * that encapsulates the Internal OpenTelemetry Object.
 *
 * @tparam T Internal OpenTelemetry object type.
 * @tparam U Basic value type held by the Internal.
 */
template<typename T, typename U>
class Counter
    : public iCounter<U>
    , public Instrument
{
public:
    /**
     * @brief Construct a new Counter object
     *
     * @param ptr A unique pointer to the instrument created with the OpenTelemetry MeterProvider Meter.
     */
    Counter(OTstd::unique_ptr<T> ptr)
        : m_counter {std::move(ptr)}
    {
    }

    /**
     * @brief Adds a value to the counter.
     *
     * @param value The value itself.
     */
    void addValue(const U& value) override
    {
        if (getEnabledStatus())
        {
            m_counter->Add(value);
        }
    }

private:
    /**
     * @brief A unique pointer to the instrument created with the OpenTelemetry MeterProvider.
     */
    OTstd::unique_ptr<T> m_counter;
};

/**
 * @brief Template class to build Histogram Class. Instrument
 * that encapsulates the Internal OpenTelemetry Object.
 *
 * @tparam T Internal OpenTelemetry object type.
 * @tparam U Basic value type held by the Internal.
 */
template<typename T, typename U>
class Histogram
    : public iHistogram<U>
    , public Instrument
{
public:
    /**
     * @brief Construct a new Histogram object
     *
     * @param ptr A unique pointer to the instrument created with the OpenTelemetry MeterProvider Meter.
     */
    Histogram(OTstd::unique_ptr<T> ptr)
        : m_histogram {std::move(ptr)}
    {
    }

    /**
     * @brief Records a value into the histogram.
     *
     * @param value The value itself.
     */
    void recordValue(const U& value) override
    {
        auto context = opentelemetry::context::Context {};
        std::map<std::string, std::string> labels;
        auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)> {labels};

        if (getEnabledStatus())
        {
            m_histogram->Record(value, labelkv, context);
        }
    }

private:
    /**
     * @brief A unique pointer to the instrument created with the OpenTelemetry MeterProvider.
     */
    OTstd::unique_ptr<T> m_histogram;
};

/**
 * @brief Template class to build Gauge Class. Instrument
 * that encapsulates the Internal OpenTelemetry Object.
 *
 * @tparam U Basic value type held by the Internal.
 */
template<typename U>
class Gauge
    : public iGauge<U>
    , public Instrument
{
public:
    /**
     * @brief Construct a new Gauge object
     *
     * @param ptr A shared pointer to the instrument created with the OpenTelemetry MeterProvider Meter.
     */
    Gauge(OTstd::shared_ptr<OTMetrics::ObservableInstrument> ptr)
        : m_gauge {std::move(ptr)}
    {
    }

    /**
     * @brief Registers a callback into the internal instrument that responds when observed.
     *
     * @param callback The callback function.
     * @param id The ID of the instrument.
     * @param defaultValue The default value of the observable instrument before first observation.
     */
    void AddCallback(OTMetrics::ObservableCallbackPtr callback, void* id, U defaultValue)
    {
        m_instrumentCallback = callback;
        m_instrumentId = id;
        m_gauge->AddCallback(callback, id);
        m_value = defaultValue;
    }

    /**
     * @brief Returns the held value to any consumer.
     *
     * @return The Value itself
     */
    U readValue()
    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        U retValue = m_value;
        return retValue;
    }

    /**
     *
     *  @brief Set the Value itself from any producer.
     *
     * @param value
     */
    void setValue(const U& value) override
    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        if (getEnabledStatus())
        {
            m_value = value;
        }
    }

    /**
     * @brief Destroy the Gauge object and removes the internal callback.
     */
    ~Gauge() { m_gauge->RemoveCallback(m_instrumentCallback, m_instrumentId); }

private:
    /**
     * @brief A shared pointer to the instrument created with the OpenTelemetry MeterProvider.
     */
    OTstd::shared_ptr<OTMetrics::ObservableInstrument> m_gauge;

    /**
     * @brief Copy of the internal callback.
     */
    OTMetrics::ObservableCallbackPtr m_instrumentCallback;

    /**
     * @brief Copy of the instrument id.
     */
    void* m_instrumentId;

    /**
     * @brief Synchronization object.
     */
    std::mutex m_mutex;

    /**
     * @brief The Value itself living in Mordor.
     */
    U m_value;
};

} // namespace metricsManager

#endif // _METRICS_INSTRUMENTS_H
