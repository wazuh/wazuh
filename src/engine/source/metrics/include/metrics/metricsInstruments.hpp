#ifndef _METRICS_INSTRUMENTS_H
#define _METRICS_INSTRUMENTS_H

#include <metrics/IMetricsInstruments.hpp>
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/metrics/async_instruments.h"

#include <mutex>

namespace metricsManager 
{

namespace OTstd = opentelemetry::nostd;
namespace OTMetrics = opentelemetry::metrics;
using OTCallBack = opentelemetry::metrics::ObservableCallbackPtr;

template <typename T, typename U>
class Counter : public iCounter<U>
{
public:
    Counter(OTstd::unique_ptr<T> ptr):
    m_counter{std::move(ptr)}
    {
    }

    void addValue(const U& value) override
    {
        if (iInstrument::m_status)
        {
            m_counter->Add(value);
        }
    }
private:
    OTstd::unique_ptr<T> m_counter;
};

template <typename T, typename U>
class Histogram : public iHistogram<U>
{
public:
    Histogram(OTstd::unique_ptr<T> ptr):
    m_histogram{std::move(ptr)}
    {
    }

    void recordValue(const U& value) override
    {
        auto context = opentelemetry::context::Context{};
        std::map<std::string, std::string> labels;
        auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};

        if (iInstrument::m_status)
        {
            m_histogram->Record(value, labelkv, context);
        }
    }
private:
    OTstd::unique_ptr<T> m_histogram;
};

template <typename U>
class Gauge : public iGauge<U>
{
public:
    Gauge(OTstd::shared_ptr<OTMetrics::ObservableInstrument> ptr):
    m_gauge{std::move(ptr)}
    {
    }

    void AddCallback(
        OTMetrics::ObservableCallbackPtr callback, 
        void* id, 
        U defaultValue)
    {
        m_instrumentCallback = callback;
        m_instrumentId = id;
        m_gauge->AddCallback(callback, id);
        m_value = defaultValue;
    }

    U readValue()
    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        U retValue = m_value;
        return retValue;
    }

    void setValue(const U& value) override 
    {
        const std::lock_guard<std::mutex> lock(m_mutex);     
        if (iInstrument::m_status)
        {
            m_value = value;
        }
    }

    ~Gauge() 
    {
        m_gauge->RemoveCallback(m_instrumentCallback, m_instrumentId);
    }

private:
    OTstd::shared_ptr<OTMetrics::ObservableInstrument> m_gauge;
    
    OTMetrics::ObservableCallbackPtr m_instrumentCallback;
    void* m_instrumentId;
    
    std::mutex m_mutex;

    U m_value;
};

} // namespace metricsManager

#endif // _METRICS_INSTRUMENTS_H
