#ifndef _METRICS_INSTRUMENTS_H
#define _METRICS_INSTRUMENTS_H

#include <metrics/IMetricsInstruments.hpp>
#include "opentelemetry/sdk/metrics/meter_provider.h"

namespace metrics_manager 
{

template <typename T, typename U>
class Counter : public iCounter<U>
{
public:
    Counter(opentelemetry::nostd::unique_ptr<T> ptr):
    m_counter{std::move(ptr)}
    {
    }

    void addValue(const U& value) override
    {
        m_counter->Add(value);
    }
private:
    opentelemetry::nostd::unique_ptr<T> m_counter;
};

template <typename T, typename U>
class Histogram : public iHistogram<U>
{
public:
    Histogram(opentelemetry::nostd::unique_ptr<T> ptr):
    m_histogram{std::move(ptr)}
    {
    }

    void recordValue(const U& value) override
    {
        auto context = opentelemetry::context::Context{};
        std::map<std::string, std::string> labels;
        auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};

        m_histogram->Record(value, labelkv, context);
    }
private:
    opentelemetry::nostd::unique_ptr<T> m_histogram;
};

} // namespace metrics_manager

#endif // _METRICS_INSTRUMENTS_H
