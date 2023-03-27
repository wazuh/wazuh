#ifndef _METRICS_INSTRUMENTS_H
#define _METRICS_INSTRUMENTS_H

#include <metrics/IMetricsInstruments.hpp>
#include "opentelemetry/sdk/metrics/meter_provider.h"

namespace metrics_manager 
{

namespace instruments
{
    template <typename T, typename U>
    class Counter : public iCounter<U>
    {
    public:
        Counter(opentelemetry::nostd::unique_ptr<T> ptr):
        m_counter{std::move(ptr)}
        {}

        void addValue(const U& value) override
        {
            m_counter->Add(value);
        }

    private:
        opentelemetry::nostd::unique_ptr<T> m_counter;
    };

} // namespace instruments

} // namespace metrics_manager

#endif // _METRICS_INSTRUMENTS_H