#ifndef _METRICS_INSTRUMENTS_H
#define _METRICS_INSTRUMENTS_H

#include <metrics/IMetricsInstruments.hpp>
#include "opentelemetry/sdk/metrics/meter_provider.h"

namespace metrics_manager 
{

namespace instruments
{
    class CounterDouble : public iCounterDouble
    {
    public:
        CounterDouble(opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>> ptr );
        
        void addValue(const double &value) override;

    private:
        opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>> m_counter;
    };

    class CounterInteger : public iCounterInteger
    {
    public:
        CounterInteger(opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>> ptr );
        
        void addValue(const uint64_t &value) override;

    private:
        opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>> m_counter;
    };

} // namespace instruments

} // namespace metrics_manager

#endif // _METRICS_INSTRUMENTS_H