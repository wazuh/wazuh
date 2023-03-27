#ifndef _I_METRICS_INSTRUMENTS_H
#define _I_METRICS_INSTRUMENTS_H

#include <cstdint>

namespace metrics_manager 
{

namespace instruments
{

template <typename T>
class iCounter
{
public:
    virtual void addValue(const T &value) = 0;
};

template <typename T>
class iHistogram
{
public:
    virtual void recordValue(const T &value) = 0;
};

} // namespace instruments

} // namespace metrics_manager

#endif // _I_METRICS_INSTRUMENTS_H

/*
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>>
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<uint64_t>>
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<double>>
opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<int64_t>>
opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument>
opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument>
*/