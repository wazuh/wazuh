#ifndef _I_METRICS_INSTRUMENTS_H
#define _I_METRICS_INSTRUMENTS_H

namespace metrics_manager 
{

namespace instruments
{

class iCounterDouble
{
public:
    virtual void addValue(const double &value) = 0;
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