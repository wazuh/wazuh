#include <metrics/metricsInstruments.hpp>

namespace metrics_manager 
{

namespace instruments
{

CounterDouble::CounterDouble(opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>> ptr )
: m_counter{std::move(ptr)} 
{
}

void CounterDouble::addValue(const double &value)
{
    m_counter->Add(value);
}

CounterInteger::CounterInteger(opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>> ptr )
: m_counter{std::move(ptr)} 
{
}

void CounterInteger::addValue(const uint64_t &value)
{
    m_counter->Add(value);
}


} // namespace instruments

} // namespace metrics_manager