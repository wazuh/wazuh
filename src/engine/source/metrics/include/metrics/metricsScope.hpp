#ifndef _METRICS_SCOPE_H
#define _METRICS_SCOPE_H

#include <string>

#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"

#include <metrics/iMetricsScope.hpp>
#include <metrics/dataHub.hpp>
#include <metrics/dataHubExporter.hpp>

#include <metrics/metricsInstruments.hpp>
#include <metrics/instrumentCollection.hpp>

namespace metrics_manager
{

using OTSDKMeterProvider = opentelemetry::sdk::metrics::MeterProvider;

class MetricsScope : public IMetricsScope
{
public:
    // TODO: Add exceptions
    void initialize();

    json::Json getAllMetrics();
    
    std::shared_ptr<instruments::iCounter<double>> getCounterDouble(const std::string& name) override;
    std::shared_ptr<instruments::iCounter<uint64_t>> getCounterInteger(const std::string& name) override;
    std::shared_ptr<instruments::iCounter<double>> getUpDownCounterDouble(const std::string& name) override;
    std::shared_ptr<instruments::iCounter<int64_t>> getUpDownCounterInteger(const std::string& name) override;
    std::shared_ptr<instruments::iHistogram<double>> getHistogramDouble(const std::string& name) override;
    std::shared_ptr<instruments::iHistogram<uint64_t>> getHistogramInteger(const std::string& name) override;

private:
    std::shared_ptr<DataHub> m_dataHub;
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;

    InstrumentCollection<instruments::Counter<opentelemetry::metrics::Counter<double>, double>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>>> m_collection_counter_double;
    InstrumentCollection<instruments::Counter<opentelemetry::metrics::Counter<uint64_t>, uint64_t>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>> m_collection_counter_integer;
    InstrumentCollection<instruments::Counter<opentelemetry::metrics::UpDownCounter<double>, double>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<double>>> m_collection_updowncounter_double;
    InstrumentCollection<instruments::Counter<opentelemetry::metrics::UpDownCounter<int64_t>, int64_t>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<int64_t>>> m_collection_updowncounter_integer;
    InstrumentCollection<instruments::Histogram<opentelemetry::metrics::Histogram<double>, double>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>> m_collection_histogram_double;
    InstrumentCollection<instruments::Histogram<opentelemetry::metrics::Histogram<uint64_t>, uint64_t>, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<uint64_t>>> m_collection_histogram_integer;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
