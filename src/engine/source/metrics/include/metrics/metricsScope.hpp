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

namespace OTMetrics = opentelemetry::metrics;
namespace OTstd = opentelemetry::nostd;

class MetricsScope : public IMetricsScope
{
public:
    // TODO: Add exceptions
    void initialize();

    json::Json getAllMetrics();
    
    std::shared_ptr<iCounter<double>>
        getCounterDouble(const std::string& name) override;

    std::shared_ptr<iCounter<uint64_t>>
        getCounterInteger(const std::string& name) override;

    std::shared_ptr<iCounter<double>>
        getUpDownCounterDouble(const std::string& name) override;

    std::shared_ptr<iCounter<int64_t>>
        getUpDownCounterInteger(const std::string& name) override;

    std::shared_ptr<iHistogram<double>> 
        getHistogramDouble(const std::string& name) override;

    std::shared_ptr<iHistogram<uint64_t>>
        getHistogramInteger(const std::string& name) override;

private:
    std::shared_ptr<DataHub> m_dataHub;
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;

    InstrumentCollection<
        Counter< OTMetrics::Counter<double>, double >, 
        OTstd::unique_ptr< OTMetrics::Counter<double> >
    > m_collection_counter_double;

    InstrumentCollection<
        Counter< OTMetrics::Counter<uint64_t>, uint64_t >,
        OTstd::unique_ptr< OTMetrics::Counter<uint64_t> >
    > m_collection_counter_integer;

    InstrumentCollection<
        Counter< OTMetrics::UpDownCounter<double>, double >,
        OTstd::unique_ptr< OTMetrics::UpDownCounter<double> > 
    > m_collection_updowncounter_double;

    InstrumentCollection<
        Counter< OTMetrics::UpDownCounter<int64_t>, int64_t >,
        OTstd::unique_ptr< OTMetrics::UpDownCounter<int64_t> >
    > m_collection_updowncounter_integer;

    InstrumentCollection<
        Histogram< OTMetrics::Histogram<double>, double >,
        OTstd::unique_ptr< OTMetrics::Histogram<double> >
    > m_collection_histogram_double;

    InstrumentCollection<
        Histogram< OTMetrics::Histogram<uint64_t>, uint64_t>,
        OTstd::unique_ptr< OTMetrics::Histogram<uint64_t> >
    > m_collection_histogram_integer;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
