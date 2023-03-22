#include <metrics/metricsScope.hpp>

using OTSDKMetricExporter = opentelemetry::sdk::metrics::PushMetricExporter;
using OTSDKMetricReader = opentelemetry::sdk::metrics::MetricReader;
using OTDataHubExporter = opentelemetry::exporter::metrics::DataHubExporter;
using OTSDKPerodicMetricReader = opentelemetry::sdk::metrics::PeriodicExportingMetricReader;
using OTSDKPerodicMetricReaderOptions = opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions;

namespace metrics_manager
{

void MetricsScope::initialize() 
{
    // Create Exporter
    std::unique_ptr<OTSDKMetricExporter> metricExporter(
        new OTDataHubExporter(m_dataHub));

    // Create Reader
    OTSDKPerodicMetricReaderOptions options;
    options.export_interval_millis = std::chrono::milliseconds(500);
    options.export_timeout_millis = std::chrono::milliseconds(500);

    std::unique_ptr<OTSDKMetricReader> metricReader(  
        new OTSDKPerodicMetricReader(std::move(metricExporter), options));

    // Create Provider
    m_meterProvider = std::shared_ptr<OTSDKMeterProvider>(
        new opentelemetry::sdk::metrics::MeterProvider());

    m_meterProvider->AddMetricReader(std::move(metricReader));    
}

} // namespace metrics_manager
