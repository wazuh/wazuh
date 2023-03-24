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
    options.export_interval_millis = std::chrono::milliseconds(700);
    options.export_timeout_millis = std::chrono::milliseconds(500);

    std::unique_ptr<OTSDKMetricReader> metricReader(  
        new OTSDKPerodicMetricReader(std::move(metricExporter), options));

    // Create Provider
    m_meterProvider = std::shared_ptr<OTSDKMeterProvider>(
        new opentelemetry::sdk::metrics::MeterProvider());

    m_meterProvider->AddMetricReader(std::move(metricReader));    
}

json::Json MetricsScope::getAllMetrics()
{
    return m_dataHub->getAllResources();
}

std::shared_ptr<instruments::iCounterDouble> MetricsScope::getCounterDouble(const std::string& name)
{
    auto it = m_instruments.find(name);
    if (m_instruments.end() == it)
    {
        opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = m_meterProvider->GetMeter(name);
        auto newMeter = meter->CreateDoubleCounter(name);
        std::shared_ptr<instruments::CounterDouble> newInstrument = std::make_shared<instruments::CounterDouble>(std::move(newMeter));
        m_instruments.insert(
            std::make_pair<std::string, std::shared_ptr<instruments::CounterDouble>>(std::string(name), std::move(newInstrument)));
    }

    return m_instruments[name];
}

} // namespace metrics_manager
