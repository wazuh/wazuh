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
    m_dataHub = std::make_shared<DataHub>();

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

std::shared_ptr<iCounter<double>> MetricsScope::getCounterDouble(const std::string& name)
{
    auto retValue = m_collection_counter_double.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleCounter(name);
        }
    );

    return retValue;
}

std::shared_ptr<iCounter<uint64_t>> MetricsScope::getCounterInteger(const std::string& name)
{
    auto retValue = m_collection_counter_integer.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateUInt64Counter(name);
        }
    );

    return retValue;
}

std::shared_ptr<iCounter<double>> MetricsScope::getUpDownCounterDouble(const std::string& name)
{
    auto retValue = m_collection_updowncounter_double.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleUpDownCounter(name);
        }
    );

    return retValue;
}

std::shared_ptr<iCounter<int64_t>> MetricsScope::getUpDownCounterInteger(const std::string& name)
{
    auto retValue = m_collection_updowncounter_integer.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateInt64UpDownCounter(name);
        }
    );

    return retValue;
}

std::shared_ptr<iHistogram<double>> MetricsScope::getHistogramDouble(const std::string& name)
{
    auto retValue = m_collection_histogram_double.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleHistogram(name);
        }
    );

    return retValue;
}

std::shared_ptr<iHistogram<uint64_t>> MetricsScope::getHistogramInteger(const std::string& name)
{
    auto retValue = m_collection_histogram_integer.getInstrument(
        name, [&]() {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateUInt64Histogram(name);
        }
    );

    return retValue;
}

} // namespace metrics_manager
