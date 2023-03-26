#include <metrics/metricsScope.hpp>

using OTSDKMetricExporter = opentelemetry::sdk::metrics::PushMetricExporter;
using OTSDKMetricReader = opentelemetry::sdk::metrics::MetricReader;
using OTDataHubExporter = opentelemetry::exporter::metrics::DataHubExporter;
using OTSDKPerodicMetricReader = opentelemetry::sdk::metrics::PeriodicExportingMetricReader;
using OTSDKPerodicMetricReaderOptions = opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions;

using namespace metrics_manager::instruments;

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

std::shared_ptr<iCounterDouble> MetricsScope::getCounterDouble(const std::string& name)
{
    auto it = m_instruments_counter_double.find(name);
    if (m_instruments_counter_double.end() == it)
    {
        auto meter = m_meterProvider->GetMeter(name);
        auto newCounter = meter->CreateDoubleCounter(name);

        std::shared_ptr<CounterDouble> newInstrument = 
            std::make_shared<CounterDouble>(std::move(newCounter));

        m_instruments_counter_double.insert(
            std::make_pair<std::string, std::shared_ptr<CounterDouble>>(
                std::string(name),
                std::move(newInstrument)));
    }

    return m_instruments_counter_double[name];
}

std::shared_ptr<iCounterInteger> MetricsScope::getCounterInteger(const std::string& name)
{
    auto it = m_instruments_counter_integer.find(name);
    if (m_instruments_counter_integer.end() == it)
    {
        auto meter = m_meterProvider->GetMeter(name);
        auto newCounter = meter->CreateUInt64Counter(name);

        std::shared_ptr<CounterInteger> newInstrument = 
            std::make_shared<CounterInteger>(std::move(newCounter));

        m_instruments_counter_integer.insert(
            std::make_pair<std::string, std::shared_ptr<CounterInteger>>(
                std::string(name),
                std::move(newInstrument)));
    }

    return m_instruments_counter_integer[name];
}

} // namespace metrics_manager
