#include <metrics/metricsScope.hpp>

using OTSDKMetricExporter = opentelemetry::sdk::metrics::PushMetricExporter;
using OTSDKMetricReader = opentelemetry::sdk::metrics::MetricReader;
using OTDataHubExporter = opentelemetry::exporter::metrics::DataHubExporter;
using OTSDKPerodicMetricReader = opentelemetry::sdk::metrics::PeriodicExportingMetricReader;
using OTSDKPerodicMetricReaderOptions = opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions;
using OTGaugeInteger = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<int64_t>>;
using OTGaugeDouble = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<double>>;
using OTTemporality = opentelemetry::v1::sdk::metrics::AggregationTemporality;

namespace metricsManager
{

void MetricsScope::initialize(bool delta, int exporterIntervalMS, int exporterTimeoutMS)
{
    m_dataHub = std::make_shared<DataHub>();

    // Create Exporter
    OTTemporality temporality = delta?(OTTemporality::kDelta):(OTTemporality::kCumulative);
    std::unique_ptr<OTSDKMetricExporter> metricExporter(new OTDataHubExporter(m_dataHub, temporality));

    // Create Reader
    OTSDKPerodicMetricReaderOptions options;
    options.export_interval_millis = std::chrono::milliseconds(exporterIntervalMS);
    options.export_timeout_millis = std::chrono::milliseconds(exporterTimeoutMS);

    std::unique_ptr<OTSDKMetricReader> metricReader(new OTSDKPerodicMetricReader(std::move(metricExporter), options));

    // Create Provider
    m_meterProvider = std::shared_ptr<OTSDKMeterProvider>(new opentelemetry::sdk::metrics::MeterProvider());

    m_meterProvider->AddMetricReader(std::move(metricReader));
}

json::Json MetricsScope::getAllMetrics(const std::string& metricsInstrumentName)
{
    if (metricsInstrumentName.empty())
    {
        return m_dataHub->getAllResources();
    }
    else
    {
        return m_dataHub->getResource(metricsInstrumentName);
    }
}

std::shared_ptr<iCounter<double>> MetricsScope::getCounterDouble(const std::string& name)
{
    auto retValue = m_collection_counter_double.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleCounter(name);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iCounter<uint64_t>> MetricsScope::getCounterUInteger(const std::string& name)
{
    auto retValue = m_collection_counter_integer.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateUInt64Counter(name);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iCounter<double>> MetricsScope::getUpDownCounterDouble(const std::string& name)
{
    auto retValue = m_collection_updowncounter_double.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleUpDownCounter(name);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iCounter<int64_t>> MetricsScope::getUpDownCounterInteger(const std::string& name)
{
    auto retValue = m_collection_updowncounter_integer.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateInt64UpDownCounter(name);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iHistogram<double>> MetricsScope::getHistogramDouble(const std::string& name)
{
    auto retValue = m_collection_histogram_double.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateDoubleHistogram(name);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iHistogram<uint64_t>> MetricsScope::getHistogramUInteger(const std::string& name)
{
    auto retValue = m_collection_histogram_integer.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            return meter->CreateUInt64Histogram(name);
        });

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iGauge<int64_t>> MetricsScope::getGaugeInteger(const std::string& name, int64_t defaultValue)
{
    auto retValue = m_collection_gauge_integer.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            auto retValue = meter->CreateInt64ObservableGauge(name);
            return retValue;
        },
        [&](const std::shared_ptr<Gauge<int64_t>>& gauge)
        {
            gauge->AddCallback(MetricsScope::FetcherInteger, static_cast<void*>(gauge.get()), defaultValue);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

std::shared_ptr<iGauge<double>> MetricsScope::getGaugeDouble(const std::string& name, double defaultValue)
{
    auto retValue = m_collection_gauge_double.getInstrument(
        name,
        [&]()
        {
            auto meter = m_meterProvider->GetMeter(name);
            auto retValue = meter->CreateDoubleObservableGauge(name);
            return retValue;
        },
        [&](const std::shared_ptr<Gauge<double>>& gauge)
        {
            gauge->AddCallback(MetricsScope::FetcherDouble, static_cast<void*>(gauge.get()), defaultValue);
        }
    );

    registerInstrument(name, retValue);

    return retValue;
}

void MetricsScope::FetcherInteger(opentelemetry::metrics::ObserverResult observer_result, void* id)
{
    if (opentelemetry::nostd::holds_alternative<OTGaugeInteger>(observer_result))
    {
        Gauge<int64_t>* gauge = (Gauge<int64_t>*)id;
        int64_t value = gauge->readValue();
        opentelemetry::nostd::get<OTGaugeInteger>(observer_result)->Observe(value);
    }
}

void MetricsScope::FetcherDouble(opentelemetry::metrics::ObserverResult observer_result, void* id)
{
    if (opentelemetry::nostd::holds_alternative<
            OTGaugeDouble>(observer_result))
    {
        Gauge<double>* gauge = (Gauge<double>*)id;
        double value = gauge->readValue();
        opentelemetry::nostd::get<OTGaugeDouble>(observer_result)->Observe(value);
    }
}

bool MetricsScope::setEnabledStatus(const std::string& instrumentName, bool newStatus)
{
    auto instrument = getInstrument(instrumentName);
    if (instrument == nullptr)
    {
        return false;
    }
    instrument->setEnabledStatus(newStatus);
    return true;
}

bool MetricsScope::getEnabledStatus(const std::string& instrumentName)
{
    return getInstrument(instrumentName)->getEnabledStatus();
}

void MetricsScope::registerInstrument(const std::string& name, const std::shared_ptr<Instrument>& instrument)
{
    auto it = m_namesMap.find(name);
    if (it == m_namesMap.end())
    {
        m_namesMap.insert(std::make_pair(name, instrument));
    }
}

std::shared_ptr<Instrument> MetricsScope::getInstrument(const std::string& name)
{
    auto it = m_namesMap.find(name);
    if (it != m_namesMap.end())
    {
        return m_namesMap[name];
    }
    else
    {
        return nullptr;
    }
}

} // namespace metricsManager
