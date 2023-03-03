#include <stdexcept>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "metrics.hpp"
#include "processorHandler.hpp"
#include "exporterHandler.hpp"
#include "readerHandler.hpp"
#include "providerHandler.hpp"
#include "opentelemetry/metrics/provider.h"
#include <logging/logging.hpp>

std::unordered_map<std::string, ProviderTypes> const PROVIDER_TYPES =
{
    {"meter", ProviderTypes::Meter},
    {"tracer", ProviderTypes::Tracer}
};

std::unordered_map<std::string, InstrumentTypes> const INSTRUMENT_TYPES =
{
    {"counter", InstrumentTypes::Counter},
    {"histogram", InstrumentTypes::Histogram},
    {"upDownCounter", InstrumentTypes::UpDownCounter},
    {"observableGauge", InstrumentTypes::ObservableGauge}
};

std::unordered_map<std::string, SubType> const SUB_TYPES =
{
    {"double", SubType::Double},
    {"int64", SubType::Int64},
    {"uint64", SubType::UInt64}
};

std::unordered_map<std::string, ExportersTypes> const EXPORTER_TYPES =
{
    {"logging", ExportersTypes::Logging},
    {"memory", ExportersTypes::Memory},
    {"zipkin", ExportersTypes::Zipkin}
};

std::unordered_map<std::string, ProcessorsTypes> const PROCESSOR_TYPES =
{
    {"simple", ProcessorsTypes::Simple},
    {"batch", ProcessorsTypes::Batch}
};

Metrics::Metrics() 
{
    m_dataHub = std::make_shared<DataHub>();
}

void Metrics::clean()
{
    std::shared_ptr<opentelemetry::metrics::MeterProvider> noneMeter;
    std::shared_ptr<opentelemetry::trace::TracerProvider> noneTracer;
    opentelemetry::metrics::Provider::SetMeterProvider(noneMeter);
    opentelemetry::trace::Provider::SetTracerProvider(noneTracer);

    for(auto &context : m_upContext)
    {
        if (context->file.is_open())
        {
            context->file.close();
        }
    }
}

std::shared_ptr<DataHub> Metrics::getDataHub()
{
    return m_dataHub;
}

nlohmann::json Metrics::loadJson(const std::filesystem::path& file)
{
    std::ifstream jsonFile(file);

    if (!jsonFile.is_open())
    {
        throw std::runtime_error("Could not open JSON file: " + file.string());
    }

    return nlohmann::json::parse(jsonFile);
}

void Metrics::createCommonChain(const std::filesystem::path& file)
{
    m_contextFile = loadJson(file);

    for (auto& config : m_contextFile)
    {
        m_upContext.push_back(std::make_shared<MetricsContext>());
        m_upExporter.push_back(std::make_shared<ExporterHandler>());
        m_upProvider.push_back(std::make_shared<ProviderHandler>());
    }
}

void Metrics::setMetricsConfig()
{
    auto particularContext = m_upContext.begin();

    for (auto& config : m_contextFile)
    {
        (*particularContext)->providerType = PROVIDER_TYPES.at(config.at("signalType"));
        (*particularContext)->name = config.at("name");
        (*particularContext)->enable = config.at("enable");
        (*particularContext)->dataHubEnable = config.at("dataHubEnable");
        (*particularContext)->description = config.at("description");

        if (config.contains("outputFile"))
        {
            (*particularContext)->outputFile = config.at("outputFile");
        }

        controller.insert({(*particularContext)->name, (*particularContext)->enable});

        switch ((*particularContext)->providerType)
        {
            case ProviderTypes::Tracer:
            {
                (*particularContext)->exporterType = EXPORTER_TYPES.at(config.at("exporterType"));
                (*particularContext)->processorType = PROCESSOR_TYPES.at(config.at("processorType"));

                m_upProcessor.push_back(std::make_shared<ProcessorHandler>());
                break;
            }
            case ProviderTypes::Meter:
            {
                (*particularContext)->instrumentType = INSTRUMENT_TYPES.at(config.at("instrumentType"));
                (*particularContext)->subType = SUB_TYPES.at(config.at("subType"));
                (*particularContext)->export_interval_millis = static_cast<std::chrono::milliseconds>(config.at("exportIntervalMillis"));
                (*particularContext)->export_timeout_millis = static_cast<std::chrono::milliseconds>(config.at("exportTimeoutMillis"));
                (*particularContext)->unit = config.at("unit");

                m_upReader.push_back(std::make_shared<ReaderHandler>());
                break;
            }
            default:
                throw std::runtime_error {"Failure to evaluate type of provider"};
        }

        std::advance(particularContext, 1);
    }
}

void Metrics::setInstrumentConfig(const std::shared_ptr<MetricsContext> context)
{
    switch (context->providerType)
    {
        case ProviderTypes::Meter:
        {
            if (context->instrumentType == InstrumentTypes::Counter)
            {
                initCounter(context);
                break;
            }
            else if (context->instrumentType == InstrumentTypes::Histogram)
            {
                initHistogram(context);
                break;
            }
            else if (context->instrumentType == InstrumentTypes::UpDownCounter)
            {
                initUpDownCounter(context);
                break;
            }
            else if (context->instrumentType == InstrumentTypes::ObservableGauge)
            {
                initObservableGauge(context);
                break;
            }
        }
        case ProviderTypes::Tracer:
        {
            initTracer(context);
            break;
        }
        default:
            throw std::runtime_error {"Failure to evaluate type of provider"};
    }
}

void Metrics::createFullChain()
{
    auto particularContext = m_upContext.begin();
    auto particularExporter = m_upExporter.begin();
    auto particularProvider = m_upProvider.begin();

    for (auto& config : m_contextFile)
    {
        switch ((*particularContext)->providerType)
        {
            case ProviderTypes::Tracer:
            {
                auto particularProcessor = m_upProcessor.begin();
                (*particularExporter)->setNext(*particularProcessor)->setNext(*particularProvider);
                std::advance(particularProcessor, 1);
                break;
            }
            case ProviderTypes::Meter:
            {
                auto particularReader = m_upReader.begin();
                (*particularExporter)->setNext(*particularReader)->setNext(*particularProvider);
                std::advance(particularReader, 1);
                break;
            }
            default:
                throw std::runtime_error {"Failure to evaluate type of provider"};
        }

        (*particularExporter)->handleRequest(*particularContext);

        setInstrumentConfig(*particularContext);

        std::advance(particularContext, 1);
        std::advance(particularExporter, 1);
        std::advance(particularProvider, 1);
    }
}

void Metrics::initMetrics(const std::string& moduleName, const std::filesystem::path& file)
{
    m_moduleName = moduleName;

    opentelemetry::sdk::common::internal_log::GlobalLogHandler::SetLogLevel(opentelemetry::sdk::common::internal_log::LogLevel::Error);

    createCommonChain(file);

    setMetricsConfig();

    createFullChain();
}

void Metrics::initTracer(const std::shared_ptr<MetricsContext> context)
{
    auto provider = opentelemetry::trace::Provider::GetTracerProvider();
    m_spProvider = provider->GetTracer(m_moduleName);
}

void Metrics::setScopeSpan(const std::string& name) const
{
    opentelemetry::trace::Scope(m_spProvider->StartSpan(name));
}

void Metrics::initCounter(const std::shared_ptr<MetricsContext> context)
{
    auto counterName = context->name + "_counter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(context->name);

    switch (context->subType)
    {
        case SubType::Double:
        {
            if (m_doubleCounter.find(context->name) == m_doubleCounter.end())
            {
                m_doubleCounter.insert({context->name, meter->CreateDoubleCounter(counterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The Counter " + context->name + " has already been created."};
            }
        }
        case SubType::Int64:
        {
            throw std::runtime_error {"Counter type instrument does not accept integers."};
        }
        case SubType::UInt64:
        {
            if (m_uint64Counter.find(context->name) == m_uint64Counter.end())
            {
                m_uint64Counter.insert({context->name, meter->CreateUInt64Counter(counterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The Counter " + context->name + " has already been created."};
            }
        }
        default:
            throw std::runtime_error {"Failure to evaluate type of metering instrument"};
    }
}

void Metrics::addCounterValue(std::string counterName, const double value) const
{
    if (m_doubleCounter.find(counterName) != m_doubleCounter.end())
    {
        if(controller.at(counterName))
        {
            m_doubleCounter.at(counterName)->Add(value);
        }
    }
    else
    {
        throw std::runtime_error {"The Counter" + counterName + " has not been created."};
    }
}

void Metrics::addCounterValue(std::string counterName, const uint64_t value) const
{
    if (m_uint64Counter.find(counterName) != m_uint64Counter.end())
    {
        if(controller.at(counterName))
        {
            m_uint64Counter.at(counterName)->Add(value);
        }
    }
    else
    {
        throw std::runtime_error {"The Counter" + counterName + " has not been created."};
    }
}

void Metrics::initHistogram(const std::shared_ptr<MetricsContext> context)
{
    auto histogramName = context->name + "_histogram";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(context->name);

    switch (context->subType)
    {
        case SubType::Double:
        {
            if (m_doubleHistogram.find(context->name) == m_doubleHistogram.end())
            {
                m_doubleHistogram.insert({context->name, meter->CreateDoubleHistogram(histogramName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The Histogram " + context->name + " has already been created."};
            }
        }
        case SubType::Int64:
        {
            throw std::runtime_error {"Histogram type instrument does not accept integers."};
        }
        case SubType::UInt64:
        {
            if (m_uint64Histogram.find(context->name) == m_uint64Histogram.end())
            {
                m_uint64Histogram.insert({context->name, meter->CreateUInt64Histogram(histogramName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The Histogram " + context->name + " has already been created."};
            }
        }
        default:
            throw std::runtime_error {"Failure to evaluate type of metering instrument"};
    }

    m_context = opentelemetry::context::Context{};
}

void Metrics::addHistogramValue(std::string histogramName, const double value) const
{
    if (m_doubleHistogram.find(histogramName) != m_doubleHistogram.end())
    {
        if(controller.at(histogramName))
        {
            std::map<std::string, std::string> labels;
            auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};
            m_doubleHistogram.at(histogramName)->Record(value, labelkv, m_context);
        }
    }
    else
    {
        throw std::runtime_error {"The Histogram" + histogramName + " has not been created."};
    }
}

void Metrics::addHistogramValue(std::string histogramName, const uint64_t value, std::map<std::string, std::string> labels) const
{
    if (m_uint64Histogram.find(histogramName) != m_uint64Histogram.end())
    {
        if(controller.at(histogramName))
        {
            auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};
            m_uint64Histogram.at(histogramName)->Record(value, labelkv, m_context);
        }
    }
    else
    {
        throw std::runtime_error {"The Histogram" + histogramName + " has not been created."};
    }
}

void Metrics::initUpDownCounter(const std::shared_ptr<MetricsContext> context)
{
    auto UpDownCounterName = context->name + "_upDownCounter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(context->name);

    switch (context->subType)
    {
        case SubType::Double:
        {
            if (m_doubleUpDownCounter.find(context->name) == m_doubleUpDownCounter.end())
            {
                m_doubleUpDownCounter.insert({context->name, meter->CreateDoubleUpDownCounter(UpDownCounterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The UpDownCounter " + context->name + " has already been created."};
            }
        }
        case SubType::UInt64:
        {
            throw std::runtime_error {"UpDownCounter  type instrument does not accept unsigned integers."};
        }
        case SubType::Int64:
        {
            if (m_int64UpDownCounter.find(context->name) == m_int64UpDownCounter.end())
            {
                m_int64UpDownCounter.insert({context->name, meter->CreateInt64UpDownCounter(UpDownCounterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The UpDownCounter " + context->name + " has already been created."};
            }
        }
        default:
            throw std::runtime_error {"Failure to evaluate type of metering instrument"};
    }
}

void Metrics::addUpDownCounterValue(std::string upDownCounterName, const double value) const
{
    if (m_doubleUpDownCounter.find(upDownCounterName) != m_doubleUpDownCounter.end())
    {
        if(controller.at(upDownCounterName))
        {
            m_doubleUpDownCounter.at(upDownCounterName)->Add(value);
        }
    }
    else
    {
        throw std::runtime_error {"The UpDownCounter" + upDownCounterName + " has not been created."};
    }
}

void Metrics::addUpDownCounterValue(std::string upDownCounterName, const int64_t value) const
{
    if (m_int64UpDownCounter.find(upDownCounterName) != m_int64UpDownCounter.end())
    {
        if(controller.at(upDownCounterName))
        {
            m_int64UpDownCounter.at(upDownCounterName)->Add(value);
        }
    }
    else
    {
        throw std::runtime_error {"The UpDownCounter" + upDownCounterName + " has not been created."};
    }
}

void Metrics::initObservableGauge(const std::shared_ptr<MetricsContext> context)
{
    auto UpDownCounterName = context->name + "_observableGauge";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(context->name);

    switch (context->subType)
    {
        case SubType::Double:
        {
            if (m_doubleObservableGauge.find(context->name) == m_doubleObservableGauge.end())
            {
                m_doubleObservableGauge.insert({context->name, meter->CreateDoubleObservableGauge(UpDownCounterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The ObservableGauge " + context->name + " has already been created."};
            }
        }
        case SubType::UInt64:
        {
            throw std::runtime_error {"ObservableGauge type instrument does not accept unsigned integers."};
        }
        case SubType::Int64:
        {
            if (m_int64ObservableGauge.find(context->name) == m_int64ObservableGauge.end())
            {
                m_int64ObservableGauge.insert({context->name, meter->CreateInt64ObservableGauge(UpDownCounterName, context->description, context->unit)});
                break;
            }
            else
            {
                throw std::runtime_error {"The ObservableGauge " + context->name + " has already been created."};
            }
        }
        default:
            throw std::runtime_error {"Failure to evaluate type of metering instrument"};
    }
}

void Metrics::addObservableGauge(std::string observableGaugeName, opentelemetry::v1::metrics::ObservableCallbackPtr callback) const
{
    if (m_doubleObservableGauge.find(observableGaugeName) != m_doubleObservableGauge.end())
    {
        if(controller.at(observableGaugeName))
        {
            m_doubleObservableGauge.at(observableGaugeName)->AddCallback(callback, nullptr);
        }
    }
    else if (m_int64ObservableGauge.find(observableGaugeName) != m_int64ObservableGauge.end())
    {
        if(controller.at(observableGaugeName))
        {
            m_int64ObservableGauge.at(observableGaugeName)->AddCallback(callback, nullptr);
        }
    }
    else
    {
        throw std::runtime_error {"The UpDownCounter" + observableGaugeName + " has not been created."};
    }
}

void Metrics::removeObservableGauge(std::string observableGaugeName, opentelemetry::v1::metrics::ObservableCallbackPtr callback) const
{
    if (m_doubleObservableGauge.find(observableGaugeName) != m_doubleObservableGauge.end())
    {
        if(controller.at(observableGaugeName))
        {
            m_doubleObservableGauge.at(observableGaugeName)->RemoveCallback(callback, nullptr);
        }
    }
    else if (m_int64ObservableGauge.find(observableGaugeName) != m_int64ObservableGauge.end())
    {
        if(controller.at(observableGaugeName))
        {
            m_int64ObservableGauge.at(observableGaugeName)->RemoveCallback(callback, nullptr);
        }
    }
    else
    {
        throw std::runtime_error {"The UpDownCounter" + observableGaugeName + " has not been created."};
    }
}
