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

Metrics::~Metrics()
{
    std::shared_ptr<opentelemetry::metrics::MeterProvider> noneMeter;
    std::shared_ptr<opentelemetry::trace::TracerProvider> noneTracer;
    opentelemetry::metrics::Provider::SetMeterProvider(noneMeter);
    opentelemetry::trace::Provider::SetTracerProvider(noneTracer);
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

                m_upReader.push_back(std::make_shared<ReaderHandler>());
                break;
            }
            default:
                break;
        }

        std::advance(particularContext, 1);
    }
}

void Metrics::initMetrics(const std::string& moduleName, const std::filesystem::path& file)
{
    m_moduleName = moduleName;

    createCommonChain(file);

    setMetricsConfig();

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
                break;
        }

        (*particularExporter)->handleRequest(*particularContext);

        if ((*particularContext)->providerType == ProviderTypes::Meter)
        {
            if ((*particularContext)->instrumentType == InstrumentTypes::Counter)
            {
                initCounter((*particularContext)->name, (*particularContext)->subType);
            }
            else if ((*particularContext)->instrumentType == InstrumentTypes::Histogram)
            {
                initHistogram((*particularContext)->name, (*particularContext)->subType);
            }
            else if ((*particularContext)->instrumentType == InstrumentTypes::UpDownCounter)
            {
                initUpDownCounter((*particularContext)->name, (*particularContext)->subType);
            }
            else if ((*particularContext)->instrumentType == InstrumentTypes::ObservableGauge)
            {
                initObservableGauge((*particularContext)->name, (*particularContext)->subType);
            }
        }
        else if ((*particularContext)->providerType == ProviderTypes::Tracer)
        {
            initTracer((*particularContext)->name);
        }

        std::advance(particularContext, 1);
        std::advance(particularExporter, 1);
        std::advance(particularProvider, 1);
    }
}

void Metrics::initTracer(const std::string& name)
{
    auto provider = opentelemetry::trace::Provider::GetTracerProvider();
    m_tracers.insert({name, provider->GetTracer(name)});
}

void Metrics::setScopeSpam(const std::string& name) const
{
    if (m_tracers.find(name) != m_tracers.end())
    {
        if(controller.at(name))
        {
            opentelemetry::trace::Scope(m_tracers.at(name)->StartSpan(name));
        }
    }
    else
    {
        throw std::runtime_error {"The Tracer" + name + " has not been created."};
    }
}

void Metrics::initCounter(const std::string& name, SubType subType)
{
    auto counterName = name + "_counter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);

    switch (subType)
    {
        case SubType::Double:
        {
            if (m_doubleCounter.find(name) == m_doubleCounter.end())
            {
                m_doubleCounter.insert({name, meter->CreateDoubleCounter(counterName)});
            }
            else
            {
                throw std::runtime_error {"The Counter " + name + " has already been created."};
            }
            break;
        }
        case SubType::Int64:
        {
            throw std::runtime_error {"Counter type instrument does not accept integers."};
        }
        case SubType::UInt64:
        {
            if (m_uint64Counter.find(name) == m_uint64Counter.end())
            {
                m_uint64Counter.insert({name, meter->CreateUInt64Counter(counterName)});
            }
            else
            {
                throw std::runtime_error {"The Counter " + name + " has already been created."};
            }
        }
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

void Metrics::initHistogram(const std::string& name, SubType subType)
{
    auto histogramName = name + "_histogram";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);

    switch (subType)
    {
        case SubType::Double:
        {
            if (m_doubleHistogram.find(name) == m_doubleHistogram.end())
            {
                m_doubleHistogram.insert({name, meter->CreateDoubleHistogram(histogramName)});
            }
            else
            {
                throw std::runtime_error {"The Histogram " + name + " has already been created."};
            }
            break;
        }
        case SubType::Int64:
        {
            throw std::runtime_error {"Histogram type instrument does not accept integers."};
        }
        case SubType::UInt64:
        {
            if (m_uint64Histogram.find(name) == m_uint64Histogram.end())
            {
                m_uint64Histogram.insert({name, meter->CreateUInt64Histogram(histogramName)});
            }
            else
            {
                throw std::runtime_error {"The Histogram " + name + " has already been created."};
            }
        }
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

void Metrics::addHistogramValue(std::string histogramName, const uint64_t value) const
{
    if (m_uint64Histogram.find(histogramName) != m_uint64Histogram.end())
    {
        if(controller.at(histogramName))
        {
            std::map<std::string, std::string> labels;
            auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};
            m_uint64Histogram.at(histogramName)->Record(value, labelkv, m_context);
        }
    }
    else
    {
        throw std::runtime_error {"The Histogram" + histogramName + " has not been created."};
    }
}

void Metrics::initUpDownCounter(const std::string& name, SubType subType)
{
    auto UpDownCounterName = name + "_upDownCounter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);

    switch (subType)
    {
        case SubType::Double:
        {
            if (m_doubleUpDownCounter.find(name) == m_doubleUpDownCounter.end())
            {
                m_doubleUpDownCounter.insert({name, meter->CreateDoubleUpDownCounter(UpDownCounterName)});
            }
            else
            {
                throw std::runtime_error {"The UpDownCounter " + name + " has already been created."};
            }
            break;
        }
        case SubType::UInt64:
        {
            throw std::runtime_error {"UpDownCounter  type instrument does not accept unsigned integers."};
        }
        case SubType::Int64:
        {
            if (m_int64UpDownCounter.find(name) == m_int64UpDownCounter.end())
            {
                m_int64UpDownCounter.insert({name, meter->CreateInt64UpDownCounter(UpDownCounterName)});
            }
            else
            {
                throw std::runtime_error {"The UpDownCounter " + name + " has already been created."};
            }
        }
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

void Metrics::initObservableGauge(const std::string& name, SubType subType)
{
    auto UpDownCounterName = name + "_observableGauge";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);

    switch (subType)
    {
        case SubType::Double:
        {
            if (m_doubleObservableGauge.find(name) == m_doubleObservableGauge.end())
            {
                m_doubleObservableGauge.insert({name, meter->CreateDoubleObservableGauge(UpDownCounterName)});
            }
            else
            {
                throw std::runtime_error {"The ObservableGauge " + name + " has already been created."};
            }
            break;
        }
        case SubType::UInt64:
        {
            throw std::runtime_error {"ObservableGauge type instrument does not accept unsigned integers."};
        }
        case SubType::Int64:
        {
            if (m_int64ObservableGauge.find(name) == m_int64ObservableGauge.end())
            {
                m_int64ObservableGauge.insert({name, meter->CreateInt64ObservableGauge(UpDownCounterName)});
            }
            else
            {
                throw std::runtime_error {"The ObservableGauge " + name + " has already been created."};
            }
        }
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
