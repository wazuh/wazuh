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

std::unordered_map<std::string, ProviderTypes> const PROVIDER_TYPES =
{
    {"meter", ProviderTypes::Meter},
    {"tracer", ProviderTypes::Tracer}
};

std::unordered_map<std::string, InstrumentTypes> const INSTRUMENT_TYPES =
{
    {"counter", InstrumentTypes::Counter},
    {"histrogram", InstrumentTypes::Histogram}
};

Metrics::~Metrics()
{
    std::shared_ptr<opentelemetry::metrics::MeterProvider> none;
    opentelemetry::metrics::Provider::SetMeterProvider(none);
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

void Metrics::createContext(const std::filesystem::path& file)
{
    m_contextFile = loadJson(file);
    for (auto& config : m_contextFile)
    {
        m_upContext.push_back(std::make_shared<MetricsContext>());
        m_upExporter.push_back(std::make_shared<ExporterHandler>());
        m_upProvider.push_back(std::make_shared<ProviderHandler>());
    }
}

void Metrics::setContext()
{
    auto particularContext = m_upContext.begin();

    for (auto& config : m_contextFile)
    {
        (*particularContext)->providerType = PROVIDER_TYPES.at(config.at("signalType"));
        (*particularContext)->instrumentType = INSTRUMENT_TYPES.at(config.at("subtype"));
        (*particularContext)->loggingFileExport = config.at("loggingFileExport");
        (*particularContext)->export_interval_millis = static_cast<std::chrono::milliseconds>(config.at("exportIntervalMillis"));
        (*particularContext)->export_timeout_millis = static_cast<std::chrono::milliseconds>(config.at("exportTimeoutMillis"));
        (*particularContext)->outputFile = config.at("outputFile");
        (*particularContext)->counterName = config.at("name");
        (*particularContext)->enable = config.at("enable");

        controller.insert({(*particularContext)->counterName, (*particularContext)->enable});

        switch ((*particularContext)->providerType)
        {
            case ProviderTypes::Tracer:
            {
                m_upProcessor.push_back(std::make_shared<ProcessorHandler>());
                break;
            }
            case ProviderTypes::Meter:
            {
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

    createContext(file);

    setContext();

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
                initCounter((*particularContext)->counterName);
            }
            else if ((*particularContext)->instrumentType == InstrumentTypes::Histogram)
            {
                initHistogram((*particularContext)->histogramName, "const std::string& description", "");
            }
        }

        std::advance(particularContext, 1);
        std::advance(particularExporter, 1);
        std::advance(particularProvider, 1);
    }
}

void Metrics::setScopeSpam(const std::string& spamName) const
{
    auto provider = opentelemetry::trace::Provider::GetTracerProvider();
    auto tracer = provider->GetTracer(m_moduleName, OPENTELEMETRY_SDK_VERSION);
    opentelemetry::trace::Scope(tracer->StartSpan(spamName));
}

void Metrics::initCounter(const std::string& name)
{
    auto counterName = name + "_counter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);
    m_doubleCounter.insert({name, meter->CreateDoubleCounter(counterName)});
}

void Metrics::addCounterValue(std::string counterName, const double& value) const
{
    if ((m_doubleCounter.find(counterName)) != m_doubleCounter.end())
    {
        if (value < 0)
        {
            throw std::runtime_error {"The increment amount. MUST be non-negative."};
        }
        if(controller.at(counterName))
        {
            m_doubleCounter.at(counterName)->Add(value);
        }
    }
    else
    {
        throw std::runtime_error {"The counter" + counterName + " has not been created."};
    }
}

void Metrics::initHistogram(const std::string& name, const std::string& description, const std::string& unit)
{
    auto histogramName = name + "_histogram";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name);
    m_doubleHistogram.insert({name, meter->CreateDoubleHistogram(histogramName, description, unit)});
    m_context = opentelemetry::context::Context{};
}

void Metrics::addHistogramValue(std::string histogramName, const double& value) const
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
        throw std::runtime_error {"The counter" + histogramName + " has not been created."};
    }
}
