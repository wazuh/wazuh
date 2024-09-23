#include <metrics/manager.hpp>

#include <stdexcept>

#include <fmt/format.h>

#include "exporter/indexerMetricsExporter.hpp"
#include "metric/metric.hpp"
#include "ot.hpp"
#include "otLogger.hpp"

namespace
{
using namespace metrics;

// Set custom logger once
std::once_flag LOGGER_FLAG;

otsdk::internal_log::LogLevel convertLogLevel(logging::Level level)
{
    switch (level)
    {
        case logging::Level::Debug: return otsdk::internal_log::LogLevel::Debug;
        case logging::Level::Info: return otsdk::internal_log::LogLevel::Info;
        case logging::Level::Warn: return otsdk::internal_log::LogLevel::Warning;
        default: return otsdk::internal_log::LogLevel::Error;
    }
}

std::shared_ptr<ManagedMetric>
createMetric(MetricType metricType, std::string&& name, std::string&& desc, std::string&& unit)
{
    switch (metricType)
    {
        case MetricType::UINTCOUNTER:
            return std::make_shared<UIntCounter>(std::move(name), std::move(desc), std::move(unit));
        case MetricType::UINTHISTOGRAM:
            return std::make_shared<UIntHistogram>(std::move(name), std::move(desc), std::move(unit));
        default: throw std::runtime_error("Unsupported metric type");
    }
}

} // namespace

namespace metrics
{

void Manager::validateConfig(const std::shared_ptr<ManagerConfig>& config)
{
    if (!config->indexerConnectorFactory)
    {
        throw std::runtime_error("Indexer connector factory cannot be null");
    }

    if (config->exportInterval.count() <= 0)
    {
        throw std::runtime_error("Export interval must be greater than zero");
    }

    if (config->exportTimeout.count() <= 0)
    {
        throw std::runtime_error("Export timeout must be greater than zero");
    }

    if (config->exportTimeout >= config->exportInterval)
    {
        throw std::runtime_error("Export timeout must be less than export interval");
    }

    if (config->logLevel != logging::Level::Warn && config->logLevel != logging::Level::Err
        && config->logLevel != logging::Level::Info && config->logLevel != logging::Level::Debug)
    {
        throw std::runtime_error("Invalid log level");
    }
}

void Manager::unsafeConfigure(const std::shared_ptr<Config>& config)
{
    if (m_enabled)
    {
        throw std::runtime_error(
            "Cannot configure manager while it is enabled, use reload with new configuration instead");
    }

    if (!config)
    {
        throw std::runtime_error("Configuration cannot be null");
    }

    auto managerConfig = std::dynamic_pointer_cast<ManagerConfig>(config);
    if (!managerConfig)
    {
        throw std::runtime_error("Configuration must be of type ManagerConfig");
    }

    validateConfig(managerConfig);

    m_config = *managerConfig;

    LOG_INFO("Metrics manager configured successfully");
}

void Manager::createOtPipeline()
{
    std::call_once(LOGGER_FLAG,
                   [level = m_config.logLevel]()
                   {
                       otsdk::internal_log::GlobalLogHandler::SetLogLevel(convertLogLevel(level));
                       otsdk::internal_log::GlobalLogHandler::SetLogHandler(
                           otapi::shared_ptr<OtLogger>(new OtLogger()));
                   });

    // Exporter
    auto exporter = std::make_unique<IndexerMetricsExporter>(m_config.indexerConnectorFactory());

    // Reader
    auto readerOptions = otsdk::PeriodicExportingMetricReaderOptions();
    readerOptions.export_interval_millis = std::chrono::milliseconds(m_config.exportInterval);
    readerOptions.export_timeout_millis = std::chrono::milliseconds(m_config.exportTimeout);
    auto reader = std::make_shared<otsdk::PeriodicExportingMetricReader>(
        std::unique_ptr<otsdk::PushMetricExporter>(std::move(exporter)), readerOptions);

    // Provider
    auto provider = std::make_shared<otsdk::MeterProvider>();
    provider->AddMetricReader(reader);

    // Set the global provider
    otapi::Provider::SetMeterProvider(otapi::shared_ptr<otsdk::MeterProvider>(std::move(provider)));
}

void Manager::destroyOtPipeline()
{
    auto nullProvider = otapi::shared_ptr<otsdk::MeterProvider>(nullptr);
    otapi::Provider::SetMeterProvider(std::move(nullProvider));
}

void Manager::unsafeEnable()
{
    if (m_enabled)
    {
        throw std::runtime_error("Metrics manager is already enabled");
    }

    try
    {
        createOtPipeline();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to create metrics internal pipeline: {}", e.what());
        throw;
    }
    m_enabled = true;

    LOG_INFO("Metrics pipeline enabled successfully");

    // Enable all metrics
    for (const auto& [name, metric] : m_metrics)
    {
        try
        {
            metric->enable();
            LOG_INFO("Metric '{}' enabled successfully", name);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to enable metric '{}': {}", name, e.what());
        }
    }
}

void Manager::unsafeDisable()
{
    if (!m_enabled)
    {
        return;
    }

    destroyOtPipeline();

    // Logic to disable the manager
    m_enabled = false;

    LOG_INFO("Metrics pipeline disabled successfully");

    // Disable all metrics
    for (const auto& [name, metric] : m_metrics)
    {
        metric->disable();
    }
}

std::shared_ptr<IMetric>
Manager::addMetric(MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit)
{
    std::unique_lock lock(m_mutex);
    if (name.parts().size() != 2)
    {
        throw std::runtime_error("Invalid metric name, must follow the pattern 'module.metric'");
    }

    if (m_metrics.find(name.str()) != m_metrics.end())
    {
        throw std::runtime_error(fmt::format("Metric '{}' already exists", name));
    }

    auto metric = createMetric(metricType, std::string(name.str()), std::string(desc), std::string(unit));

    m_metrics.emplace(name, metric);

    if (m_enabled)
    {
        metric->create();
        metric->enable();
    }

    return metric;
}

std::shared_ptr<IMetric> Manager::getMetric(const DotPath& name) const
{
    std::shared_lock lock(m_mutex);
    auto it = m_metrics.find(name);
    if (it == m_metrics.end())
    {
        throw std::runtime_error(fmt::format("Metric '{}' not found", name));
    }

    return it->second;
}

void Manager::configure(const std::shared_ptr<Config>& config)
{
    std::unique_lock lock(m_mutex);
    unsafeConfigure(config);
}

void Manager::enable()
{
    std::unique_lock lock(m_mutex);
    unsafeEnable();
}

void Manager::disable()
{
    std::unique_lock lock(m_mutex);
    unsafeDisable();
}

void Manager::reload(const std::shared_ptr<Config>& newConfig)
{
    std::unique_lock lock(m_mutex);
    if (!m_enabled)
    {
        unsafeConfigure(newConfig);
    }
    else
    {
        auto backupConfig = std::make_shared<ManagerConfig>(m_config);

        try
        {
            unsafeDisable();
            unsafeConfigure(newConfig);
            unsafeEnable();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to apply new metrics configuration: {}", e.what());
            try
            {
                unsafeConfigure(backupConfig);
                unsafeEnable();
            }
            catch (const std::exception& eNested)
            {
                LOG_ERROR("Metrics disabled, Failed to restore previous configuration: {}", eNested.what());
                throw std::runtime_error(
                    fmt::format("Failed to reload new configuration: {}. Failed to restore previous configuration: {}",
                                e.what(),
                                eNested.what()));
            }
            LOG_WARNING("Metrics restored to previous configuration");

            throw std::runtime_error(
                fmt::format("Metrics manager restored to previous configuration, due to: {}", e.what()));
        }
    }
}

void Manager::enableModule(const DotPath& name)
{
    std::unique_lock lock(m_mutex);
    if (name.parts().size() != 1)
    {
        throw std::runtime_error("Invalid module name, must follow the pattern 'module'");
    }

    for (const auto& [metricName, metric] : m_metrics)
    {
        if (metricName.parts()[0] == name.parts()[0])
        {
            metric->enable();
        }
    }
}

void Manager::disableModule(const DotPath& name)
{
    std::unique_lock lock(m_mutex);
    if (name.parts().size() != 1)
    {
        throw std::runtime_error("Invalid module name, must follow the pattern 'module'");
    }

    for (const auto& [metricName, metric] : m_metrics)
    {
        if (metricName.parts()[0] == name.parts()[0])
        {
            metric->disable();
        }
    }
}
} // namespace metrics
