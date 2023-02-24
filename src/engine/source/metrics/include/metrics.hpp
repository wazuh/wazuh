#ifndef _METRICS_H
#define _METRICS_H

#include <any>
#include <functional>
#include <string>
#include <unordered_map>
#include "metricsContext.hpp"
#include "exporterHandler.hpp"
#include "processorHandler.hpp"
#include "providerHandler.hpp"
#include "readerHandler.hpp"
#include <nlohmann/json.hpp>
#include "opentelemetry/metrics/sync_instruments.h"
#include <filesystem>

class Metrics final
{
public:
    ~Metrics();
    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initMetrics(const std::string& moduleName, const std::filesystem::path& file);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void setScopeSpam(const std::string& spamName) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initCounter(const std::string& name);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addCounterValue(std::string counterName, const double& value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initHistogram(const std::string& name, const std::string& description, const std::string& unit);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addHistogramValue(std::string histogramName, const double& value) const;

private:
    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void setContext();

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void createContext(const std::filesystem::path& file);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    nlohmann::json loadJson(const std::filesystem::path& file);

private:
    std::string m_moduleName;
    std::vector<std::shared_ptr<MetricsContext>> m_upContext;
    std::vector<std::shared_ptr<ExporterHandler>> m_upExporter;
    std::vector<std::shared_ptr<ProviderHandler>> m_upProvider;
    std::vector<std::shared_ptr<ProcessorHandler>> m_upProcessor;
    std::vector<std::shared_ptr<ReaderHandler>> m_upReader;
    nlohmann::json m_contextFile;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>>> m_doubleCounter;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>> m_doubleHistogram;
    opentelemetry::context::Context m_context;
    std::unordered_map<std::string, bool> controller;
};

#endif // _METRICS_H
