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
#include "dataHub.hpp"
#include <fmt/format.h>
#include <error.hpp>

class Metrics final
{
public:
    /**
     * @brief Returns a reference to the created object.
     *
     * @return Metrics& Reference to the created object.
     */
    // LCOV_EXCL_START
    static Metrics& instance()
    {
        static Metrics s_instance;
        return s_instance;
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Clean MeterProvider and MeterTrace.
     */
    void clean();

    /**
     * @brief Get dataHub.
     * @return std::shared_ptr<DataHub> the same handler that has been set as
     * next
     */
    std::shared_ptr<DataHub> getDataHub();
    
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
    void setScopeSpan(const std::string& spanName) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addCounterValue(std::string counterName, const double value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addCounterValue(std::string counterName, const uint64_t value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addHistogramValue(std::string histogramName, const double value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addHistogramValue(std::string histogramName, const uint64_t value, std::map<std::string, std::string> labels = {}) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addUpDownCounterValue(std::string upDownCounterName, const double value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addUpDownCounterValue(std::string upDownCounterName, const int64_t value) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void addObservableGauge(std::string upDownCounterName, opentelemetry::v1::metrics::ObservableCallbackPtr callback) const;

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void removeObservableGauge(std::string observableGaugeName, opentelemetry::v1::metrics::ObservableCallbackPtr callback) const;

    /**
     * @brief Set the status of any instrument.
     *
     * @param instrumentName name of the instrument.
     * @param state new state of the instrument.
     */
    void setEnableInstrument(const std::string& instrumentName, bool state);

    /**
     * @brief Obtains information about the list of configured instruments.
     * @return name, state and type of the instrument.
     */
    std::ostringstream getListInstruments();

    /**
     * @brief Generate dummy metrics for testing.
     */
    void generateCounterToTesting();
private:
    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void setMetricsConfig();

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void createCommonChain(const std::filesystem::path& file);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void setInstrumentConfig(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void createFullChain();

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    nlohmann::json loadJson(const std::filesystem::path& file);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initTracer(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initCounter(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initHistogram(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initUpDownCounter(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Set the next handle on the chain
     *
     * @param handler handler that will be set as the next on the chain
     * @return std::shared_ptr<Handler> the same handler that has been set as
     * next
     */
    void initObservableGauge(const std::shared_ptr<MetricsContext> context);

protected:
    Metrics();
    // LCOV_EXCL_START
    virtual ~Metrics() = default;
    // LCOV_EXCL_STOP
    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;

private:
    std::shared_ptr<DataHub> m_dataHub;
    std::list<std::string> m_instrumentsTypes;
    std::string m_moduleName;
    std::vector<std::shared_ptr<MetricsContext>> m_upContext;
    std::vector<std::shared_ptr<ExporterHandler>> m_upExporter;
    std::vector<std::shared_ptr<ProviderHandler>> m_upProvider;
    std::vector<std::shared_ptr<ProcessorHandler>> m_upProcessor;
    std::vector<std::shared_ptr<ReaderHandler>> m_upReader;
    nlohmann::json m_contextFile;
    opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> m_spProvider;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<double>>> m_doubleCounter;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>> m_uint64Counter;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>> m_doubleHistogram;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<uint64_t>>> m_uint64Histogram;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<double>>> m_doubleUpDownCounter;
    std::unordered_map<std::string, opentelemetry::nostd::unique_ptr<opentelemetry::metrics::UpDownCounter<int64_t>>> m_int64UpDownCounter;
    std::unordered_map<std::string, opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument>> m_doubleObservableGauge;
    std::unordered_map<std::string, opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument>> m_int64ObservableGauge;
    opentelemetry::context::Context m_context;
    std::unordered_map<std::string, bool> controller;
};

#endif // _METRICS_H
