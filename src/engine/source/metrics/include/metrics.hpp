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

struct PairHasher {
    std::size_t operator()(const std::pair<std::string, bool>& p) const {
        return std::hash<std::string>()(p.first) ^ std::hash<bool>()(p.second);
    }
};

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
     *
     * @return std::shared_ptr<DataHub> the same handler that has been set as
     * next
     */
    std::shared_ptr<DataHub> getDataHub();

    /**
     * @brief Initialize the metrics module.
     *
     * @param moduleName Specifies the name of module
     * @param file Configuration file
     */
    void initMetrics(const std::string& moduleName, const std::filesystem::path& file);

    /**
     * @brief Set Scope Span.
     *
     * @param spanName Specifies the name of Span.
     * next
     */
    void setScopeSpan(const std::string& spanName) const;

    /**
     * @brief Add Counter Value.
     *
     * @param counterName Specifies the name of counter.
     * @param value The value to add.
     */
    void addCounterValue(std::string counterName, const double value) const;

    /**
     * @brief Add Counter Value.
     *
     * @param counterName Specifies the name of counter.
     * @param value The value to add.
     */
    void addCounterValue(std::string counterName, const uint64_t value) const;

    /**
     * @brief Add Histogram Value.
     *
     * @param histogramName Specifies the name of histogram.
     * @param value The value to add.
     */
    void addHistogramValue(std::string histogramName, const double value) const;

    /**
     * @brief Add Histogram Value.
     *
     * @param histogramName Specifies the name of histogram.
     * @param value The value to add.
     * @param labels The attributes to set.
     */
    void addHistogramValue(std::string histogramName, const uint64_t value, std::map<std::string, std::string> labels = {}) const;

    /**
     * @brief Add UpDown Counter Value.
     *
     * @param upDownCounterName Specifies the name of UpDown counter.
     * @param value The value to add.
     */
    void addUpDownCounterValue(std::string upDownCounterName, const double value) const;

    /**
     * @brief Add UpDown Counter Value.
     *
     * @param upDownCounterName Specifies the name of UpDown counter.
     * @param value The value to add.
     */
    void addUpDownCounterValue(std::string upDownCounterName, const int64_t value) const;

    /**
     * @brief Add Observable Gauge Value.
     *
     * @param observableGaugeName Specifies the name of Observable Gauge.
     * @param callback The callback function.
     */
    void addObservableGauge(std::string observableGaugeName, opentelemetry::v1::metrics::ObservableCallbackPtr callback) const;

    /**
     * @brief Remove Observable Gauge callback.
     *
     * @param observableGaugeName Specifies the name of Observable Gauge.
     * @param callback The callback function to remove.
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
     *
     * @return name, state and type of the instrument.
     */
    std::ostringstream getInstrumentsList();

    /**
     * @brief Generate dummy metrics for testing.
     */
    void generateCounterToTesting();

private:
    /**
     * @brief Set Metrics Config.
     */
    void setMetricsConfig();

    /**
     * @brief Create the common chain.
     *
     * @param file Configuration file.
     */
    void createCommonChain(const std::filesystem::path& file);

    /**
     * @brief Set Instrument Config.
     *
     * @param context Context of metrics.
     */
    void setInstrumentConfig(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Create the full chain.
     */
    void createFullChain();

    /**
     * @brief Load the json.
     *
     * @param file Configuration file.
     */
    nlohmann::json loadJson(const std::filesystem::path& file);

    /**
     * @brief Initialize the tracer.
     *
     * @param context Context of metrics.
     */
    void initTracer(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Initialize the counter.
     *
     * @param context Context of metrics.
     */
    void initCounter(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Initialize the histogram.
     *
     * @param context Context of metrics.
     */
    void initHistogram(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Initialize the UpDown counter.
     *
     * @param context Context of metrics.
     */
    void initUpDownCounter(const std::shared_ptr<MetricsContext> context);

    /**
     * @brief Initialize the Observable gauge.
     *
     * @param context Context of metrics.
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
    std::unordered_map<std::pair<std::string, bool>, std::string, PairHasher> m_instrumentState;
};

#endif // _METRICS_H
