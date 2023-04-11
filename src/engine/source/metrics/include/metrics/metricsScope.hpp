#ifndef _METRICS_SCOPE_H
#define _METRICS_SCOPE_H

#include <string>

#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"

#include <metrics/dataHub.hpp>
#include <metrics/dataHubExporter.hpp>
#include <metrics/iMetricsScope.hpp>
#include <metrics/instrumentCollection.hpp>
#include <metrics/metricsInstruments.hpp>

namespace metricsManager
{

using OTSDKMeterProvider = opentelemetry::sdk::metrics::MeterProvider;

/**
 * @brief Implementation of IMetricsScope. Contains functionallity and datahubs for the metrics scopes.
 */
class MetricsScope : public IMetricsScope
{
public:
    /**
     * @brief Initialize the scope and creates the chain of exporter/reader/provider.
     *
     * @param delta Aggregation temporality type is Delta or Accummulative.
     * @param exporterIntervalMS Time in ms by which the exporters retrieves the data from the Instruments.
     * @param exporterTimeoutMS Time in ms by which the exporters fallback in timeout if can't retrieve.
     */
    void initialize(bool delta, int exporterIntervalMS, int exporterTimeoutMS);

    /**
     * @brief Get the collected data in the DataHub of this scope or associated with the provided instrument.
     *
     * @param metricsInstrumentName Name of the instrument.
     * @return Json representation of the data.
     */
    json::Json getAllMetrics(const std::string& metricsInstrumentName = "");

    /**
     * @copydoc IMetricsScope::getCounterDouble()
     */
    std::shared_ptr<iCounter<double>> getCounterDouble(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getCounterUInteger()
     */
    std::shared_ptr<iCounter<uint64_t>> getCounterUInteger(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getUpDownCounterDouble()
     */
    std::shared_ptr<iCounter<double>> getUpDownCounterDouble(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getUpDownCounterInteger()
     */
    std::shared_ptr<iCounter<int64_t>> getUpDownCounterInteger(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getHistogramDouble()
     */
    std::shared_ptr<iHistogram<double>> getHistogramDouble(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getHistogramUInteger()
     */
    std::shared_ptr<iHistogram<uint64_t>> getHistogramUInteger(const std::string& name) override;

    /**
     * @copydoc IMetricsScope::getGaugeInteger()
     */
    std::shared_ptr<iGauge<int64_t>> getGaugeInteger(const std::string& name, int64_t defaultValue) override;

    /**
     * @copydoc IMetricsScope::getGaugeDouble()
     */
    std::shared_ptr<iGauge<double>> getGaugeDouble(const std::string& name, double defaultValue) override;

    /**
     * @brief Sets the enabled status of the specified instrument.
     *
     * @param instrumentName The name of the instrument.
     * @param newStatus The new enabled status.
     * @return Operation succeeded.
     */
    bool setEnabledStatus(const std::string& instrumentName, bool newStatus);

    /**
     * @brief Gets the enabled status of the specified instrument.
     *
     * @param instrumentName The name of the instrument.
     * @return The enabled status of the instrument.
     */
    bool getEnabledStatus(const std::string& instrumentName);

private:
    /**
     * @brief DataHub collection
     */
    std::shared_ptr<DataHub> m_dataHub;

    /**
     * @brief Provider of Instruments. Binds the instruments to the exporters.
     */
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;

    /**
     * @brief Collection of Double Counters mapping to OpenTelemetry internals.
     */
    InstrumentCollection<Counter<OTMetrics::Counter<double>, double>,
                        OTstd::unique_ptr<OTMetrics::Counter<double>>>
        m_collection_counter_double;

    /**
     * @brief Collection of unsigned integer counters that map to OpenTelemetry internals.
     */
    InstrumentCollection<Counter<OTMetrics::Counter<uint64_t>, uint64_t>,
                         OTstd::unique_ptr<OTMetrics::Counter<uint64_t>>>
        m_collection_counter_integer;

    /**
     * @brief Collection of double up-down counters that map to OpenTelemetry internals.
     */
    InstrumentCollection<Counter<OTMetrics::UpDownCounter<double>, double>,
                         OTstd::unique_ptr<OTMetrics::UpDownCounter<double>>>
        m_collection_updowncounter_double;

    /**
     * @brief Collection of integer up-down counters that map to OpenTelemetry internals.
     */
    InstrumentCollection<Counter<OTMetrics::UpDownCounter<int64_t>, int64_t>,
                         OTstd::unique_ptr<OTMetrics::UpDownCounter<int64_t>>>
        m_collection_updowncounter_integer;

    /**
     * @brief Collection of double histograms that map to OpenTelemetry internals.
     */
    InstrumentCollection<Histogram<OTMetrics::Histogram<double>, double>,
                         OTstd::unique_ptr<OTMetrics::Histogram<double>>>
        m_collection_histogram_double;

    /**
     * @brief Collection of unsigned integer histograms that map to OpenTelemetry internals.
     */
    InstrumentCollection<Histogram<OTMetrics::Histogram<uint64_t>, uint64_t>,
                         OTstd::unique_ptr<OTMetrics::Histogram<uint64_t>>>
        m_collection_histogram_integer;

    /**
     * @brief Collection of integer gauges that map to OpenTelemetry internals.
     */
    InstrumentCollection<Gauge<int64_t>, OTstd::shared_ptr<OTMetrics::ObservableInstrument>> m_collection_gauge_integer;

    /**
     * @brief Collection of double gauges that map to OpenTelemetry internals.
     */
    InstrumentCollection<Gauge<double>, OTstd::shared_ptr<OTMetrics::ObservableInstrument>> m_collection_gauge_double;

    /**
     * @brief Mapping of instruments indexed by name.
     */
    std::unordered_map<std::string, std::shared_ptr<Instrument>> m_namesMap;

    /**
     * @brief Register a new instrument in the name index.
     *
     * @param name Name of the Instrument.
     * @param instrument Shared Pointer to the Instrument.
     */

    void registerInstrument(const std::string& name, const std::shared_ptr<Instrument>& instrument);

    /**
     * @brief Gets the instrument with the specified name.
     *
     * @param name The name of the instrument.
     * @return A shared pointer to the instrument.
     */
    std::shared_ptr<Instrument> getInstrument(const std::string& name);

    /**
     * @brief Callback for Observable instrument of type Integer.
     *
     * @param observer_result Internals Open Telemetry holding the observer result.
     * @param id Identification of instrument.
     */
    static void FetcherInteger(OTMetrics::ObserverResult observer_result, void *id);

    /**
     * @brief Callback for Observable instrument of type Double.
     *
     * @param observer_result Internals Open Telemetry holding the observer result.
     * @param id Identification of instrument.
     */
    static void FetcherDouble(OTMetrics::ObserverResult observer_result, void *id);
};

} // namespace metricsManager

#endif // _METRICS_SCOPE_H
