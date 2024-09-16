#ifndef _METRICS_INDEXERMETRICSEXPORTER_HPP
#define _METRICS_INDEXERMETRICSEXPORTER_HPP

#include <memory>
#include <stdexcept>

#include <opentelemetry/sdk/metrics/push_metric_exporter.h>

#include <base/json.hpp>
#include <indexerConnector/iindexerconnector.hpp>

#include <metrics/ot.hpp>

namespace metrics
{

/**
 * IndexerMetricsExporter push metrics data to the Indexer.
 */
class IndexerMetricsExporter final : public ot::PushMetricExporter
{
private:
    std::shared_ptr<IIndexerConnector> m_indexerConnector;

public:
    ~IndexerMetricsExporter() override = default;

    /**
     * @brief Construct a new Indexer Metrics Exporter object
     *
     * @param indexerConnector Indexer Connector
     */
    IndexerMetricsExporter(const std::shared_ptr<IIndexerConnector>& indexerConnector)
        : m_indexerConnector(indexerConnector)
    {
        if (!m_indexerConnector)
        {
            throw std::runtime_error("Cannot create IndexerMetricsExporter with a nullptr indexerConnector");
        }
    }

    /**
     * Exports a batch of metrics data. This method must not be called
     * concurrently for the same exporter instance.
     * @param data metrics data
     */
    ot::ExportResult Export(const ot::ResourceMetrics& data) noexcept override;

    /**
     * Get the AggregationTemporality for given Instrument Type for this exporter.
     *
     * @return AggregationTemporality
     */
    ot::AggregationTemporality GetAggregationTemporality(ot::InstrumentType instrument_type) const noexcept override;

    /**
     * Force flush the exporter.
     */
    bool ForceFlush(std::chrono::microseconds timeout) noexcept override;

    /**
     * Shut down the metric exporter.
     * @param timeout an optional timeout.
     * @return return the status of the operation.
     */
    bool Shutdown(std::chrono::microseconds timeout) noexcept override;
};

} // namespace metrics

#endif // _METRICS_INDEXERMETRICSEXPORTER_HPP
