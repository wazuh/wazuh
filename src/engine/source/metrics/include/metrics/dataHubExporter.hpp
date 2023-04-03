#ifndef __DATAHUB_EXPORTER_H
#define __DATAHUB_EXPORTER_H

#include "opentelemetry/common/spin_lock_mutex.h"
#include "opentelemetry/sdk/metrics/data/metric_data.h"
#include "opentelemetry/sdk/metrics/instruments.h"
#include "opentelemetry/sdk/metrics/push_metric_exporter.h"
#include "opentelemetry/version.h"
#include <iostream>
#include <json/json.hpp>
#include <string>

#include <metrics/iDataHub.hpp>

OPENTELEMETRY_BEGIN_NAMESPACE
namespace exporter
{
namespace metrics
{

/**
 * The DataHubExporter exports record data through an ostream
 */
class DataHubExporter final : public opentelemetry::sdk::metrics::PushMetricExporter
{
public:
    /**
     * Create an DataHubExporter. This constructor takes in a reference to an ostream that
     * the export() function will send metrics data into. The default ostream is set to
     * stdout
     */
    explicit DataHubExporter(std::shared_ptr<metricsManager::IDataHub> dataHub,
                          sdk::metrics::AggregationTemporality aggregation_temporality =
                              sdk::metrics::AggregationTemporality::kCumulative) noexcept;

    /**
     * Export
     * @param data metrics data
     */
    sdk::common::ExportResult
    Export(const sdk::metrics::ResourceMetrics& data) noexcept override;

    /**
     * Get the AggregationTemporality for ostream exporter
     *
     * @return AggregationTemporality
     */
    sdk::metrics::AggregationTemporality GetAggregationTemporality(
        sdk::metrics::InstrumentType instrument_type) const noexcept override;

    /**
     * Force flush the exporter.
     */
    bool ForceFlush(std::chrono::microseconds timeout =
                        (std::chrono::microseconds::max)()) noexcept override;

    /**
     * Shut down the exporter.
     * @param timeout an optional timeout.
     * @return return the status of this operation
     */
    bool Shutdown(std::chrono::microseconds timeout =
                      (std::chrono::microseconds::max)()) noexcept override;

private:
    std::shared_ptr<metricsManager::IDataHub> m_dataHub;

    bool is_shutdown_ = false;
    mutable opentelemetry::common::SpinLockMutex lock_;
    sdk::metrics::AggregationTemporality aggregation_temporality_;
    bool isShutdown() const noexcept;
    void
    printInstrumentationInfoMetricData(const sdk::metrics::ScopeMetrics& info_metrics,
                                       const sdk::metrics::ResourceMetrics& data);
    void printPointData(json::Json& jsonObj, const opentelemetry::sdk::metrics::PointType& point_data);
    void printPointAttributes(json::Json& jsonObj,
        const opentelemetry::sdk::metrics::PointAttributes& point_attributes);
    void
    printAttributes(const std::map<std::string, sdk::common::OwnedAttributeValue>& map,
                    const std::string prefix);
    void printResources(json::Json& jsonObj, const opentelemetry::sdk::resource::Resource& resources);
};
} // namespace metrics
} // namespace exporter
OPENTELEMETRY_END_NAMESPACE

#endif // __DATAHUB_EXPORTER_H
