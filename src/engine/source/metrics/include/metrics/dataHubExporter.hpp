#ifndef _METRICS_DATAHUB_EXPORTER_H
#define _METRICS_DATAHUB_EXPORTER_H

#include "opentelemetry/common/spin_lock_mutex.h"
#include "opentelemetry/sdk/metrics/data/metric_data.h"
#include "opentelemetry/sdk/metrics/instruments.h"
#include "opentelemetry/sdk/metrics/push_metric_exporter.h"
#include "opentelemetry/version.h"
#include <iostream>
#include <base/json.hpp>
#include <string>

#include <metrics/iDataHub.hpp>

OPENTELEMETRY_BEGIN_NAMESPACE
namespace exporter
{
namespace metrics
{

/**
 * @brief Custom implementation of Stream Exporter that pushes data into DataHub Container
 *
 */
class DataHubExporter final : public opentelemetry::sdk::metrics::PushMetricExporter
{
public:
    /**
     * @brief Construct a new Data Hub Exporter object
     *
     * @param dataHub Interface to DataHub container
     * @param aggregation_temporality How new samples are processed with existing ones.
     */
    explicit DataHubExporter(std::shared_ptr<metricsManager::IDataHub> dataHub,
                             sdk::metrics::AggregationTemporality aggregationTemporality =
                                 sdk::metrics::AggregationTemporality::kCumulative) noexcept;

    /**
     * @brief Export the registered instruments samples in the provider
     *
     * @param data Internal structure of OpenTelemetry containing samples
     * @return Result of the operation in OpenTelemetry's terms.
     */
    sdk::common::ExportResult Export(const sdk::metrics::ResourceMetrics& data) noexcept override;

    /**
     * @brief Get the Aggregation Temporality object
     *
     * @param instrument_type Instrument Type
     * @return sdk::metrics::AggregationTemporality
     */
    sdk::metrics::AggregationTemporality
    GetAggregationTemporality(sdk::metrics::InstrumentType instrument_type) const noexcept override;

    /**
     * @brief Force flush the stream
     *
     * @param timeout Timeout to wait for the flush to finish
     * @return true If flush was done
     * @return false If flush was timeout
     */
    bool ForceFlush(std::chrono::microseconds timeout) noexcept override;

    /**
     * @brief Shuts Down the exporter.
     *
     * @param timeout Timeout to wait for Shutdown.
     * @return true If shutdown succeeded.
     * @return false Otherwise.
     */
    bool Shutdown(std::chrono::microseconds timeout) noexcept override;

private:
    /**
     * @brief Interface to Datahub Container.
     */
    std::shared_ptr<metricsManager::IDataHub> m_dataHub;

    /**
     * @brief Control variable to flag shutdown cycle.
     */
    bool is_shutdown_ = false;

    /**
     * @brief Synchronization Object.
     */
    mutable opentelemetry::common::SpinLockMutex lock_;

    /**
     * @brief Aggregation Temporality that represent how new samples are processed with existing ones.
     */
    sdk::metrics::AggregationTemporality aggregationTemporality_;

    /**
     * @brief Check if the program is in the process of shutting down.
     */
    bool isShutdown() const noexcept;

    /**
     * @brief Print instrumentation info metric data.
     */
    void printInstrumentationInfoMetricData(const sdk::metrics::ScopeMetrics& infoMetrics,
                                            const sdk::metrics::ResourceMetrics& data);

    /**
     * @brief Print point data in JSON format.
     */
    void printPointData(json::Json& jsonObj, const opentelemetry::sdk::metrics::PointType& pointdata);

    /**
     * @brief Print point attributes in JSON format.
     */
    void printPointAttributes(json::Json& jsonObj,
                              const opentelemetry::sdk::metrics::PointAttributes& point_attributes);
    /**
     * @brief Print attributes in JSON format with a prefix.
     */
    void printAttributes(const std::map<std::string, sdk::common::OwnedAttributeValue>& map, const std::string prefix);

    /**
     * @brief Print resources in JSON format.
     */
    void printResources(json::Json& jsonObj, const opentelemetry::sdk::resource::Resource& resources);
};

} // namespace metrics
} // namespace exporter
OPENTELEMETRY_END_NAMESPACE

#endif // _METRICS_DATAHUB_EXPORTER_H
