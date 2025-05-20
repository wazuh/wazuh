#include "indexerMetricsExporter.hpp"

#include <stdexcept>

#include <base/logging.hpp>
#include <base/utils/timeUtils.hpp>

#include "metricSerializer.hpp"
#include "pointDataSerializer.hpp"
#include "scopeSerializer.hpp"

namespace metrics
{

otsdk::ExportResult IndexerMetricsExporter::Export(const otsdk::ResourceMetrics& data) noexcept
{
    try
    {

        for (const auto& record : data.scope_metric_data_)
        {
            json::Json jsonMessage;
            jsonMessage.setString("ADD", "/operation");

            jsonMessage.set("/data", details::scopeToJson(*record.scope_));
            for (const auto& metric : record.metric_data_)
            {
                auto metricJson = details::metricDataToJson(metric);
                for (const auto& point : metric.point_data_attr_)
                {
                    auto pointDataJson = details::pointDataToJson(point.point_data);
                    metricJson.appendJson(pointDataJson, "/points");
                }
                jsonMessage.appendJson(metricJson, "/data/metrics");
            }

            const auto timestamp = base::utils::time::getCurrentISO8601();
            jsonMessage.setString(timestamp, "/data/timestamp");

            this->m_indexerConnector->publish(jsonMessage.str());
        }
        return otsdk::ExportResult::kSuccess;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failure exporting metrics: {}", e.what());
        return otsdk::ExportResult::kFailure;
    }
}

otsdk::AggregationTemporality
IndexerMetricsExporter::GetAggregationTemporality(otsdk::InstrumentType instrument_type) const noexcept
{
    return otsdk::AggregationTemporality::kCumulative;
}

bool IndexerMetricsExporter::ForceFlush(std::chrono::microseconds timeout) noexcept
{
    return true;
}

bool IndexerMetricsExporter::Shutdown(std::chrono::microseconds timeout) noexcept
{
    return true;
}

} // namespace metrics
