#include "indexerMetricsExporter.hpp"

#include <stdexcept>

#include <base/logging.hpp>

#include <metrics/ot.hpp>

#include "metricSerializer.hpp"
#include "pointDataSerializer.hpp"
#include "scopeSerializer.hpp"

namespace metrics
{

ot::ExportResult IndexerMetricsExporter::Export(const ot::ResourceMetrics& data) noexcept
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

            this->m_indexerConnector->publish(jsonMessage.str());
        }
        return ot::ExportResult::kSuccess;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failure exporting metrics: {}", e.what());
        return ot::ExportResult::kFailure;
    }
}

ot::AggregationTemporality
IndexerMetricsExporter::GetAggregationTemporality(ot::InstrumentType instrument_type) const noexcept
{
    return ot::AggregationTemporality::kCumulative;
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
