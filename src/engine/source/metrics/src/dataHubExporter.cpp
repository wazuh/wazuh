#include <metrics/dataHubExporter.hpp>

#include <rapidjson/document.h>
#include <algorithm>
#include <chrono>
#include <map>

#include "opentelemetry/exporters/ostream/common_utils.h"
#include "opentelemetry/sdk/metrics/aggregation/default_aggregation.h"
#include "opentelemetry/sdk/metrics/aggregation/histogram_aggregation.h"
#include "opentelemetry/sdk_config.h"

namespace
{
std::string timeToString(opentelemetry::common::SystemTimestamp time_stamp)
{
  std::time_t epoch_time = std::chrono::system_clock::to_time_t(time_stamp);

  struct tm *tm_ptr = nullptr;
#if defined(_MSC_VER)
  struct tm buf_tm;
  if (!gmtime_s(&buf_tm, &epoch_time))
  {
    tm_ptr = &buf_tm;
  }
#else
  tm_ptr = std::gmtime(&epoch_time);
#endif

  char buf[100];
  char *date_str = nullptr;
  if (tm_ptr == nullptr)
  {
    OTEL_INTERNAL_LOG_ERROR("[OStream Metric] gmtime failed for " << epoch_time);
  }
  else if (std::strftime(buf, sizeof(buf), "%c", tm_ptr) > 0)
  {
    date_str = buf;
  }
  else
  {
    OTEL_INTERNAL_LOG_ERROR("[OStream Metric] strftime failed for " << epoch_time);
  }

  return std::string{date_str};
}
}  // namespace

OPENTELEMETRY_BEGIN_NAMESPACE
namespace exporter
{
namespace metrics
{

using namespace metrics_manager;

DataHubExporter::DataHubExporter(
    std::shared_ptr<metrics_manager::IDataHub> dataHub,
    sdk::metrics::AggregationTemporality aggregation_temporality) noexcept
    : m_dataHub(dataHub), aggregation_temporality_(aggregation_temporality)
{}

sdk::metrics::AggregationTemporality DataHubExporter::GetAggregationTemporality(
    sdk::metrics::InstrumentType /* instrument_type */) const noexcept
{
  return aggregation_temporality_;
}

sdk::common::ExportResult DataHubExporter::Export(
    const sdk::metrics::ResourceMetrics &data) noexcept
{
  if (isShutdown())
  {
    OTEL_INTERNAL_LOG_ERROR("[OStream Metric] Exporting "
                            << data.scope_metric_data_.size()
                            << " records(s) failed, exporter is shutdown");
    return sdk::common::ExportResult::kFailure;
  }

  for (auto &record : data.scope_metric_data_)
  {
    printInstrumentationInfoMetricData(record, data);
  }

  return sdk::common::ExportResult::kSuccess;
}


void DataHubExporter::printInstrumentationInfoMetricData(
    const sdk::metrics::ScopeMetrics &info_metric,
    const sdk::metrics::ResourceMetrics &data)
{

  const std::lock_guard<opentelemetry::common::SpinLockMutex> locked(lock_);

  auto scopeName = info_metric.scope_->GetName();
  auto schemaUrl = info_metric.scope_->GetSchemaURL();
  auto version   = info_metric.scope_->GetVersion();

  json::Json jMetricData;

  jMetricData.setString(scopeName, "/scope");
  jMetricData.setString(schemaUrl, "/schema");
  jMetricData.setString(version, "/version");

  json::Json jDataRecords;

  for (const auto &record : info_metric.metric_data_)
  {
    json::Json jRecord;

    auto startTime      = timeToString(record.start_ts);
    auto endTime        = timeToString(record.end_ts);
    auto instrumentName = record.instrument_descriptor.name_;
    auto description    = record.instrument_descriptor.description_;
    auto unit           = record.instrument_descriptor.unit_;

    jRecord.setString(startTime, "/start_time" );
    jRecord.setString(endTime, "/start_time" );
    jRecord.setString(instrumentName, "/instrument_name" );
    jRecord.setString(description, "/instrument_description" );
    jRecord.setString(unit, "/unit" );

    json::Json jAttributes;

    for (const auto &pd : record.point_data_attr_)
    {
      if (!nostd::holds_alternative<sdk::metrics::DropPointData>(pd.point_data))
      {
        json::Json jPointAttributes;
        printPointData(jPointAttributes,  pd.point_data);
        jAttributes.appendJson(jPointAttributes);
      }
    }

    jRecord.set("/attributes", jAttributes);
    jDataRecords.appendJson(jRecord);

    jMetricData.set("/records", jDataRecords);

  }
  m_dataHub->setResource(scopeName, jMetricData);
}

void DataHubExporter::printPointData(json::Json& jsonObj, const opentelemetry::sdk::metrics::PointType &point_data)
{
  if (nostd::holds_alternative<sdk::metrics::SumPointData>(point_data))
  {
    auto sum_point_data = nostd::get<sdk::metrics::SumPointData>(point_data);
    jsonObj.setString("SumPointData", "/type");

    if (nostd::holds_alternative<double>(sum_point_data.value_))
    {
      auto valueData = nostd::get<double>(sum_point_data.value_);
      jsonObj.setDouble(valueData, "/value");
    }
    else if (nostd::holds_alternative<int64_t>(sum_point_data.value_))
    {
      auto valueData = nostd::get<int64_t>(sum_point_data.value_);
      jsonObj.setInt64(valueData, "/value");
    }
  }
  else if (nostd::holds_alternative<sdk::metrics::HistogramPointData>(point_data))
  {
    auto histogram_point_data = nostd::get<sdk::metrics::HistogramPointData>(point_data);
    auto count = histogram_point_data.count_;
    jsonObj.setString("HistogramPointData", "/type");
    jsonObj.setInt64(count, "/count");
    if (nostd::holds_alternative<double>(histogram_point_data.sum_))
    {
      auto valueData = nostd::get<double>(histogram_point_data.sum_);
      jsonObj.setDouble(valueData, "/sum");
    }
    else if (nostd::holds_alternative<int64_t>(histogram_point_data.sum_))
    {
      auto valueData = nostd::get<int64_t>(histogram_point_data.sum_);
      jsonObj.setInt64(valueData, "/sum");
    }

    if (histogram_point_data.record_min_max_)
    {
      if (nostd::holds_alternative<int64_t>(histogram_point_data.min_))
      {
        auto valueData = nostd::get<int64_t>(histogram_point_data.min_);
        jsonObj.setInt64(valueData, "/min");
      }
      else if (nostd::holds_alternative<double>(histogram_point_data.min_))
      {
        auto valueData = nostd::get<double>(histogram_point_data.min_);
        jsonObj.setDouble(valueData, "/min");
      }
      if (nostd::holds_alternative<int64_t>(histogram_point_data.max_))
      {
        auto valueData = nostd::get<int64_t>(histogram_point_data.max_);
        jsonObj.setInt64(valueData, "/max");
      }
      if (nostd::holds_alternative<double>(histogram_point_data.max_))
      {
        auto valueData = nostd::get<double>(histogram_point_data.max_);
        jsonObj.setDouble(valueData, "/max");
      }
    }

    {
      rapidjson::Document jBuckets;
      jBuckets.SetArray();
      auto allocator = jBuckets.GetAllocator();
      for (auto &bElement : histogram_point_data.boundaries_)
      {
        rapidjson::Value tmp(bElement);
        jBuckets.PushBack(tmp, allocator);
      }

      json::Json ob(std::move(jBuckets));
      jsonObj.set("/buckets", ob);
    }

    {
      rapidjson::Document jCounts;
      jCounts.SetArray();
      auto allocator = jCounts.GetAllocator();
      for (auto &bElement : histogram_point_data.counts_)
      {
        rapidjson::Value tmp(bElement);
        jCounts.PushBack(tmp, allocator);
      }

      json::Json ob(std::move(jCounts));
      jsonObj.set("/counts", ob);
    }


  }
  else if (nostd::holds_alternative<sdk::metrics::LastValuePointData>(point_data))
  {
    auto last_point_data = nostd::get<sdk::metrics::LastValuePointData>(point_data);
    jsonObj.setString("LastValuePointData", "/type");
    auto timestamp = std::to_string(last_point_data.sample_ts_.time_since_epoch().count());
    jsonObj.setString(timestamp, "/timestamp");
    jsonObj.setBool(last_point_data.is_lastvalue_valid_, "/valid");

    if (nostd::holds_alternative<double>(last_point_data.value_))
    {
      auto valueData = nostd::get<double>(last_point_data.value_);
      jsonObj.setDouble(valueData, "/value");
    }
    else if (nostd::holds_alternative<int64_t>(last_point_data.value_))
    {
      auto valueData = nostd::get<int64_t>(last_point_data.value_);
      jsonObj.setInt64(valueData, "/value");
    }
  }
}

bool DataHubExporter::ForceFlush(std::chrono::microseconds /* timeout */) noexcept
{
  const std::lock_guard<opentelemetry::common::SpinLockMutex> locked(lock_);
  return true;
}

bool DataHubExporter::Shutdown(std::chrono::microseconds /* timeout */) noexcept
{
  const std::lock_guard<opentelemetry::common::SpinLockMutex> locked(lock_);
  is_shutdown_ = true;
  return true;
}

bool DataHubExporter::isShutdown() const noexcept
{
  const std::lock_guard<opentelemetry::common::SpinLockMutex> locked(lock_);
  return is_shutdown_;
}

}  // namespace metrics
}  // namespace exporter
OPENTELEMETRY_END_NAMESPACE
