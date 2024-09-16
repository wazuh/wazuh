#ifndef _METRICS_METRICSERIALIZER_HPP
#define _METRICS_METRICSERIALIZER_HPP

#include <opentelemetry/sdk/metrics/data/metric_data.h>

#include <base/json.hpp>

#include <metrics/ot.hpp>

namespace metrics::details
{
/**
 * @brief Serialize MetricData to json
 *
 * @param metricData
 * @return json::Json
 */
inline json::Json metricDataToJson(const ot::MetricData& metricData)
{
    json::Json jsonMetric;
    jsonMetric.setString(metricData.instrument_descriptor.name_, "/name");
    jsonMetric.setString(metricData.instrument_descriptor.description_, "/description");
    jsonMetric.setString(metricData.instrument_descriptor.unit_, "/unit");
    return jsonMetric;
}
} // namespace metrics::details

#endif // _METRICS_METRICSERIALIZER_HPP
