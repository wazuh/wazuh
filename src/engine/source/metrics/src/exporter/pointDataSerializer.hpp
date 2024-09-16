#ifndef _METRICS_POINTDATASERIALIZER_HPP
#define _METRICS_POINTDATASERIALIZER_HPP

#include <opentelemetry/sdk/metrics/data/point_data.h>

#include <base/json.hpp>

#include <metrics/ot.hpp>

namespace metrics::details
{
/**
 * @brief Serialize SumPointData to json
 *
 * @param pointData
 * @return json::Json
 */
inline json::Json pointDataToJson(const ot::SumPointData pointData)
{
    json::Json jsonPoint;
    if (pointData.is_monotonic_)
    {
        jsonPoint.setBool(true, "/isMonotonic");
    }
    if (std::holds_alternative<int64_t>(pointData.value_))
    {
        jsonPoint.setInt64(std::get<int64_t>(pointData.value_), "/value");
    }
    else if (std::holds_alternative<double>(pointData.value_))
    {
        jsonPoint.setDouble(std::get<double>(pointData.value_), "/value");
    }
    else
    {
        throw std::runtime_error("Unsupported point data value type");
    }
    return jsonPoint;
}

/**
 * @brief Serialize LastValuePointData to json
 *
 * @param pointData
 * @return json::Json
 */
inline json::Json pointDataToJson(const ot::LastValuePointData pointData)
{
    json::Json jsonPoint;
    if (std::holds_alternative<int64_t>(pointData.value_))
    {
        jsonPoint.setInt64(std::get<int64_t>(pointData.value_), "/value");
    }
    else if (std::holds_alternative<double>(pointData.value_))
    {
        jsonPoint.setDouble(std::get<double>(pointData.value_), "/value");
    }
    else
    {
        throw std::runtime_error("Unsupported point data value type");
    }

    jsonPoint.setBool(pointData.is_lastvalue_valid_, "/valid");
    jsonPoint.setString(std::to_string(pointData.sample_ts_.time_since_epoch().count()), "/timestamp");

    return jsonPoint;
}

/**
 * @brief Serialize HistogramPointData to json
 *
 * @param pointData
 * @return json::Json
 */
inline json::Json pointDataToJson(const ot::HistogramPointData pointData)
{
    json::Json jsonPoint;
    jsonPoint.setInt64(pointData.count_, "/count");
    if (pointData.record_min_max_)
    {
        if (std::holds_alternative<int64_t>(pointData.min_))
        {
            jsonPoint.setInt64(std::get<int64_t>(pointData.min_), "/min");
        }
        else if (std::holds_alternative<double>(pointData.min_))
        {
            jsonPoint.setDouble(std::get<double>(pointData.min_), "/min");
        }
        if (std::holds_alternative<int64_t>(pointData.max_))
        {
            jsonPoint.setInt64(std::get<int64_t>(pointData.max_), "/max");
        }
        else if (std::holds_alternative<double>(pointData.max_))
        {
            jsonPoint.setDouble(std::get<double>(pointData.max_), "/max");
        }
    }

    if (std::holds_alternative<int64_t>(pointData.sum_))
    {
        jsonPoint.setInt64(std::get<int64_t>(pointData.sum_), "/sum");
    }
    else if (std::holds_alternative<double>(pointData.sum_))
    {
        jsonPoint.setDouble(std::get<double>(pointData.sum_), "/sum");
    }

    json::Json boundaries;
    boundaries.setArray("/boundaries");
    for (const auto& boundary : pointData.boundaries_)
    {
        json::Json boundaryJson;
        boundaryJson.setDouble(boundary);
        boundaries.appendJson(boundaryJson);
    }
    jsonPoint.appendJson(boundaries, "/boundaries");

    json::Json counts;
    counts.setArray("/counts");
    for (const auto& count : pointData.counts_)
    {
        json::Json countJson;
        countJson.setInt64(count);
        counts.appendJson(countJson);
    }
    jsonPoint.appendJson(counts, "/counts");

    return jsonPoint;
}

/**
 * @brief Serialize DropPointData to json (Represents no recorded data)
 *
 * @param pointData
 * @return json::Json
 */
inline json::Json pointDataToJson(const ot::DropPointData pointData)
{
    return json::Json {};
}

/**
 * @brief Serialize PointData to json
 *
 * @param pointData
 * @return json::Json
 */
inline json::Json pointDataToJson(const ot::PointType& pointData)
{
    switch (pointData.index())
    {
        case 0: return pointDataToJson(std::get<ot::SumPointData>(pointData));
        case 1: return pointDataToJson(std::get<ot::HistogramPointData>(pointData));
        case 2: return pointDataToJson(std::get<ot::LastValuePointData>(pointData));
        case 3: return pointDataToJson(std::get<ot::DropPointData>(pointData));
        default: throw std::runtime_error("Unsupported point data type");
    }
}

} // namespace metrics::details

#endif // _METRICS_POINTDATASERIALIZER_HPP
