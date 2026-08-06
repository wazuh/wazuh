/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <wazuh_metrics/jsonDump.hpp>

namespace
{
    const char* typeName(wazuh::metrics::MetricType type)
    {
        // Same strings the engine's /metrics dump uses, plus the histogram.
        switch (type)
        {
            case wazuh::metrics::MetricType::COUNTER: return "counter";
            case wazuh::metrics::MetricType::GAUGE_INT: return "gauge_int";
            case wazuh::metrics::MetricType::PULL: return "pull";
            case wazuh::metrics::MetricType::HISTOGRAM: return "histogram";
        }
        return "unknown";
    }

    std::string nowISO8601()
    {
        std::time_t now {};
        std::time(&now);
        std::tm utc {};
        gmtime_r(&now, &utc);
        char buffer[sizeof "1970-01-01T00:00:00Z"];
        std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &utc);
        return buffer;
    }

    template<typename WriterT>
    void writeMetric(WriterT& writer,
                     const std::string& name,
                     const wazuh::metrics::IMetric& metric,
                     const wazuh::metrics::IManager::Metadata& metadata)
    {
        writer.StartObject();
        writer.Key("name");
        writer.String(name.c_str(), static_cast<rapidjson::SizeType>(name.size()));
        writer.Key("type");
        writer.String(typeName(metric.type()));
        writer.Key("enabled");
        writer.Bool(metric.isEnabled());

        // dynamic_cast rather than trusting type(): this is the cold path, and a
        // foreign IMetric implementation mismatching its declared type must not be UB.
        const auto* counter = dynamic_cast<const wazuh::metrics::ICounter*>(&metric);
        const auto* gauge = dynamic_cast<const wazuh::metrics::IGaugeInt*>(&metric);
        const auto* histogram = dynamic_cast<const wazuh::metrics::IHistogram*>(&metric);

        writer.Key("value");
        if (counter)
        {
            writer.Uint64(counter->get());
        }
        else if (gauge)
        {
            writer.Int64(gauge->get());
        }
        else if (histogram)
        {
            // The observation count; the distribution follows in "summary".
            writer.Uint64(histogram->snapshot().count);
        }
        else
        {
            writer.Double(metric.value());
        }

        if (!metadata.description.empty())
        {
            writer.Key("description");
            writer.String(metadata.description.c_str(), static_cast<rapidjson::SizeType>(metadata.description.size()));
        }
        if (!metadata.unit.empty())
        {
            writer.Key("unit");
            writer.String(metadata.unit.c_str(), static_cast<rapidjson::SizeType>(metadata.unit.size()));
        }

        if (histogram)
        {
            const auto snapshot = histogram->snapshot();
            writer.Key("summary");
            writer.StartObject();
            writer.Key("count");
            writer.Uint64(snapshot.count);
            writer.Key("sum");
            writer.Uint64(snapshot.sum);
            writer.Key("min");
            writer.Uint64(snapshot.min);
            writer.Key("max");
            writer.Uint64(snapshot.max);
            writer.Key("p50");
            writer.Uint64(snapshot.p50);
            writer.Key("p90");
            writer.Uint64(snapshot.p90);
            writer.Key("p99");
            writer.Uint64(snapshot.p99);
            writer.EndObject();
        }

        writer.EndObject();
    }

    template<typename WriterT>
    void
    writeDocument(WriterT& writer, const wazuh::metrics::IManager& manager, const wazuh::metrics::DumpOptions& options)
    {
        writer.StartObject();
        writer.Key("name");
        writer.String(options.daemonName.c_str(), static_cast<rapidjson::SizeType>(options.daemonName.size()));
        writer.Key("timestamp");
        const auto timestamp = options.timestampISO.empty() ? nowISO8601() : options.timestampISO;
        writer.String(timestamp.c_str(), static_cast<rapidjson::SizeType>(timestamp.size()));

        writer.Key("metrics");
        writer.StartArray();

        auto names = manager.getAllNames();
        std::sort(names.begin(), names.end());
        for (const auto& name : names)
        {
            const auto metric = manager.get(name);
            if (!metric)
            {
                continue; // racing a clear(); skip rather than emit a hole
            }
            writeMetric(writer, name, *metric, manager.getMetadata(name));
        }

        writer.EndArray();
        writer.EndObject();
    }
} // namespace

namespace wazuh::metrics
{

    std::string dumpJson(const IManager& manager, const DumpOptions& options)
    {
        rapidjson::StringBuffer buffer;
        if (options.pretty)
        {
            rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
            writeDocument(writer, manager, options);
        }
        else
        {
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            writeDocument(writer, manager, options);
        }
        return {buffer.GetString(), buffer.GetSize()};
    }

} // namespace wazuh::metrics
