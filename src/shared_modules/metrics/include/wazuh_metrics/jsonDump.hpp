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

#ifndef _WAZUH_METRICS_JSON_DUMP_HPP
#define _WAZUH_METRICS_JSON_DUMP_HPP

/**
 * @file jsonDump.hpp
 * @brief JSON serialization of a metric registry.
 *
 * Kept OUT of Manager on purpose: the metric core stays pure STL, and
 * rapidjson exists only inside jsonDump.cpp -- no rapidjson type ever appears
 * in a public header, so consumers (and their unit tests) never need its
 * include path.
 */

#include <string>

#include <wazuh_metrics/iManager.hpp>

namespace wazuh::metrics
{

    /**
     * @brief Options for dumpJson().
     */
    struct DumpOptions
    {
        /// Goes into the envelope's "name" field (the reporting daemon).
        std::string daemonName;
        /// Envelope timestamp. Empty means "now", UTC ISO-8601.
        std::string timestampISO;
        /// Pretty-print the output (default: compact).
        bool pretty {false};
    };

    /**
     * @brief Serialize every registered metric to a JSON string.
     *
     * Envelope: {"name": ..., "timestamp": ..., "metrics": [...]}, entries sorted
     * by metric name so the output is deterministic. Each entry carries
     * {name, type, enabled, value} -- counters and histogram counts as exact
     * unsigned integers, gauges as signed, pulls as double -- plus "description"/
     * "unit" when the metric registered them and a "summary" object
     * (count/sum/min/max/p50/p90/p99) for histograms.
     *
     * Cold path: takes the registry's shared lock per lookup; do not call per-event.
     *
     * @param manager The registry to dump.
     * @param options See DumpOptions.
     * @return The JSON document as a string.
     */
    std::string dumpJson(const IManager& manager, const DumpOptions& options = {});

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_JSON_DUMP_HPP
