/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_COMMON_METRIC_NAMES_HPP
#define _INVSYNC_COMMON_METRIC_NAMES_HPP

/**
 * @file metricNames.hpp
 * @brief This module's metric catalog (D18) and the shared per-code counter set.
 *
 * Names encode their dimensions (wazuh_metrics has no labels on purpose):
 * `sync.requests.total.<code>`, `sync.shard.<i>.depth`. The catalog lives here
 * so the dump reads as one coherent namespace and no two components invent
 * competing names for the same thing.
 */

#include <cstddef>
#include <memory>
#include <string>

#include <wazuh_metrics/iManager.hpp>

namespace invsync::metrics
{
    // -- pipeline ---------------------------------------------------------------------------
    constexpr auto REQUESTS_TOTAL_PREFIX {"sync.requests.total."}; ///< + HTTP status code
    constexpr auto PIPELINE_SHED_TOTAL {"sync.pipeline.shed.total"};
    constexpr auto BULK_FLUSHES {"sync.bulk.flushes"};
    constexpr auto BULK_BYTES_TOTAL {"sync.bulk.bytes.total"};
    constexpr auto BULK_SESSIONS_TOTAL {"sync.bulk.sessions.total"};
    constexpr auto SESSION_DURATION_BULK {"sync.session.duration.bulk"};
    constexpr auto SESSION_DURATION_IMMEDIATE {"sync.session.duration.immediate"};
    constexpr auto SHARD_PREFIX {"sync.shard."}; ///< + <worker> + ".depth" / ".bytes"

    // -- session application ----------------------------------------------------------------
    constexpr auto DOCS_INDEXED {"sync.docs.indexed"};
    constexpr auto DOCS_SKIPPED {"sync.docs.skipped"};
    constexpr auto BYTES_INGESTED {"sync.bytes.ingested"};

    // -- vulnerability-detection lane -------------------------------------------------------
    constexpr auto VD_CAPACITY_503_TOTAL {"vd.capacity.503.total"};
    constexpr auto VD_LANE_DEPTH {"vd.lane.depth"};
    constexpr auto VD_LANE_TIME {"vd.lane.time"};
    constexpr auto VD_OFFSET_MISMATCH_TOTAL {"vd.offset_mismatch.total"};
    constexpr auto VD_RETRY_AFTER_TOTAL {"vd.retry_after.total"};
    constexpr auto VD_SCAN_DURATION {"vd.scan.duration"};
    constexpr auto VD_SCANS_OK {"vd.scans.ok"};
    constexpr auto VD_SCANS_FAILED {"vd.scans.failed"};
    constexpr auto VD_SCANS_SKIPPED {"vd.scans.skipped"};

    /// @brief Gauge name for one pipeline shard: sync.shard.<index>.depth / .bytes
    inline std::string shardName(std::size_t index, const char* what)
    {
        return std::string {SHARD_PREFIX} + std::to_string(index) + "." + what;
    }

    /**
     * @brief The `sync.requests.total.<code>` counter family, pre-resolved.
     *
     * One counter per contract status, selected by a switch -- the hot path never
     * formats a metric name. Every component that SENDS a response (endpoint,
     * pipeline, scan lane) holds one of these; they resolve to the SAME underlying
     * counters because the names match on one manager. Each request is counted at
     * the single place its response is sent, so a request is never counted twice.
     *
     * Default-constructed (all null) it counts nothing -- the null-object the
     * tests rely on.
     */
    struct RequestCounters
    {
        std::shared_ptr<wazuh::metrics::ICounter> c200;
        std::shared_ptr<wazuh::metrics::ICounter> c400;
        std::shared_ptr<wazuh::metrics::ICounter> c403;
        std::shared_ptr<wazuh::metrics::ICounter> c409;
        std::shared_ptr<wazuh::metrics::ICounter> c500;
        std::shared_ptr<wazuh::metrics::ICounter> c503;
        std::shared_ptr<wazuh::metrics::ICounter> other;

        static RequestCounters make(wazuh::metrics::IManager& manager)
        {
            const auto counter = [&manager](const char* code)
            {
                return manager.getOrCreateCounter(std::string {REQUESTS_TOTAL_PREFIX} + code,
                                                  "POST /stateful (and deletion) responses sent with this status",
                                                  "count");
            };
            return RequestCounters {counter("200"),
                                    counter("400"),
                                    counter("403"),
                                    counter("409"),
                                    counter("500"),
                                    counter("503"),
                                    counter("other")};
        }

        void count(int status) const
        {
            const auto& counter = [this, status]() -> const std::shared_ptr<wazuh::metrics::ICounter>&
            {
                switch (status)
                {
                    case 200: return c200;
                    case 400: return c400;
                    case 403: return c403;
                    case 409: return c409;
                    case 500: return c500;
                    case 503: return c503;
                    default: return other;
                }
            }();
            if (counter)
            {
                counter->add();
            }
        }
    };

} // namespace invsync::metrics

#endif // _INVSYNC_COMMON_METRIC_NAMES_HPP
