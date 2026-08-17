/*
 * Wazuh remoted module - /scan/vd endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_SCANVD_METRICS_HPP
#define _REMOTED_SCANVD_METRICS_HPP

#include <atomic>
#include <cstdint>

namespace remoted::scanvd
{
    struct ScanVdMetrics
    {
        std::atomic<uint64_t> requestsTotal {0};
        std::atomic<uint64_t> versionMismatchCount {0};      ///< 409s: requested offset != current offset.
        std::atomic<uint64_t> queueFullCount {0};            ///< 503s: tracking table at capacity.
        std::atomic<uint64_t> invalidAgentCount {0};         ///< 400s: agentId 0 reached the handler.
        std::atomic<uint64_t> acceptedCount {0};             ///< 200s: queued, or refreshed an existing entry.
        std::atomic<uint64_t> scanSucceededCount {0};        ///< Worker successfully triggered the VD scan.
        std::atomic<uint64_t> scanRetriedCount {0};          ///< Worker hit a retryable failure, backing off.
        std::atomic<uint64_t> scanRetriesExhaustedCount {0}; ///< Worker gave up after MAX_RETRIES.
        std::atomic<uint64_t> scanPermanentFailureCount {0}; ///< VD returned a non-retryable error.
        std::atomic<uint64_t> scanDiscardedCount {0};        ///< Skipped at execution time: offset moved on.
    };

    inline void incRequests(ScanVdMetrics& m)
    {
        m.requestsTotal.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incVersionMismatch(ScanVdMetrics& m)
    {
        m.versionMismatchCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incQueueFull(ScanVdMetrics& m)
    {
        m.queueFullCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incInvalidAgent(ScanVdMetrics& m)
    {
        m.invalidAgentCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incAccepted(ScanVdMetrics& m)
    {
        m.acceptedCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incScanSucceeded(ScanVdMetrics& m)
    {
        m.scanSucceededCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incScanRetried(ScanVdMetrics& m)
    {
        m.scanRetriedCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incScanRetriesExhausted(ScanVdMetrics& m)
    {
        m.scanRetriesExhaustedCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incScanPermanentFailure(ScanVdMetrics& m)
    {
        m.scanPermanentFailureCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incScanDiscarded(ScanVdMetrics& m)
    {
        m.scanDiscardedCount.fetch_add(1, std::memory_order_relaxed);
    }

} // namespace remoted::scanvd

#endif // _REMOTED_SCANVD_METRICS_HPP
