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

/**
 * @file scanVdMetrics.hpp
 * @brief The /scan/vd counter catalog (`remoted.scanvd.*`) on the shared `wazuh_metrics` registry.
 *
 * Same shape as control/metrics.hpp: the counters live in the facade's metric manager, this
 * struct only caches the resolved shared_ptrs (resolve once via makeScanVdMetrics(), then every
 * inc* is a single relaxed atomic op), and a default-constructed struct is the null object that
 * counts nothing. NEVER exposed through the public HTTPS endpoint.
 */

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::scanvd
{
    // The remoted.scanvd.* name catalog. `requests`/`accepted`/... count the handler's immediate
    // accept/reject decision; the `scans.*` names count what the background worker did with an
    // accepted request afterwards.
    constexpr auto METRIC_REQUESTS_TOTAL {"remoted.scanvd.requests.total"};
    constexpr auto METRIC_VERSION_MISMATCH {"remoted.scanvd.version_mismatch"};
    constexpr auto METRIC_QUEUE_FULL {"remoted.scanvd.queue_full"};
    constexpr auto METRIC_INVALID_AGENT {"remoted.scanvd.invalid_agent"};
    constexpr auto METRIC_ACCEPTED {"remoted.scanvd.accepted"};
    constexpr auto METRIC_SCANS_SUCCEEDED {"remoted.scanvd.scans.succeeded"};
    constexpr auto METRIC_SCANS_RETRIED {"remoted.scanvd.scans.retried"};
    constexpr auto METRIC_SCANS_RETRIES_EXHAUSTED {"remoted.scanvd.scans.retries_exhausted"};
    constexpr auto METRIC_SCANS_PERMANENT_FAILURE {"remoted.scanvd.scans.permanent_failure"};
    constexpr auto METRIC_SCANS_DISCARDED {"remoted.scanvd.scans.discarded"};

    /**
     * @brief The /scan/vd counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null-object the tests rely on, so
     * a bare `ScanVdMetrics {}` stays a valid collaborator for ScanVdHandlerImpl.
     */
    struct ScanVdMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> requests;
        std::shared_ptr<wazuh::metrics::ICounter> versionMismatch;      ///< 409s: requested offset != current offset.
        std::shared_ptr<wazuh::metrics::ICounter> queueFull;            ///< 503s: tracking table at capacity.
        std::shared_ptr<wazuh::metrics::ICounter> invalidAgent;         ///< 400s: agentId 0 reached the handler.
        std::shared_ptr<wazuh::metrics::ICounter> accepted;             ///< 200s: queued, or refreshed an entry.
        std::shared_ptr<wazuh::metrics::ICounter> scanSucceeded;        ///< Worker successfully triggered the scan.
        std::shared_ptr<wazuh::metrics::ICounter> scanRetried;          ///< Worker hit a retryable failure.
        std::shared_ptr<wazuh::metrics::ICounter> scanRetriesExhausted; ///< Worker gave up after MAX_RETRIES.
        std::shared_ptr<wazuh::metrics::ICounter> scanPermanentFailure; ///< VD returned a non-retryable error.
        std::shared_ptr<wazuh::metrics::ICounter> scanDiscarded;        ///< Skipped at execution: offset moved on.
    };

    /// Resolves the remoted.scanvd.* family on @p manager (creating it on first call; totals
    /// carry over on later calls because getOrCreateCounter dedupes by name).
    inline ScanVdMetrics makeScanVdMetrics(wazuh::metrics::IManager& manager)
    {
        return ScanVdMetrics {
            manager.getOrCreateCounter(METRIC_REQUESTS_TOTAL, "/scan/vd requests reaching the handler", "count"),
            manager.getOrCreateCounter(
                METRIC_VERSION_MISMATCH, "409 rejections: requested offset != current offset", "count"),
            manager.getOrCreateCounter(METRIC_QUEUE_FULL, "503 rejections: tracking table at capacity", "count"),
            manager.getOrCreateCounter(METRIC_INVALID_AGENT, "400 rejections: agentId 0 reached the handler", "count"),
            manager.getOrCreateCounter(
                METRIC_ACCEPTED, "200 acceptances: queued, or refreshed an existing entry", "count"),
            manager.getOrCreateCounter(
                METRIC_SCANS_SUCCEEDED, "Scans the worker successfully triggered on VD", "count"),
            manager.getOrCreateCounter(
                METRIC_SCANS_RETRIED, "Scan attempts that hit a retryable failure and backed off", "count"),
            manager.getOrCreateCounter(
                METRIC_SCANS_RETRIES_EXHAUSTED, "Scans given up after exhausting MAX_RETRIES", "count"),
            manager.getOrCreateCounter(
                METRIC_SCANS_PERMANENT_FAILURE, "Scans VD rejected with a non-retryable error", "count"),
            manager.getOrCreateCounter(
                METRIC_SCANS_DISCARDED, "Scans skipped at execution time: offset moved on", "count")};
    }

    inline void incRequests(ScanVdMetrics& m)
    {
        if (m.requests)
        {
            m.requests->add();
        }
    }
    inline void incVersionMismatch(ScanVdMetrics& m)
    {
        if (m.versionMismatch)
        {
            m.versionMismatch->add();
        }
    }
    inline void incQueueFull(ScanVdMetrics& m)
    {
        if (m.queueFull)
        {
            m.queueFull->add();
        }
    }
    inline void incInvalidAgent(ScanVdMetrics& m)
    {
        if (m.invalidAgent)
        {
            m.invalidAgent->add();
        }
    }
    inline void incAccepted(ScanVdMetrics& m)
    {
        if (m.accepted)
        {
            m.accepted->add();
        }
    }
    inline void incScanSucceeded(ScanVdMetrics& m)
    {
        if (m.scanSucceeded)
        {
            m.scanSucceeded->add();
        }
    }
    inline void incScanRetried(ScanVdMetrics& m)
    {
        if (m.scanRetried)
        {
            m.scanRetried->add();
        }
    }
    inline void incScanRetriesExhausted(ScanVdMetrics& m)
    {
        if (m.scanRetriesExhausted)
        {
            m.scanRetriesExhausted->add();
        }
    }
    inline void incScanPermanentFailure(ScanVdMetrics& m)
    {
        if (m.scanPermanentFailure)
        {
            m.scanPermanentFailure->add();
        }
    }
    inline void incScanDiscarded(ScanVdMetrics& m)
    {
        if (m.scanDiscarded)
        {
            m.scanDiscarded->add();
        }
    }

} // namespace remoted::scanvd

#endif // _REMOTED_SCANVD_METRICS_HPP
