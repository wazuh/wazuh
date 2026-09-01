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
    // The remoted.scanvd.* name catalog. Every counter is an admission-time decision: the
    // handler is a synchronous passthrough of VD's own admission, so there is no worker-side
    // family -- what became of an accepted scan is VD's to report (its dispatcher logs each
    // outcome), and a request VD refused was answered 503, which the agent knows to retry.
    constexpr auto METRIC_REQUESTS_TOTAL {"remoted.scanvd.requests.total"};
    constexpr auto METRIC_VERSION_MISMATCH {"remoted.scanvd.version_mismatch"};
    constexpr auto METRIC_QUEUE_FULL {"remoted.scanvd.queue_full"};
    constexpr auto METRIC_INVALID_AGENT {"remoted.scanvd.invalid_agent"};
    constexpr auto METRIC_ACCEPTED {"remoted.scanvd.accepted"};
    constexpr auto METRIC_VD_ERROR {"remoted.scanvd.vd_error"};
    constexpr auto METRIC_INDEXER_UNAVAILABLE {"remoted.scanvd.indexer_unavailable"};

    /**
     * @brief The /scan/vd counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null-object the tests rely on, so
     * a bare `ScanVdMetrics {}` stays a valid collaborator for ScanVdHandlerImpl.
     */
    struct ScanVdMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> requests;
        std::shared_ptr<wazuh::metrics::ICounter> versionMismatch; ///< 409s: requested offset != current offset.
        std::shared_ptr<wazuh::metrics::ICounter> queueFull;       ///< 503s: VD's dispatch queue at capacity.
        std::shared_ptr<wazuh::metrics::ICounter> invalidAgent;    ///< 400s: agentId 0 reached the handler.
        std::shared_ptr<wazuh::metrics::ICounter> accepted;        ///< 200s: VD queued the scan -- it will run.
        std::shared_ptr<wazuh::metrics::ICounter> vdError;         ///< 503s for any other reason: VD unreachable, not
                                                                   ///< ready, stopping, or an unexpected answer.
        std::shared_ptr<wazuh::metrics::ICounter> indexerUnavailable; ///< 503s: VD refused because no indexer host is
                                                                      ///< healthy. VD's own reported cause (like
                                                                      ///< queueFull), NOT a relay failure.
    };

    /// Resolves the remoted.scanvd.* family on @p manager (creating it on first call; totals
    /// carry over on later calls because getOrCreateCounter dedupes by name).
    inline ScanVdMetrics makeScanVdMetrics(wazuh::metrics::IManager& manager)
    {
        return ScanVdMetrics {
            manager.getOrCreateCounter(METRIC_REQUESTS_TOTAL, "/scan/vd requests reaching the handler", "count"),
            manager.getOrCreateCounter(
                METRIC_VERSION_MISMATCH, "409 rejections: requested offset != current offset", "count"),
            manager.getOrCreateCounter(
                METRIC_QUEUE_FULL, "503 rejections: VD's scan dispatch queue at capacity", "count"),
            manager.getOrCreateCounter(METRIC_INVALID_AGENT, "400 rejections: agentId 0 reached the handler", "count"),
            manager.getOrCreateCounter(METRIC_ACCEPTED, "200 acceptances: VD queued the scan", "count"),
            manager.getOrCreateCounter(
                METRIC_VD_ERROR, "503s relayed for non-capacity reasons: VD unreachable, not ready, ...", "count"),
            manager.getOrCreateCounter(
                METRIC_INDEXER_UNAVAILABLE, "503 rejections: VD reports no healthy indexer host", "count")};
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
    inline void incVdError(ScanVdMetrics& m)
    {
        if (m.vdError)
        {
            m.vdError->add();
        }
    }
    inline void incIndexerUnavailable(ScanVdMetrics& m)
    {
        if (m.indexerUnavailable)
        {
            m.indexerUnavailable->add();
        }
    }

} // namespace remoted::scanvd

#endif // _REMOTED_SCANVD_METRICS_HPP
