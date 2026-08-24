/*
 * Wazuh remoted module - /download endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_DOWNLOAD_METRICS_HPP
#define _REMOTED_ENDPOINTS_DOWNLOAD_METRICS_HPP

/**
 * @file downloadMetrics.hpp
 * @brief The /download counter catalog (`remoted.download.*`) on the shared `wazuh_metrics`
 *        registry.
 *
 * Same shape as control/metrics.hpp: resolve once via makeDownloadMetrics() (cold path), every
 * inc* afterwards is a single relaxed atomic op, and a default-constructed struct is the null
 * object that counts nothing. NEVER exposed through the public HTTPS endpoint.
 *
 * Not a remoted.http.* ResponseCounters family: /download's outcomes are admission-time
 * decisions plus a stream START -- once a 200 and a chunk are on the wire the transfer's fate
 * belongs to the transport, so a "responses.2xx" would overpromise. Everything here is counted
 * BEFORE the streaming pump runs; the pump itself (thousands of chunk iterations per WPK on the
 * transport thread) is deliberately uninstrumented.
 */

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::endpoints::download
{
    // The remoted.download.* name catalog.
    constexpr auto METRIC_DOWNLOAD_REJECTED {"remoted.download.rejected"};
    constexpr auto METRIC_DOWNLOAD_NOT_FOUND {"remoted.download.not_found"};
    constexpr auto METRIC_DOWNLOAD_OPEN_ERROR {"remoted.download.open_error"};
    constexpr auto METRIC_DOWNLOAD_STARTED {"remoted.download.started"};
    constexpr auto METRIC_DOWNLOAD_BYTES_TOTAL {"remoted.download.bytes.total"};

    /**
     * @brief The /download counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null object the tests rely on.
     */
    struct DownloadMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> rejected;   ///< 400s: the request line didn't parse.
        std::shared_ptr<wazuh::metrics::ICounter> notFound;   ///< 404s: the group/WPK doesn't exist
                                                              ///< (config drift -> agent retry storms).
        std::shared_ptr<wazuh::metrics::ICounter> openError;  ///< 500s: the file exists but won't open.
        std::shared_ptr<wazuh::metrics::ICounter> started;    ///< Transfers whose stream was started.
        std::shared_ptr<wazuh::metrics::ICounter> bytesTotal; ///< Bytes OFFERED, added once per started
                                                              ///< transfer (an aborted transfer therefore
                                                              ///< overcounts). A counter, not a histogram:
                                                              ///< AtomicHistogram saturates at 2^32 and is
                                                              ///< lossy for byte counts.
    };

    /// Resolves the remoted.download.* family on @p manager (creating it on first call; totals
    /// carry over on later calls because getOrCreateCounter dedupes by name).
    inline DownloadMetrics makeDownloadMetrics(wazuh::metrics::IManager& manager)
    {
        return DownloadMetrics {
            manager.getOrCreateCounter(
                METRIC_DOWNLOAD_REJECTED, "400 rejections: the /download request did not parse", "count"),
            manager.getOrCreateCounter(
                METRIC_DOWNLOAD_NOT_FOUND, "404s: the requested group/WPK does not exist", "count"),
            manager.getOrCreateCounter(
                METRIC_DOWNLOAD_OPEN_ERROR, "500s: the located resource could not be opened", "count"),
            manager.getOrCreateCounter(METRIC_DOWNLOAD_STARTED, "Streamed transfers started", "count"),
            manager.getOrCreateCounter(
                METRIC_DOWNLOAD_BYTES_TOTAL, "Bytes offered to started transfers (counted once at start)", "bytes")};
    }

    // const&: called from the endpoint's value-capturing (non-mutable) lambda; add() mutates
    // the counter, not the struct.
    inline void incRejected(const DownloadMetrics& m)
    {
        if (m.rejected)
        {
            m.rejected->add();
        }
    }
    inline void incNotFound(const DownloadMetrics& m)
    {
        if (m.notFound)
        {
            m.notFound->add();
        }
    }
    inline void incOpenError(const DownloadMetrics& m)
    {
        if (m.openError)
        {
            m.openError->add();
        }
    }
    inline void incStarted(const DownloadMetrics& m, std::uint64_t offeredBytes)
    {
        if (m.started)
        {
            m.started->add();
        }
        if (m.bytesTotal)
        {
            m.bytesTotal->add(offeredBytes);
        }
    }

} // namespace remoted::endpoints::download

#endif // _REMOTED_ENDPOINTS_DOWNLOAD_METRICS_HPP
