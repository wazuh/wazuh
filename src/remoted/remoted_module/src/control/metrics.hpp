/*
 * Wazuh remoted module - Control endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_METRICS_HPP
#define _REMOTED_CONTROL_METRICS_HPP

/**
 * @file metrics.hpp
 * @brief The /control counter catalog (`remoted.control.*`) on the shared `wazuh_metrics` registry.
 *
 * The counters live in the facade's metric manager (shared_modules/metrics), so a dump of that
 * manager shows them alongside every other remoted family. This struct only caches the resolved
 * shared_ptrs: consumers resolve once via makeControlMetrics() (cold path) and every inc*
 * afterwards is a single relaxed atomic op, exactly like the hand-rolled std::atomic fields it
 * replaced. NEVER exposed through the public HTTPS endpoint (it is agent-facing, not an admin
 * plane); observability is the manager's dump (log today, UDS /metrics later).
 */

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::control
{
    // The remoted.control.* name catalog. Kept here (not per call-site) so the dump reads as one
    // coherent namespace and no two components invent competing names for the same thing.
    constexpr auto METRIC_STARTUP {"remoted.control.startup"};
    constexpr auto METRIC_NOTIFY {"remoted.control.notify"};
    constexpr auto METRIC_SHUTDOWN {"remoted.control.shutdown"};
    constexpr auto METRIC_WDB_ERROR {"remoted.control.wdb_error"};
    constexpr auto METRIC_TASK_FETCH {"remoted.control.task_fetch"};
    constexpr auto METRIC_TASK_FETCH_ERROR {"remoted.control.task_fetch_error"};

    /**
     * @brief The /control counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null-object the tests rely on, so
     * a bare `ControlMetrics {}` stays a valid collaborator for WazuhDBClient/TaskClient/
     * ControlHandler.
     */
    struct ControlMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> startup;
        std::shared_ptr<wazuh::metrics::ICounter> notify;
        std::shared_ptr<wazuh::metrics::ICounter> shutdown;
        std::shared_ptr<wazuh::metrics::ICounter> wdbError;
        std::shared_ptr<wazuh::metrics::ICounter> taskFetch;
        std::shared_ptr<wazuh::metrics::ICounter> taskFetchError;
    };

    /// Resolves the remoted.control.* family on @p manager (creating it on first call; totals
    /// carry over on later calls because getOrCreateCounter dedupes by name).
    inline ControlMetrics makeControlMetrics(wazuh::metrics::IManager& manager)
    {
        return ControlMetrics {
            manager.getOrCreateCounter(METRIC_STARTUP, "Startup control requests handled", "count"),
            manager.getOrCreateCounter(METRIC_NOTIFY, "Keepalive (notify) control requests handled", "count"),
            manager.getOrCreateCounter(METRIC_SHUTDOWN, "Shutdown control requests handled", "count"),
            manager.getOrCreateCounter(METRIC_WDB_ERROR, "wazuh-db round trips that failed", "count"),
            manager.getOrCreateCounter(METRIC_TASK_FETCH, "Pending-task fetches that succeeded", "count"),
            manager.getOrCreateCounter(METRIC_TASK_FETCH_ERROR, "Pending-task fetches that failed", "count")};
    }

    inline void incStartup(ControlMetrics& m)
    {
        if (m.startup)
        {
            m.startup->add();
        }
    }
    inline void incNotify(ControlMetrics& m)
    {
        if (m.notify)
        {
            m.notify->add();
        }
    }
    inline void incShutdown(ControlMetrics& m)
    {
        if (m.shutdown)
        {
            m.shutdown->add();
        }
    }
    inline void incWdbError(ControlMetrics& m)
    {
        if (m.wdbError)
        {
            m.wdbError->add();
        }
    }
    inline void incTaskFetch(ControlMetrics& m)
    {
        if (m.taskFetch)
        {
            m.taskFetch->add();
        }
    }
    inline void incTaskFetchError(ControlMetrics& m)
    {
        if (m.taskFetchError)
        {
            m.taskFetchError->add();
        }
    }

} // namespace remoted::control

#endif // _REMOTED_CONTROL_METRICS_HPP
