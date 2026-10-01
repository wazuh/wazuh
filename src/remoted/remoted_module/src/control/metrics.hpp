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
 * plane); observability is the manager's dump (GET /metrics on the local admin socket, and the
 * debug log on stop()).
 */

#include <cstdint>
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
    constexpr auto METRIC_REJECTED {"remoted.control.rejected"};
    constexpr auto METRIC_WDB_LATENCY {"remoted.control.wdb.latency"};
    constexpr auto METRIC_NO_ROW {"remoted.control.no_row"};
    // Membership publications on the local admin socket (POST /_internal/agents/groups): per-agent
    // outcomes plus the publications refused whole. Same family as the registry they write, so the
    // dump reads as one remoted.control.* namespace.
    constexpr auto METRIC_PUSH_UPDATED {"remoted.control.registry.push.updated"};
    constexpr auto METRIC_PUSH_INVALIDATED {"remoted.control.registry.push.invalidated"};
    constexpr auto METRIC_PUSH_SKIPPED {"remoted.control.registry.push.skipped"};
    constexpr auto METRIC_PUSH_REJECTED {"remoted.control.registry.push.rejected"};

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
        std::shared_ptr<wazuh::metrics::ICounter> rejected; ///< 400s: malformed /control (version drift signal).
        /// Successful wazuh-db round-trip time, microseconds. Timeouts are deliberately NOT
        /// observed -- wdbError already counts them -- so the histogram means "how long a
        /// healthy round trip takes", the number that sizes the internal options
        /// 'remoted.control_wdb_roundtrip_deadline' and 'remoted.control_wdb_request_connections'.
        std::shared_ptr<wazuh::metrics::IHistogram> wdbLatency;
        /// 503s because the local wazuh-db has no row for the agent (`ok []`): a startup or notify
        /// whose membership had to be read and could not be, because the agent is not (yet) in the
        /// node's replica. Disjoint from wdbError, which counts lookups that FAILED. Appended last:
        /// the struct is brace-initialized positionally by makeControlMetrics().
        std::shared_ptr<wazuh::metrics::ICounter> noRow;
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
            manager.getOrCreateCounter(METRIC_TASK_FETCH_ERROR, "Pending-task fetches that failed", "count"),
            manager.getOrCreateCounter(
                METRIC_REJECTED, "400 rejections: malformed /control body/JSON/agent-id/type", "count"),
            manager.getOrCreateHistogram(METRIC_WDB_LATENCY, "Successful wazuh-db round-trip time", "microseconds"),
            manager.getOrCreateCounter(
                METRIC_NO_ROW, "503s: the local wazuh-db has no row for the agent (not yet synchronized)", "count")};
    }

    /**
     * @brief The membership-publication counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null object the tests rely on.
     */
    struct PushMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> updated;     ///< Agents whose entry took the published groups.
        std::shared_ptr<wazuh::metrics::ICounter> invalidated; ///< Agents whose membership was invalidated.
        std::shared_ptr<wazuh::metrics::ICounter> skipped;     ///< Agents this node holds no entry for: nothing
                                                               ///< is created, their first download looks them up.
        std::shared_ptr<wazuh::metrics::ICounter> rejected;    ///< Publications refused whole (400 malformed,
                                                               ///< 503 registry gone): a caller bug, or shutdown.
    };

    /// Resolves the remoted.control.registry.push.* counters on @p manager (deduped by name).
    inline PushMetrics makePushMetrics(wazuh::metrics::IManager& manager)
    {
        return PushMetrics {
            manager.getOrCreateCounter(
                METRIC_PUSH_UPDATED, "Agents whose registry entry took a published membership", "agents"),
            manager.getOrCreateCounter(
                METRIC_PUSH_INVALIDATED, "Agents whose membership a publication invalidated", "agents"),
            manager.getOrCreateCounter(
                METRIC_PUSH_SKIPPED, "Published agents this node holds no registry entry for", "agents"),
            manager.getOrCreateCounter(
                METRIC_PUSH_REJECTED, "Membership publications refused whole (malformed, or no registry)", "count")};
    }

    /// Adds @p n to one PushMetrics member; a null counter (the null object) counts nothing.
    inline void addPush(const std::shared_ptr<wazuh::metrics::ICounter>& counter, std::uint64_t n = 1)
    {
        if (counter && n != 0)
        {
            counter->add(n);
        }
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
    /// const&: called from the /control endpoint's value-capturing (non-mutable) lambda; add()
    /// mutates the counter, not the struct.
    inline void incRejected(const ControlMetrics& m)
    {
        if (m.rejected)
        {
            m.rejected->add();
        }
    }
    inline void incNoRow(const ControlMetrics& m)
    {
        if (m.noRow)
        {
            m.noRow->add();
        }
    }
    /// Records one SUCCESSFUL wazuh-db round trip (see the wdbLatency member note).
    inline void observeWdbLatency(const ControlMetrics& m, std::uint64_t micros)
    {
        if (m.wdbLatency)
        {
            m.wdbLatency->observe(micros);
        }
    }

} // namespace remoted::control

#endif // _REMOTED_CONTROL_METRICS_HPP
