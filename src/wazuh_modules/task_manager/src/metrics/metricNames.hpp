/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_METRICS_METRIC_NAMES_HPP
#define _TASK_MANAGER_METRICS_METRIC_NAMES_HPP

/**
 * @brief Every metric name the module publishes, and nowhere else.
 *
 * These are an external contract: docs/ref/modules/task_manager/metrics.md, the benchmark scrapers
 * and any dashboard read them verbatim, so a change here is a rename for all of them. A `_PREFIX`
 * is completed at its one call site with a task type and, where noted, a `.<suffix>`.
 */
namespace task_manager::metrics::names
{
    // ---- agent tasks -------------------------------------------------------------------------
    constexpr auto AGENT_TASKS_CREATED {"task_manager.agent_tasks.created"};
    constexpr auto AGENT_TASKS_DELIVERED {"task_manager.agent_tasks.delivered"};
    constexpr auto AGENT_TASKS_EMPTY_CACHE_ENTRIES {"task_manager.agent_tasks.empty_cache_entries"};

    // ---- manager tasks -----------------------------------------------------------------------
    /// @brief `<prefix><task_type>`: pending rows of a registered type.
    constexpr auto QUEUE_PENDING_PREFIX {"task_manager.queue.pending."};
    /// @brief `<prefix><task_type>.<result>`: one counter per registered type and create result.
    constexpr auto MANAGER_TASKS_CREATED_PREFIX {"task_manager.manager_tasks.created."};
    /// @brief `<prefix><task_type>.<status>`: rows the executor brought to a terminal status.
    constexpr auto MANAGER_TASKS_RETIRED_PREFIX {"task_manager.manager_tasks.retired."};
    constexpr auto MANAGER_TASKS_RECLAIMED {"task_manager.manager_tasks.reclaimed"};
    /// @brief `<prefix><task_type>.<outcome>`: what each handler run returned.
    constexpr auto HANDLER_OUTCOME_PREFIX {"task_manager.handler.outcome."};
    constexpr auto HANDLER_DURATION {"task_manager.handler.duration"};
    constexpr auto EXECUTOR_BUSY_WORKERS {"task_manager.executor.busy_workers"};

    /**
     * @brief The `<task_type>` segment every type this build does not register is counted under,
     *        in the MANAGER_TASKS_CREATED_PREFIX family.
     *
     * The create route admits any type name, so naming the counter after the request would mint a
     * new metric per misspelt or invented type, for the life of the process. Unregistered types
     * share this one bucket instead; no registered type may carry this name.
     */
    constexpr auto UNKNOWN_TASK_TYPE {"unknown"};

    // ---- HTTP transport ----------------------------------------------------------------------
    constexpr auto HTTP_LIVE_SESSIONS {"task_manager.http.live_sessions"};
    constexpr auto HTTP_INFLIGHT_REQUESTS {"task_manager.http.inflight_requests"};
    constexpr auto HTTP_INFLIGHT_BYTES {"task_manager.http.inflight_bytes"};

    // ---- agent upgrades ----------------------------------------------------------------------
    constexpr auto UPGRADE_QUEUE_DEPTH {"task_manager.upgrade.queue_depth"};
    constexpr auto UPGRADE_BATCHES_SHED {"task_manager.upgrade.batches_shed"};
    constexpr auto UPGRADE_WPK_DOWNLOADS {"task_manager.upgrade.wpk_downloads"};
    constexpr auto UPGRADE_WPK_CACHE_HITS {"task_manager.upgrade.wpk_cache_hits"};
    constexpr auto UPGRADE_VERSIONS_FETCHES {"task_manager.upgrade.versions_fetches"};
    constexpr auto UPGRADE_VERSIONS_CACHE_HITS {"task_manager.upgrade.versions_cache_hits"};
} // namespace task_manager::metrics::names

#endif // _TASK_MANAGER_METRICS_METRIC_NAMES_HPP
