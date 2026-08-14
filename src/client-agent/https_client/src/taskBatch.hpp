/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_TASK_BATCH_HPP
#define _HC_TASK_BATCH_HPP

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

/// One task as parsed from a Notify response (#37733 5.1.2).
struct NotifyTask
{
    std::string id;
    std::string type;
    std::string payloadJson;
};

/// The dispatch plan for one Notify batch: tasks in dispatch order, plus the
/// tasks dropped as redundant (paired with the type that covers them).
struct TaskBatchPlan
{
    std::vector<NotifyTask> ordered;
    std::vector<std::pair<NotifyTask, std::string>> dropped;
};

namespace taskBatchDetail
{
    /// Dispatch rank over the four contract types (#37733 §2: all
    /// fire-and-forget). Terminal tasks (upgrade/restart end the process)
    /// rank last so quick work is never lost behind them; unknown types
    /// (including the removed agent_reconnect/info_request, tolerated from
    /// older managers) rank after everything, in arrival order.
    inline int rankOf(const std::string& type)
    {
        if (type == "active_response")
        {
            return 0;
        }

        if (type == "agent_reload")
        {
            return 1;
        }

        if (type == "remote_upgrade")
        {
            return 2;
        }

        if (type == "agent_restart")
        {
            return 3;
        }

        return 4;
    }

    /// The batch-mate type that makes this task redundant, or empty. All
    /// tasks are fire-and-forget, so dropping owes nothing: an upgrade ends
    /// in a restart (which reloads), and a restart reloads by itself.
    ///
    /// Collapsing is deliberately ACROSS types only; two tasks of the same
    /// type both survive. That is not an oversight:
    ///
    ///  - active_response tasks carry per-task payloads, so two of them are
    ///    two different actions (block 10.0.0.1 and block 10.0.0.2). Folding
    ///    them together would silently discard real work.
    ///  - for remote_upgrade, which of two differing payloads should win is a
    ///    contract question (#37733), not something this planner can decide.
    ///
    /// The manager is the trusted source of the batch and assigns
    /// deterministic task ids (#37944), so a batch carrying two upgrades is a
    /// manager-side defect. Worth knowing that it would dispatch twice, which
    /// once #37834 wires execution means two installer runs.
    inline std::string subsumerOf(const std::string& type, bool hasUpgrade, bool hasRestart)
    {
        if (type == "agent_restart" && hasUpgrade)
        {
            return "remote_upgrade";
        }

        if (type == "agent_reload")
        {
            if (hasUpgrade)
            {
                return "remote_upgrade";
            }

            if (hasRestart)
            {
                return "agent_restart";
            }
        }

        return {};
    }
} // namespace taskBatchDetail

/**
 * @brief Plans one Notify batch: priority order + redundancy collapse.
 *
 * Presence for subsumption is evaluated on the batch as delivered (pre-drop),
 * so a restart that is itself dropped by an upgrade still covers a reload in
 * the same batch. The relative order of same-rank tasks is preserved.
 */
inline TaskBatchPlan planTaskBatch(std::vector<NotifyTask> batch)
{
    const bool hasUpgrade =
        std::any_of(batch.begin(), batch.end(),
                    [](const NotifyTask & task)
    {
        return task.type == "remote_upgrade";
    });
    const bool hasRestart =
        std::any_of(batch.begin(), batch.end(),
                    [](const NotifyTask & task)
    {
        return task.type == "agent_restart";
    });

    TaskBatchPlan plan;

    for (auto& task : batch)
    {
        const auto subsumer = taskBatchDetail::subsumerOf(task.type, hasUpgrade, hasRestart);

        if (subsumer.empty())
        {
            plan.ordered.push_back(std::move(task));
        }
        else
        {
            plan.dropped.emplace_back(std::move(task), subsumer);
        }
    }

    std::stable_sort(plan.ordered.begin(), plan.ordered.end(),
                     [](const NotifyTask & a, const NotifyTask & b)
    {
        return taskBatchDetail::rankOf(a.type) < taskBatchDetail::rankOf(b.type);
    });
    return plan;
}

#endif // _HC_TASK_BATCH_HPP
