/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_REGISTRY_TASK_TYPE_DESCRIPTOR_HPP
#define _TASK_MANAGER_REGISTRY_TASK_TYPE_DESCRIPTOR_HPP

#include "handlers/iHandler.hpp"
#include "storage/iTaskStore.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace task_manager::registry
{
    /// @brief "Take the policy default for this field."
    constexpr int USE_DEFAULT {-1};

    /// @brief "No bound at all." Distinct from USE_DEFAULT: a type that must never give up sets
    ///        this explicitly, and it is not an operator knob.
    constexpr int UNBOUNDED {0};

    /**
     * @brief Everything the executor needs to know about one task type.
     *
     * Adding a manager task type is one of these plus a handler. It is NOT a change to the
     * executor, the scheduler, the store or the schema -- TASK_TYPE is opaque to storage.
     *
     * Note what is absent: there is no "kind" distinguishing a routed type from a local one. A
     * routed type is simply a descriptor whose handler is an HttpHandler built with a socket, a
     * path and timeouts. The retired implementation branched on that distinction in the lane
     * assignment, the claim rotation and a start-up assertion; collapsing it into the handler
     * removes all three.
     */
    struct TaskTypeDescriptor
    {
        /// @brief PERSISTED in MANAGER_TASKS.TASK_TYPE. Renaming one strands every existing row of
        ///        that type: it becomes unclaimable, and only the orphaned-type reaper will
        ///        eventually retire it.
        std::string name;

        /**
         * @brief Types sharing a group share one concurrency budget. Defaults to `name`, which
         *        gives each type its own.
         *
         * This is what replaced lanes. The single "local" lane was really enforcing one thing --
         * that daily and size-triggered log rotation never run at the same time -- and expressing
         * that as a group instead of a lane lets the disconnection sweep and the retention
         * deletion run in parallel with each other and with a rotation, which the lane forbade for
         * no reason beyond thread economy.
         */
        std::string concurrencyGroup;

        /// @brief Maximum simultaneous executions across the group.
        int maxConcurrent {1};

        /// @brief USE_DEFAULT takes the policy value; UNBOUNDED never dead-letters on attempts.
        int maxAttempts {USE_DEFAULT};
        int maxDefer {USE_DEFAULT};

        /**
         * @brief May this row ever be retired as `failed`?
         *
         * False only for work whose obligation nobody will raise again. Setting the budgets to
         * UNBOUNDED is not enough on its own: a Terminal outcome is just as final as dead_letter,
         * so a type that must never be abandoned needs both.
         *
         * Enforced in TWO places, deliberately. httpResultMapper consults it when deciding what a
         * 4xx means, which is where the distinction is most informative; and applyResult() enforces
         * it again for ANY Terminal outcome, whatever produced it, so the guarantee is a property of
         * the type rather than of the handler it happens to be wired to.
         */
        bool allowTerminalFailure {true};

        /// @brief Fold a create request into an existing pending row for the same agent.
        ///        Per-type, because two distinct deletions of one agent must never collapse.
        bool coalesceByAgent {false};

        /// @brief Admission bound on pending rows. UNBOUNDED disables it.
        int maxPending {UNBOUNDED};

        /**
         * @brief How long one attempt may take before the watchdog reports it.
         *
         * Two meanings in one field, stated here because the difference matters: for a routed type
         * libcurl ENFORCES it, and for a local type nothing does -- it is a watchdog budget only,
         * and the handler is responsible for respecting it. A local type whose budget is zero
         * would make the watchdog fire on healthy work, so the registry refuses to start with one.
         */
        std::chrono::seconds watchdogBudget {0};

        /// @brief Never null once the registry is built.
        std::shared_ptr<IHandler> handler;
    };

    /// @brief The operator-tunable defaults a descriptor can inherit.
    struct RetryPolicy
    {
        int maxAttempts {8};
        int maxDefer {48};
        std::chrono::seconds backoffBase {30};
        std::chrono::seconds backoffCap {900};
        std::chrono::seconds deferBase {5};
    };

    /// @brief What one outcome does to a row. Pure data, produced by applyResult().
    struct Transition
    {
        /// @brief Absent means "back to pending" -- retry, deferral or progress. Present means the
        ///        row is retiring, and is always one of Completed, Failed or DeadLetter.
        std::optional<TaskStatus> terminalStatus;
        int attempts {0};
        int deferCount {0};
        Timestamp nextAttemptAt {0};
    };
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_TASK_TYPE_DESCRIPTOR_HPP
