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

#ifndef _TASK_MANAGER_REGISTRY_BUILTIN_TYPES_HPP
#define _TASK_MANAGER_REGISTRY_BUILTIN_TYPES_HPP

#include "execution/executor.hpp"
#include "handlers/localHandlers.hpp"
#include "host/iHostOps.hpp"
#include "schedule/cadence.hpp"
#include "taskRegistry.hpp"
#include "task_manager.h"

#include <memory>
#include <vector>

namespace task_manager::registry
{
    /*
     * PERSISTED STRINGS. These names live in MANAGER_TASKS.TASK_TYPE and MANAGER_TASK_SCHEDULES.
     * Renaming one strands every existing row of that type -- unclaimable, and retired only when
     * the orphaned-type reaper next runs.
     */
    constexpr auto TYPE_AGENT_DELETE_INDEXER {"agent_delete_indexer"};
    constexpr auto TYPE_VD_SCAN {"vd_scan"};
    constexpr auto TYPE_AGENT_DISCONNECT_SWEEP {"agent_disconnect_sweep"};
    constexpr auto TYPE_AGENT_DELETE_OLD {"agent_delete_old"};
    constexpr auto TYPE_LOG_ROTATE_DAILY {"log_rotate_daily"};

    constexpr auto SCHEDULE_AGENT_DISCONNECT_SWEEP {"agent_disconnect_sweep"};
    constexpr auto SCHEDULE_AGENT_DELETE_OLD {"agent_delete_old"};
    constexpr auto SCHEDULE_LOG_ROTATE_DAILY {"log_rotate_daily"};

    /// @brief The one concurrency group with more than one member: the two log rotations must
    ///        never run at the same time, and the group is how that is expressed now that lanes
    ///        are gone.
    constexpr auto GROUP_ROTATION {"rotation"};

    /// @brief The name the scheduler signals every minute for size-triggered rotation.
    constexpr auto ACTION_LOG_ROTATE_SIZE {"log_rotate_size"};

    /// @brief Consumer routes. Both answer at COMPLETION, never at admission.
    constexpr auto ROUTE_AGENT_DELETE {"/_internal/agents/delete"};
    constexpr auto ROUTE_VD_SCAN {"/_internal/vd/scan"};

    /**
     * @brief Build the five built-in task types and their retry policy.
     *
     * @throws std::invalid_argument on any registry invariant, and on the one cross-type invariant
     *         this build asserts: the deletion deadline MUST exceed the scan deadline. A scan
     *         holding an agent parks that agent's deletion behind it in the consumer's per-agent
     *         queue, so with equal deadlines the deletion would expire while parked and be
     *         re-queued over work that was never its own fault.
     */
    TaskRegistry buildBuiltinRegistry(const task_manager_config_t& config,
                                      host::IHostOps& hostOps,
                                      const handlers::LocalConfig& localConfig);

    /// @brief The three recurring schedules, resolved against configuration.
    std::vector<schedule::Schedule> buildBuiltinSchedules(const task_manager_config_t& config);

    /// @brief The one periodic action that is deliberately not a task row. It joins the rotation
    ///        concurrency group, which is what keeps it from overlapping the daily rotation.
    std::shared_ptr<execution::Executor::PeriodicAction>
    makeSizeRotationAction(host::IHostOps& hostOps, const handlers::LocalConfig& localConfig);
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_BUILTIN_TYPES_HPP
