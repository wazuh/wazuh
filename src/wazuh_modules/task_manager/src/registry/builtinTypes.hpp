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

#include <chrono>
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

    /*
     * HOW OFTEN A WINDOW IS POLLED, as opposed to how wide the window is. Unrelated to
     * schedule::Scheduler::Options::sweepInterval, which is how often the scheduler sweeps its own
     * stale task rows.
     *
     * Both AGENT sweeps apply an AGE ("last keepalive older than W") on a PERIOD, and until this
     * existed the period WAS the window -- so an agent crossing W just after a run waited out a
     * whole second one, putting the real transition anywhere in [W, 2W]. An operator who raises
     * agents_disconnection_time to an hour to quieten the log does not get an hour, they get one
     * to two.
     *
     * A quarter is the fraction: it costs four runs per window instead of one and bounds the
     * overshoot at 25%, which is under the granularity anyone reasons about a keepalive threshold
     * with. The bounds matter more than the fraction:
     *
     *  - the FLOOR keeps a short window from turning into a hot loop against wazuh-db; below it,
     *    the period is the window itself, which is exactly today's behaviour and no worse.
     *  - the CEILING caps the absolute lateness rather than the relative one, so a one-hour
     *    threshold overshoots by five minutes and not by fifteen.
     *
     * The two ceilings differ because the two runs cost differently. The disconnection sweep is
     * one UPDATE whose latency an operator watches in the API, so it is polled tightly. Retention
     * deletion re-reads the whole disconnected list on every run to delete agents that have
     * already been silent for hours, so polling it every five minutes would be pure load for
     * precision nobody asked for.
     */
    constexpr long SWEEP_PERIOD_DIVISOR {4};
    constexpr long MIN_SWEEP_PERIOD_SECONDS {60};
    constexpr long MAX_DISCONNECT_SWEEP_PERIOD_SECONDS {300};
    constexpr long MAX_DELETE_OLD_SWEEP_PERIOD_SECONDS {3600};

    /**
     * @brief The polling period for a sweep that applies @p window as an age.
     *
     * Pure, so every boundary is testable without a scheduler.
     *
     * @param window    The age the sweep applies. Non-positive yields zero, which the scheduler
     *                  treats as "never" -- such a schedule is disabled anyway.
     * @param maxPeriod The ceiling for this particular sweep.
     * @return A period in [1, window]: never coarser than the window, so this can only ever move
     *         the transition earlier than the behaviour it replaced.
     */
    std::chrono::seconds sweepPeriod(std::chrono::seconds window, std::chrono::seconds maxPeriod);

    /// @brief The three recurring schedules, resolved against configuration.
    std::vector<schedule::Schedule> buildBuiltinSchedules(const task_manager_config_t& config);

    /// @brief The one periodic action that is deliberately not a task row. It joins the rotation
    ///        concurrency group, which is what keeps it from overlapping the daily rotation.
    std::shared_ptr<execution::Executor::PeriodicAction>
    makeSizeRotationAction(host::IHostOps& hostOps, const handlers::LocalConfig& localConfig);
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_BUILTIN_TYPES_HPP
