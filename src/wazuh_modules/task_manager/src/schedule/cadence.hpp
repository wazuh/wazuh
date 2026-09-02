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

#ifndef _TASK_MANAGER_SCHEDULE_CADENCE_HPP
#define _TASK_MANAGER_SCHEDULE_CADENCE_HPP

#include "model/task.hpp"

#include <chrono>
#include <string>

namespace task_manager::schedule
{
    constexpr Timestamp DAY_SECONDS {86400};

    enum class NodeScope
    {
        Any,   ///< Runs on every node.
        Master ///< Runs only on the master.
    };

    enum class Cadence
    {
        Interval, ///< Every N seconds.
        Daily     ///< Once a day, at a local-time offset past midnight.
    };

    /// @brief The immutable half of a schedule: code constants, never persisted.
    struct ScheduleDefinition
    {
        /// @brief PERSISTED as MANAGER_TASK_SCHEDULES.SCHEDULE_ID and on every spawned row.
        std::string id;
        /// @brief The manager task type each run spawns.
        std::string taskType;
        NodeScope scope {NodeScope::Any};
        Cadence cadence {Cadence::Interval};
    };

    /// @brief A definition plus the configured, mutable half.
    struct Schedule
    {
        ScheduleDefinition definition;
        std::chrono::seconds interval {0};
        std::chrono::seconds dayWait {0};
        bool enabled {false};
    };

    /**
     * @brief The next slot for an interval schedule.
     *
     * Missed runs COALESCE: after downtime spanning several slots, one run is owed, not one per
     * slot. It is computed in a single step rather than by walking -- a manager down for a week
     * owes 672 disconnection slots, and stepping to the same answer would be a visible pause
     * inside the scheduler thread.
     *
     * A schedule that has never run gets its first slot one interval out, not `now`. Starting at
     * `now` is how a restart loop becomes a sweep loop.
     */
    Timestamp nextIntervalRun(Timestamp previous, Timestamp now, std::chrono::seconds interval);

    /**
     * @brief The next daily slot: local midnight plus `dayWait`.
     *
     * Local time, and computed by breaking the clock down and re-composing it with mktime() rather
     * than by arithmetic on `now`. A day is not always 86400 seconds where a timezone observes
     * DST, so subtracting a modulus would drift the slot by an hour twice a year and could place
     * it BEFORE the previous one.
     */
    Timestamp nextDailyRun(Timestamp now, std::chrono::seconds dayWait);

    Timestamp nextRun(const Schedule& schedule, Timestamp previous, Timestamp now);

    /**
     * @brief The slot to store at startup, reconciling configuration against what was persisted.
     *
     * @param hadRow        Whether a row existed for this schedule.
     * @param storedNextRun The persisted slot.
     * @param storedEnabled The persisted ENABLED, which is the ONLY reason that column exists: a
     *                      disabled-to-enabled transition can straddle a restart, and nothing else
     *                      would make it observable. Re-enabling recomputes the slot, because
     *                      otherwise a schedule switched back on after a week carries a week-old
     *                      value, missed-run coalescing sees an overdue slot, and it fires
     *                      immediately -- for a destructive, disabled-by-default retention sweep,
     *                      an operator flipping the switch and getting an instant purge is a
     *                      surprise worth not shipping. Disabled time is not downtime.
     */
    Timestamp startupNextRun(const Schedule& schedule,
                             bool hadRow,
                             Timestamp storedNextRun,
                             bool storedEnabled,
                             Timestamp now);

    /**
     * @brief May this node run a schedule of this scope?
     *
     * @param workerState 1 worker, 0 master, -1 unknown.
     *
     * "Unknown" is treated as NOT master, explicitly. The retired monitord fell through to master
     * when the cluster configuration failed to parse, which is why a broken config silently
     * behaved as a master there.
     */
    bool nodeAllows(NodeScope scope, int workerState);
} // namespace task_manager::schedule

#endif // _TASK_MANAGER_SCHEDULE_CADENCE_HPP
