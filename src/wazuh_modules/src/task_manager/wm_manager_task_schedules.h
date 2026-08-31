/*
 * Wazuh Module for Task management: recurring manager task schedules.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The set of recurring manager tasks is fixed in code, one entry per recurring task type. Only the
 * mutable state -- NEXT_RUN_AT and ENABLED -- is persisted, in MANAGER_TASK_SCHEDULES; the task
 * type, the interval source and the node scope are compile-time properties of the entry.
 *
 * Adding a recurring task is therefore a row in the table below, a descriptor in the registry and a
 * handler. It is not a change to the spawn loop: everything the loop does with an entry -- when the
 * next slot falls, whether this node may run it, what id the instance gets -- is one of the pure
 * functions here, and none of them names a schedule.
 *
 * WHY THE INTERVALS ARE NOT NEW CONFIGURATION. Each one already has an operator-facing source that
 * predates this module, and moving them would break deployments that set them. `agents_disconnection_time`
 * is a `<global>` XML option read by remoted as well; the rest are `monitord.*` internal options.
 * The `monitord.` prefix survives the daemon: getDefine_Int splits a key at its first '.' and
 * strcmps both halves, so the prefix is a real key component rather than a label, and renaming the
 * keys would silently ignore whatever an operator has already written.
 */
#ifndef WM_MANAGER_TASK_SCHEDULES_H
#define WM_MANAGER_TASK_SCHEDULES_H

#include "shared.h"

/// Longest schedule id, which is also its wire form and its primary key.
#define WM_MANAGER_TASK_SCHEDULE_ID_LEN 64

/**
 * @brief Which nodes of a cluster may spawn a schedule's instances.
 *
 * Evaluated at spawn time only. A master that is demoted therefore leaves already-pending
 * master-scope rows behind, and its own dispatcher still executes them -- deliberately: the work
 * was already decided on, and a node that stops spawning is not a node that abandons obligations.
 */
typedef enum _wm_manager_task_node_scope {
    WM_MANAGER_TASK_SCOPE_ANY = 0, ///< Runs on every node, worker included.
    WM_MANAGER_TASK_SCOPE_MASTER   ///< Runs on the master, or on a standalone node.
} wm_manager_task_node_scope;

/**
 * @brief How a schedule's slots are spaced.
 */
typedef enum _wm_manager_task_cadence {
    WM_MANAGER_TASK_CADENCE_INTERVAL = 0, ///< Every `interval` seconds from the previous slot.
    WM_MANAGER_TASK_CADENCE_DAILY         ///< Once a day, at local midnight plus an offset.
} wm_manager_task_cadence;

/**
 * @brief One built-in schedule: its identity and the properties that cannot change at runtime.
 */
typedef struct _wm_manager_task_schedule_def {
    const char *schedule_id; ///< Primary key in MANAGER_TASK_SCHEDULES, and the log line's subject.
    const char *task_type;   ///< Registered task type whose rows this schedule spawns.
    wm_manager_task_node_scope scope;
    wm_manager_task_cadence cadence;
} wm_manager_task_schedule_def;

/**
 * @brief A built-in schedule plus the configuration resolved for it at startup.
 */
typedef struct _wm_manager_task_schedule {
    const wm_manager_task_schedule_def *def;
    int interval;  ///< Seconds between slots. Unused, and 0, for a daily schedule.
    int day_wait;  ///< Seconds after local midnight for a daily schedule. Unused otherwise.
    bool enabled;  ///< Whether this node should spawn instances at all.
} wm_manager_task_schedule;

/**
 * @brief Number of built-in schedules.
 */
size_t wm_manager_task_schedules_count(void);

/**
 * @brief Iterate the built-in schedules.
 *
 * @param[in] index Position, from zero.
 * @return The definition, or NULL once the end is reached.
 */
const wm_manager_task_schedule_def* wm_manager_task_schedules_at(size_t index);

/**
 * @brief Look up a built-in schedule by id.
 *
 * @param[in] schedule_id Schedule id.
 * @return The definition, or NULL when this build does not know it.
 */
const wm_manager_task_schedule_def* wm_manager_task_schedules_get(const char *schedule_id);

/**
 * @brief Resolve every built-in schedule's interval and enablement from configuration.
 *
 * Reads `<global><agents_disconnection_time>` and the `monitord.*` internal options. A schedule
 * whose interval source says zero comes back disabled, which is how `delete_old_agents` ships off.
 *
 * @param[out] schedules Array of at least wm_manager_task_schedules_count() entries.
 * @return Number of entries filled.
 */
size_t wm_manager_task_schedules_load(wm_manager_task_schedule *schedules);

/**
 * @brief The first slot of a fixed-interval schedule at or after a starting point, skipping past.
 *
 * MISSED RUNS COALESCE. After downtime spanning several slots the caller wants one instance and a
 * next slot in the future, not one instance per slot missed: a manager down for a day would
 * otherwise wake up owing ninety-six disconnect sweeps, all of which the first one subsumes. So
 * this advances by whole intervals from `previous` until it is strictly ahead of `now`, and the
 * caller spawns exactly one instance for the slot it was already due at.
 *
 * Anchoring on `previous` rather than on `now` is what keeps the cadence stable: a manager
 * restarted every ten minutes would otherwise never reach a fifteen minute slot.
 *
 * @param[in] previous The slot the schedule was last due at, or 0 when it has never run.
 * @param[in] now Current time.
 * @param[in] interval Seconds between slots. Must be positive.
 * @return The next slot strictly after now, or 0 on a bad interval.
 */
long long wm_manager_task_schedule_next_interval(long long previous, long long now, int interval);

/**
 * @brief The next daily slot strictly after a given time.
 *
 * The slot is local midnight plus `day_wait` seconds, in the manager's own timezone, because that
 * is what the option meant when monitord slept for it. Local time is deliberate rather than
 * incidental: an operator who set a rotation offset meant their own night, and a DST shift moving
 * one slot by an hour is the correct reading of "just after midnight".
 *
 * @param[in] now Current time.
 * @param[in] day_wait Seconds after local midnight. Clamped to a day.
 * @return The next slot, strictly after now.
 */
long long wm_manager_task_schedule_next_daily(long long now, int day_wait);

/**
 * @brief The next slot of a schedule, whichever cadence it has.
 *
 * @param[in] schedule Schedule, with its configuration resolved.
 * @param[in] previous The slot it was last due at, or 0 when it has never run.
 * @param[in] now Current time.
 * @return The next slot strictly after now, or 0 when the schedule cannot be scheduled.
 */
long long wm_manager_task_schedule_next(const wm_manager_task_schedule *schedule, long long previous, long long now);

/**
 * @brief Whether a schedule of a given scope may spawn on this node.
 *
 * TREATS "UNKNOWN" AS "NOT THE MASTER", explicitly. w_is_worker() returns OS_INVALID when
 * ossec.conf fails to parse, and monitord's switch over the same call has no default branch -- so a
 * broken cluster stanza silently behaves as a master there today, which on a real worker means two
 * nodes running the same sweep. Refusing to spawn is the safe reading: the master's own schedule
 * still fires, and a node whose configuration cannot be read is not a node to hand cluster-wide
 * work to.
 *
 * @param[in] scope Schedule's node scope.
 * @param[in] worker_state Return of w_is_worker(): 0 master, 1 worker, anything else unknown.
 * @return true when this node may spawn.
 */
bool wm_manager_task_schedule_node_allows(wm_manager_task_node_scope scope, int worker_state);

/**
 * @brief The next run to persist for a schedule whose configuration has just been read.
 *
 * Startup and re-enablement policy in one pure function, so that the three cases it distinguishes
 * are testable without a database:
 *
 *  - A schedule with no persisted row, or one that was disabled and is now enabled, gets
 *    `now + interval`. DISABLED TIME IS NOT DOWNTIME: carrying a week-old NEXT_RUN_AT across a
 *    re-enablement would make missed-run coalescing see an overdue slot and fire at once, and for
 *    `agent_delete_old` -- destructive, and off by default -- an operator flipping the switch and
 *    getting an immediate sweep is a surprise worth not shipping.
 *  - A schedule whose persisted next run no longer fits its configured interval, because the
 *    interval was changed, is recomputed the same way.
 *  - Anything else keeps its persisted value, so an enabled schedule's cadence survives a restart
 *    and a restart cannot become a way to skip a slot.
 *
 * @param[in] schedule Schedule, with its configuration resolved.
 * @param[in] had_row Whether MANAGER_TASK_SCHEDULES already held this schedule.
 * @param[in] stored_next_run Persisted NEXT_RUN_AT, meaningful only when had_row.
 * @param[in] stored_enabled Persisted ENABLED, meaningful only when had_row.
 * @param[in] now Current time.
 * @return NEXT_RUN_AT to write.
 */
long long wm_manager_task_schedule_startup_next_run(const wm_manager_task_schedule *schedule,
                                                    bool had_row,
                                                    long long stored_next_run,
                                                    int stored_enabled,
                                                    long long now);

#endif
