/*
 * Wazuh Module for Task management: recurring manager task schedules.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "config.h"
#include "global-config.h"
#include "wm_task_manager.h"
#include "wm_manager_task_schedules.h"

/* Schedule ids. These are persisted primary keys, so they are as much a wire contract as the task
 * type names are: renaming one strands its row, and the strays are not reaped, because nothing
 * walks MANAGER_TASK_SCHEDULES looking for ids this build does not know. */
#define WM_MANAGER_TASK_SCHEDULE_DISCONNECT  "agent_disconnect_sweep"
#define WM_MANAGER_TASK_SCHEDULE_DELETE_OLD  "agent_delete_old"
#define WM_MANAGER_TASK_SCHEDULE_LOG_ROTATE  "log_rotate_daily"

/* Defaults matching the sources these intervals come from, so a manager with no <global> stanza and
 * no internal options behaves exactly as monitord did with the same configuration.
 *
 * The disconnection default is monitord's own: it lives in MonitordConfig(), not in Read_Global,
 * because <global> is optional and the struct has to carry a value when the stanza is absent. */
#define WM_MANAGER_TASK_DEFAULT_DISCONNECTION_TIME 900
#define WM_MANAGER_TASK_DEFAULT_DAY_WAIT 10

/* Upper bound of monitord.day_wait, restated rather than included: MAX_DAY_WAIT lives in
 * monitord.h, which the retirement deletes, and the bound is part of the option's contract with
 * whoever has already set it. Changing it would silently reinterpret a configured value. */
#define WM_MANAGER_TASK_MAX_DAY_WAIT 600

/// Seconds in a day, the modulus of the daily cadence.
#define WM_MANAGER_TASK_DAY_SECONDS 86400

STATIC const wm_manager_task_schedule_def manager_task_schedules[] = {
    {
        /* The disconnection sweep. Master-scoped, which is a FIX rather than a port: monitord's
         * check_disconnection_trigger does not consult mond.monitor_agents -- unlike the alert and
         * deletion triggers -- and its counter increments unconditionally, so workers run this
         * sweep today despite main.c zeroing the flag on a worker to prevent exactly that. */
        .schedule_id = WM_MANAGER_TASK_SCHEDULE_DISCONNECT,
        .task_type = "agent_disconnect_sweep",
        .scope = WM_MANAGER_TASK_SCOPE_MASTER,
        .cadence = WM_MANAGER_TASK_CADENCE_INTERVAL,
    },
    {
        /* Retention deletion of long-disconnected agents. Master-scoped because it deletes from a
         * database the master owns, and disabled by default because its interval source is. */
        .schedule_id = WM_MANAGER_TASK_SCHEDULE_DELETE_OLD,
        .task_type = "agent_delete_old",
        .scope = WM_MANAGER_TASK_SCOPE_MASTER,
        .cadence = WM_MANAGER_TASK_CADENCE_INTERVAL,
    },
    {
        /* Daily log rotation. Scope ANY: every node writes its own logs, so this is local work
         * with no cluster-wide meaning, and a worker that stopped rotating would fill its disk. */
        .schedule_id = WM_MANAGER_TASK_SCHEDULE_LOG_ROTATE,
        .task_type = "log_rotate_daily",
        .scope = WM_MANAGER_TASK_SCOPE_ANY,
        .cadence = WM_MANAGER_TASK_CADENCE_DAILY,
    },
};

#define SCHEDULE_COUNT (sizeof(manager_task_schedules) / sizeof(*manager_task_schedules))

size_t wm_manager_task_schedules_count(void) {
    return SCHEDULE_COUNT;
}

const wm_manager_task_schedule_def* wm_manager_task_schedules_at(size_t index) {
    return index < SCHEDULE_COUNT ? &manager_task_schedules[index] : NULL;
}

const wm_manager_task_schedule_def* wm_manager_task_schedules_get(const char *schedule_id) {
    if (!schedule_id) {
        return NULL;
    }

    for (size_t i = 0; i < SCHEDULE_COUNT; i++) {
        if (strcmp(manager_task_schedules[i].schedule_id, schedule_id) == 0) {
            return &manager_task_schedules[i];
        }
    }

    return NULL;
}

/**
 * @brief Read `<global><agents_disconnection_time>` from ossec.conf.
 *
 * Its own read rather than a shared one: modulesd does not parse CGLOBAL anywhere else, and remoted
 * reads the same value into its own struct. The section must therefore survive monitord's removal,
 * which is why the retirement checklist keeps Read_Global.
 *
 * A parse failure keeps the default instead of exiting. monitord called merror_exit here, which was
 * proportionate for a daemon whose whole job depended on the value; in modulesd it would take down
 * every other module for a `<global>` typo.
 *
 * @return Disconnection time in seconds, always positive.
 */
STATIC int wm_manager_task_disconnection_time(void) {
    _Config global = {0};

    global.agents_disconnection_time = WM_MANAGER_TASK_DEFAULT_DISCONNECTION_TIME;

    if (ReadConfig(CGLOBAL, WAZUHCONF, &global, NULL) < 0) {
        mtwarn(WM_TASK_MANAGER_LOGTAG,
               "Cannot read the <global> configuration; the agent disconnection sweep will run every %d seconds.",
               WM_MANAGER_TASK_DEFAULT_DISCONNECTION_TIME);
        return WM_MANAGER_TASK_DEFAULT_DISCONNECTION_TIME;
    }

    // Read_Global already rejects a value below 1, leaving the struct untouched, so this covers a
    // caller mistake rather than operator input.
    return global.agents_disconnection_time > 0 ? (int)global.agents_disconnection_time
                                                : WM_MANAGER_TASK_DEFAULT_DISCONNECTION_TIME;
}

size_t wm_manager_task_schedules_load(wm_manager_task_schedule *schedules) {
    int disconnection_time = 0;
    int delete_old_agents = 0;
    int monitor_agents = 0;
    int rotate_log = 0;
    int day_wait = 0;

    if (!schedules) {
        return 0;
    }

    disconnection_time = wm_manager_task_disconnection_time();

    /* Bounds copied from MonitordConfig() rather than chosen here: an operator who has already set
     * one of these keys must get the same value out of it, and getDefine_Int_default clamps to the
     * range it is given. `delete_old_agents` and `monitor_agents` are not in internal_options.conf
     * at all -- only these calls define them -- so the defaults here are the whole contract. */
    delete_old_agents = getDefine_Int_default("monitord", "delete_old_agents", 0, 9600, 0);
    monitor_agents = getDefine_Int_default("monitord", "monitor_agents", 0, 1, 1);
    rotate_log = getDefine_Int_default("monitord", "rotate_log", 0, 1, 1);
    day_wait = getDefine_Int_default("monitord", "day_wait", 0, WM_MANAGER_TASK_MAX_DAY_WAIT, WM_MANAGER_TASK_DEFAULT_DAY_WAIT);

    for (size_t i = 0; i < SCHEDULE_COUNT; i++) {
        const wm_manager_task_schedule_def *def = &manager_task_schedules[i];

        schedules[i].def = def;
        schedules[i].interval = 0;
        schedules[i].day_wait = 0;
        schedules[i].enabled = false;

        if (strcmp(def->schedule_id, WM_MANAGER_TASK_SCHEDULE_DISCONNECT) == 0) {
            schedules[i].interval = disconnection_time;
            // Always on. There is no option that turns agent disconnection detection off: today
            // monitord marks agents disconnected regardless of monitor_agents, which only ever
            // gated the log line and the retention deletion.
            schedules[i].enabled = true;
        } else if (strcmp(def->schedule_id, WM_MANAGER_TASK_SCHEDULE_DELETE_OLD) == 0) {
            schedules[i].interval = delete_old_agents * 60;
            // Both gates, as check_deletion_trigger had them: monitor_agents = 0 disables the
            // retention deletion as well as the disconnection logging.
            schedules[i].enabled = delete_old_agents > 0 && monitor_agents != 0;
        } else if (strcmp(def->schedule_id, WM_MANAGER_TASK_SCHEDULE_LOG_ROTATE) == 0) {
            schedules[i].day_wait = day_wait;
            schedules[i].enabled = rotate_log != 0;
        }
    }

    return SCHEDULE_COUNT;
}

long long wm_manager_task_schedule_next_interval(long long previous, long long now, int interval) {
    long long next = 0;
    long long behind = 0;

    if (interval <= 0) {
        return 0;
    }

    // Never run: the first slot is one interval out. Starting at `now` instead would make every
    // restart fire every schedule, which is how a restart loop becomes a sweep loop.
    if (previous <= 0) {
        return now + interval;
    }

    if (previous > now) {
        return previous;
    }

    /* Coalescing, in one step rather than a loop: a manager down for a week owes 672 disconnect
     * slots, and walking them one at a time to arrive at the same answer would be a visible pause
     * inside the scheduler thread. */
    behind = now - previous;
    next = previous + ((behind / interval) + 1) * (long long)interval;

    return next;
}

long long wm_manager_task_schedule_next_daily(long long now, int day_wait) {
    time_t stamp = (time_t)now;
    struct tm broken = {0};
    long long offset = day_wait > 0 ? day_wait : 0;
    long long slot = 0;

    if (offset >= WM_MANAGER_TASK_DAY_SECONDS) {
        offset = WM_MANAGER_TASK_DAY_SECONDS - 1;
    }

    if (!localtime_r(&stamp, &broken)) {
        // Only reachable on a timestamp the C library cannot break down at all. One interval out is
        // the honest answer: the schedule stays alive and retries a day later.
        return now + WM_MANAGER_TASK_DAY_SECONDS;
    }

    /* mktime() over a zeroed-out clock rather than arithmetic on `now`, because a day is not always
     * 86400 seconds where a timezone observes DST: subtracting a modulus would drift the slot by an
     * hour twice a year and, worse, could place it before the previous one. */
    broken.tm_sec = 0;
    broken.tm_min = 0;
    broken.tm_hour = 0;
    broken.tm_isdst = -1;

    slot = (long long)mktime(&broken) + offset;

    if (slot > now) {
        return slot;
    }

    // Today's slot has passed, so re-break tomorrow rather than adding a day to `slot`: letting
    // mktime normalise an out-of-range tm_mday is what keeps the offset anchored to local midnight
    // across a DST transition.
    broken.tm_mday += 1;
    broken.tm_isdst = -1;

    return (long long)mktime(&broken) + offset;
}

long long wm_manager_task_schedule_next(const wm_manager_task_schedule *schedule, long long previous, long long now) {
    if (!schedule || !schedule->def) {
        return 0;
    }

    if (schedule->def->cadence == WM_MANAGER_TASK_CADENCE_DAILY) {
        // `previous` is deliberately unused: a daily slot is a property of the calendar, not of
        // when the last one ran, so there is nothing to anchor and nothing to coalesce -- several
        // missed days collapse into the next midnight by construction.
        return wm_manager_task_schedule_next_daily(now, schedule->day_wait);
    }

    return wm_manager_task_schedule_next_interval(previous, now, schedule->interval);
}

bool wm_manager_task_schedule_node_allows(wm_manager_task_node_scope scope, int worker_state) {
    if (scope == WM_MANAGER_TASK_SCOPE_ANY) {
        return true;
    }

    return worker_state == 0;
}

long long wm_manager_task_schedule_startup_next_run(const wm_manager_task_schedule *schedule,
                                                    bool had_row,
                                                    long long stored_next_run,
                                                    int stored_enabled,
                                                    long long now) {
    long long fresh = 0;

    if (!schedule || !schedule->def) {
        return 0;
    }

    fresh = wm_manager_task_schedule_next(schedule, 0, now);

    if (!had_row || stored_next_run <= 0) {
        return fresh;
    }

    // Disabled-to-enabled. The only reason ENABLED is persisted at all: the transition can straddle
    // a restart, and nothing else would make it observable.
    if (schedule->enabled && !stored_enabled) {
        return fresh;
    }

    /* An interval that SHRANK. The interval itself is not persisted -- it belongs to the code, not
     * to the row -- so it is detected by its consequence: a stored slot further out than one whole
     * interval from now cannot have been produced by the interval configured today. Without this,
     * an operator who lowers agents_disconnection_time still waits out the old, longer one.
     *
     * An interval that GREW needs no handling: the stored slot merely falls sooner than the new
     * interval would place it, so it fires once early and re-anchors on the next advance. */
    if (schedule->def->cadence == WM_MANAGER_TASK_CADENCE_INTERVAL && schedule->interval > 0 &&
        stored_next_run > now + schedule->interval) {
        return fresh;
    }

    // A daily slot is derived from the calendar on every advance, so a stored value that no longer
    // matches the configured offset is corrected the same way.
    if (schedule->def->cadence == WM_MANAGER_TASK_CADENCE_DAILY && stored_next_run > fresh) {
        return fresh;
    }

    return stored_next_run;
}
