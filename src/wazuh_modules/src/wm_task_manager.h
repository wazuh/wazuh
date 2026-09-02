/*
 * Wazuh Module for Task management
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

#define WM_TASK_MANAGER_LOGTAG ARGV0 ":task-manager"

#include "wmodules.h"

/**
 * Configuration for the task manager module.
 *
 * The four XML options come from <wodle name="task-manager"> and are parsed by
 * config/src/wmodules-task-manager.c. Everything else is an internal option, read HERE -- that is,
 * inside wm_config(), before modulesd daemonizes -- so an out-of-range value fails
 * `wazuh-modulesd -t` instead of aborting a module thread hours later.
 *
 * Zero means "no opinion, use the module's own default" for every integer. The defaults live in
 * exactly one place, the C++ module, and this struct never second-guesses them.
 */
typedef struct wm_task_manager {
    unsigned int enabled:1;

    /* <task-manager> XML options. */
    int task_ttl;
    int cleanup_interval;
    int max_payload_bytes;
    int max_tasks_per_poll;

    /* Queue mechanics. */
    int max_attempts;
    int max_defer;
    int backoff_base;
    int backoff_cap;
    int defer_base;
    int wake_backstop;
    int sweep_interval;
    int claim_grace;
    int wdb_timeout;

    /* Per-type bounds. */
    int vd_scan_timeout;
    int delete_timeout;
    int max_pending_deletes;
    int max_pending_scans;

    /* Retention. */
    int retention_days;
    int dead_letter_retention_days;
    int history_per_schedule;
    int max_rows;

    /* Recurring work. */
    int disconnection_time;
    int delete_old_agents;
    int monitor_agents;
    int disconnect_log_max;
    int rotate_log;
    int compress;
    int keep_log_days;
    int size_rotate_mb;
    int daily_rotations;
    int day_wait;
    int delete_old_batch;
    int delete_old_budget;

    /* Threading. */
    int io_threads;
    int executor_threads;
} wm_task_manager;

extern const wm_context WM_TASK_MANAGER_CONTEXT;

/**
 * @brief Create the default instance and resolve every internal option.
 *
 * Runs from wm_initialize_default_modules(), which wm_config() calls BEFORE it loads the effective
 * document -- so nothing here may read that document. The internal options can be resolved at this
 * point because they come from internal_options.conf, and resolving them here is what makes an
 * out-of-range value fail `wazuh-modulesd -t` rather than abort a module thread later.
 *
 * @param xml Unused; the manager has no XML reader for this module.
 * @param nodes Unused, for the same reason.
 * @param module Module to fill in.
 * @return 0 on success, OS_INVALID on an out-of-range internal option.
 */
int wm_task_manager_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

/**
 * @brief Reader of the `task-manager` section of the effective document (etc/wazuh-manager.conf).
 *
 * `module` must already be initialised by wm_task_manager_read(NULL, NULL, module). A NULL section
 * keeps the defaults, but `agents_disconnection_time` is still read from `global` -- the sweep
 * needs its interval whether or not `task-manager` itself is present.
 *
 * @param section The section, or NULL when the document does not define it.
 * @param module Module to fill in.
 * @return 0 on success, negative on a value the reader rejects.
 */
int wm_task_manager_read_json(const cJSON *section, wmodule *module);

#endif
