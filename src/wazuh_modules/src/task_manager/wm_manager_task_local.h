/*
 * Wazuh Module for Task management: in-process manager task handlers.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The manager's three periodic housekeeping jobs, as manager task handlers: the agent disconnection
 * sweep, the retention deletion of long-disconnected agents, and the daily log rotation. Plus
 * size-based rotation, which is NOT a task -- see below.
 *
 * WHAT A LOCAL HANDLER OWES THE DISPATCHER, and what makes these three different from the routed
 * types:
 *
 *  - IT MUST BE IDEMPOTENT. An outcome write can fail after the work is done, leaving the row
 *    claimed for the next sweep to reclaim and re-run. There is no way to make two processes agree
 *    atomically, so every handler absorbs a repeat instead.
 *  - IT MUST BOUND ITSELF. There is no cancellation primitive in the tree: no pthread_cancel, no
 *    usable alarm -- SIGALRM is wired to a terminating handler -- so a handler that blocks forever
 *    blocks the lane forever and the watchdog can only say so. Each one below either sets socket
 *    deadlines or carries an elapsed-time budget, and agent_delete_old carries both.
 *  - IT SHARES ITS LANE. All three run on the depth-1 `local` lane, so the time one spends is
 *    latency for the others and for the size rotation the same lane performs.
 */
#ifndef WM_MANAGER_TASK_LOCAL_H
#define WM_MANAGER_TASK_LOCAL_H

#include "shared.h"
#include "wm_manager_task_registry.h"

/**
 * @brief Everything the local handlers read from configuration, resolved once at startup.
 *
 * Held module-wide rather than passed in, because wm_manager_task_handler carries no context
 * pointer: a handler is identified with its task type, and a per-type context would be a second
 * registry. Loaded before any lane thread starts and never written again.
 */
typedef struct _wm_manager_task_local_config {
    int disconnection_time; ///< <global><agents_disconnection_time>, seconds.
    int delete_old_agents;  ///< Retention window in minutes. 0 disables the retention sweep.
    int monitor_agents;     ///< 0 disables the retention sweep and silences the disconnection log.
    int rotate_log;         ///< Whether either kind of log rotation happens at all.
    int compress;           ///< Whether rotated logs are gzipped.
    int keep_log_days;      ///< How long rotated logs are kept.
    long size_rotate;       ///< Size-rotation threshold in bytes. 0 disables size rotation.
    int daily_rotations;    ///< Rotated slots per day, per file.
    int delete_old_batch;   ///< Agents examined per attempt before returning incomplete.
    int delete_old_budget;  ///< Seconds of lane occupancy per attempt.
    int wdb_timeout;        ///< Send and receive deadline on this module's own wazuh-db socket.
} wm_manager_task_local_config;

/**
 * @brief Resolve the local handlers' configuration. Call once, before any lane starts.
 *
 * Must run before the registry is built, because the registry derives each local type's watchdog
 * budget from the bounds resolved here.
 */
void wm_manager_task_local_init(void);

/**
 * @brief How long one attempt of a local task may run before the watchdog reports it.
 *
 * NOT A DEADLINE. Nothing can interrupt a local handler -- there is no cancellation primitive in the
 * tree -- so this is only the point past which a running handler is worth a log line. It exists
 * because the alternative, leaving the field at zero, makes the watchdog measure against its bare
 * margin and warn on every healthy run of all three of these types.
 *
 * Call after wm_manager_task_local_init(): the retention sweep's budget is configuration.
 *
 * @param[in] task_type Registered local task type.
 * @return Seconds, always positive, including for an unknown type.
 */
int wm_manager_task_local_watchdog_budget(const char *task_type);

/**
 * @brief The resolved configuration, for the callers that need to reason about it.
 */
const wm_manager_task_local_config* wm_manager_task_local_config_get(void);

/**
 * @brief Close whatever sockets the local handlers are holding. Call after the lanes are joined.
 */
void wm_manager_task_local_teardown(void);

/**
 * @brief Transition every agent past its keepalive deadline to `disconnected`, and log each one.
 *
 * The DB transition and the log line are one job, not two: wdb_disconnect_agents() already returns
 * the ids it just transitioned, so the set is in hand and no separate pass -- or the in-memory
 * queue one would need -- is required.
 *
 * @see wm_manager_task_handler for the parameter contract.
 */
wm_manager_task_result wm_manager_task_handler_agent_disconnect_sweep(const char *agent_id,
                                                                      const char *payload,
                                                                      char *error,
                                                                      size_t error_len);

/**
 * @brief Delete agents that have been disconnected for longer than the retention window.
 *
 * SELF-BOUNDED, by an examined-agent count and an elapsed-time budget, returning `incomplete` when
 * either is reached with agents left to examine. The time bound is the one that matters: what is
 * being protected is size-rotation latency on the shared lane, measured in seconds, while the batch
 * is counted in agents.
 *
 * @see wm_manager_task_handler for the parameter contract.
 */
wm_manager_task_result wm_manager_task_handler_agent_delete_old(const char *agent_id,
                                                                const char *payload,
                                                                char *error,
                                                                size_t error_len);

/**
 * @brief Rotate the manager log and its JSON twin into the day's archive directory.
 *
 * @see wm_manager_task_handler for the parameter contract.
 */
wm_manager_task_result wm_manager_task_handler_log_rotate_daily(const char *agent_id,
                                                                const char *payload,
                                                                char *error,
                                                                size_t error_len);

/**
 * @brief Rotate either log that has grown past `size_rotate`. A direct action, not a task.
 *
 * NOT A TASK, deliberately. Routing two w_stat() calls through insert, poll, claim, commit, execute
 * and retention would cost about 1440 rows a day for work that is idempotent, instantaneous and
 * harmless to miss -- a skipped tick just rotates a minute later.
 *
 * It runs on the local LANE thread rather than on the scheduler that signals it, because
 * w_rotate_log() with compression on gzips a file of up to the configured threshold inline, and the
 * scheduler is also the work poller and the ownership sweeper.
 */
void wm_manager_task_log_rotate_size(void);

/* The decisions, separated from the sockets and the filesystem they act on. */

/**
 * @brief Whether an agent's last keepalive is old enough for the retention sweep to delete it.
 *
 * The window is the disconnection time PLUS the retention interval: an agent is not eligible the
 * moment it is marked disconnected, but one whole retention period afterwards.
 *
 * @param[in] last_keepalive Agent's last keepalive.
 * @param[in] now Current time.
 * @param[in] disconnection_time Seconds of silence that mark an agent disconnected.
 * @param[in] delete_old_agents Retention window, in minutes.
 * @return true when the agent may be deleted.
 */
bool wm_manager_task_delete_old_expired(long long last_keepalive,
                                        long long now,
                                        int disconnection_time,
                                        int delete_old_agents);

/**
 * @brief What one agent's removal outcome means for the sweep as a whole.
 *
 * The mapping that makes the retention sweep survive a busy manager. Three of authd's refusals are
 * not failures at all: an agent that is already gone, and an agent whose deletion is already
 * journaled, both leave the world in the state the sweep wanted. The backlog refusal is the one
 * that must be retried rather than counted as done, because the agent is still there.
 *
 * @param[in] answered Whether authd answered at all.
 * @param[in] authd_error authd's error field, meaningful only when answered.
 * @param[out] error Short reason, written on any non-OK result.
 * @param[in] error_len Size of that buffer.
 * @return OK when this agent needs nothing further, RETRYABLE to try the sweep again later,
 *         TERMINAL when no retry can help.
 */
wm_manager_task_result wm_manager_task_delete_old_outcome(bool answered,
                                                          int authd_error,
                                                          char *error,
                                                          size_t error_len);

#endif
