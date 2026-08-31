/*
 * Wazuh Module for Task management: manager task wazuh-db client.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * A thin, bounded client for the task actor's manager task sub-commands. Every operation goes
 * through one generic call, so adding a sub-command is a call site rather than another near
 * identical wrapper; the typed helpers below exist only where a caller needs the arguments
 * checked or the response reshaped.
 *
 * Each lane owns one of these. The socket is persistent because a lane claims, executes and
 * records in a loop, and reconnecting per operation would triple the syscalls on the hot path.
 */
#ifndef WM_MANAGER_TASK_CLIENT_H
#define WM_MANAGER_TASK_CLIENT_H

#include "shared.h"
#include "wm_manager_task_registry.h"

/**
 * @brief A bounded, reusable connection to the task actor.
 */
typedef struct _wm_manager_task_client {
    int sock;    ///< Persistent socket, -1 when disconnected.
    int timeout; ///< Send and receive deadline in seconds.
} wm_manager_task_client;

/**
 * @brief Prepare a client. Does not connect; the first call does that.
 *
 * @param[out] client Client to initialise.
 */
void wm_manager_task_client_init(wm_manager_task_client *client);

/**
 * @brief Close a client's socket if it holds one.
 *
 * @param[in,out] client Client to close.
 */
void wm_manager_task_client_close(wm_manager_task_client *client);

/**
 * @brief Send one manager task sub-command and return its response object.
 *
 * A failed call closes the socket, so the next one reconnects rather than reusing a connection
 * whose state is unknown.
 *
 * @param[in,out] client Client to send through.
 * @param[in] command Sub-command name, as registered in wazuh-db's task actor.
 * @param[in] parameters Parameters object. Always consumed, including on failure.
 * @param[out] response Response object with the error field removed, or NULL when the caller does
 *             not need it. Caller frees.
 * @return 0 on success, -1 on a transport, protocol or database error.
 */
int wm_manager_task_client_call(wm_manager_task_client *client,
                                const char *command,
                                cJSON *parameters,
                                cJSON **response);

/**
 * @brief Claim the next eligible task of one type.
 *
 * @param[in,out] client Client.
 * @param[in] task_type Type to claim.
 * @param[in] owner This lane's identity.
 * @param[out] task Claimed task, or NULL when the queue held nothing due. Caller frees.
 * @return 0 on success, including when nothing was claimed; -1 on error.
 */
int wm_manager_task_client_claim(wm_manager_task_client *client,
                                 const char *task_type,
                                 const char *owner,
                                 cJSON **task);

/**
 * @brief Write the row state a handler result implies.
 *
 * Routes to the re-queue sub-command or the terminal one according to the transition, so that
 * the choice between them is made once rather than at every call site.
 *
 * @param[in,out] client Client.
 * @param[in] desc Task type, which decides whether a competing pending row can exist.
 * @param[in] task_id Row to write.
 * @param[in] agent_id Subject agent, or NULL.
 * @param[in] transition State to write.
 * @param[in] last_error Reason to record, or NULL.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_apply(wm_manager_task_client *client,
                                 const wm_manager_task_descriptor *desc,
                                 const char *task_id,
                                 const char *agent_id,
                                 const wm_manager_task_transition_t *transition,
                                 const char *last_error);

/**
 * @brief Ask which task types have pending work, and when each next comes due.
 *
 * @param[in,out] client Client.
 * @param[out] types Array of {task_type, next_attempt_at}. Caller frees.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_poll(wm_manager_task_client *client, cJSON **types);

/**
 * @brief Fetch one page of claimed rows for the ownership sweep.
 *
 * @param[in,out] client Client.
 * @param[in] owner Restrict to one lane, or NULL for every claimed row.
 * @param[in] last_task_id Highest task id of the previous page, or NULL to start.
 * @param[out] tasks Array of claimed rows. Caller frees.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_claimed(wm_manager_task_client *client,
                                   const char *owner,
                                   const char *last_task_id,
                                   cJSON **tasks);

/**
 * @brief Create a manager task.
 *
 * @param[in,out] client Client.
 * @param[in] desc Task type, which supplies the coalescing and admission policy.
 * @param[in] task_id Identity, derived per type by the caller.
 * @param[in] agent_id Subject agent, or NULL.
 * @param[in] payload Consumer request body, verbatim.
 * @param[in] next_attempt_at When the row first becomes eligible, or 0 for its creation time.
 * @param[out] outcome Which of created, coalesced, collided or queue_full happened. May be NULL.
 * @param[out] surviving_task_id Id of the row the caller should track. Caller frees. May be NULL.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_create(wm_manager_task_client *client,
                                  const wm_manager_task_descriptor *desc,
                                  const char *task_id,
                                  const char *agent_id,
                                  const char *payload,
                                  long long next_attempt_at,
                                  char **outcome,
                                  char **surviving_task_id);

/**
 * @brief Create one instance of a schedule, stamped with the slot it belongs to.
 *
 * Separate from wm_manager_task_client_create() rather than two more parameters on it, because the
 * two creators are different shapes: a producer knows an agent and a body, a schedule knows a slot.
 * SCHEDULE_ID and SCHEDULED_RUN_AT are what make a run's history queryable per schedule and what
 * the per-schedule retention cap counts on.
 *
 * @param[in,out] client Client.
 * @param[in] desc Task type this schedule spawns.
 * @param[in] task_id Identity, derived from the schedule and its slot.
 * @param[in] schedule_id Schedule that spawned this row.
 * @param[in] scheduled_run_at Slot the row belongs to.
 * @param[out] outcome Which of created, coalesced, collided or queue_full happened. May be NULL.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_spawn(wm_manager_task_client *client,
                                 const wm_manager_task_descriptor *desc,
                                 const char *task_id,
                                 const char *schedule_id,
                                 long long scheduled_run_at,
                                 char **outcome);

/**
 * @brief Write one schedule's persisted state, reporting what was there before.
 *
 * @param[in,out] client Client.
 * @param[in] schedule_id Schedule to write.
 * @param[in] next_run_at Next run to store.
 * @param[in] enabled Whether the schedule spawns instances.
 * @param[out] previous The row as it was, or NULL when the schedule is new. Caller frees.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_schedule_upsert(wm_manager_task_client *client,
                                           const char *schedule_id,
                                           long long next_run_at,
                                           bool enabled,
                                           cJSON **previous);

/**
 * @brief Advance one schedule's next run.
 *
 * @param[in,out] client Client.
 * @param[in] schedule_id Schedule to advance.
 * @param[in] next_run_at New slot.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_schedule_advance(wm_manager_task_client *client,
                                            const char *schedule_id,
                                            long long next_run_at);

/**
 * @brief List the enabled schedules whose next run has come due.
 *
 * @param[in,out] client Client.
 * @param[in] now Current time.
 * @param[out] schedules Array of {schedule_id, next_run_at}. Caller frees.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_schedule_due(wm_manager_task_client *client, long long now, cJSON **schedules);

/**
 * @brief Whether a schedule still has a pending or claimed instance.
 *
 * @param[in,out] client Client.
 * @param[in] schedule_id Schedule to check.
 * @param[out] active Set to true when a non-terminal instance exists.
 * @return 0 on success, -1 on error.
 */
int wm_manager_task_client_schedule_active(wm_manager_task_client *client, const char *schedule_id, bool *active);

#endif
