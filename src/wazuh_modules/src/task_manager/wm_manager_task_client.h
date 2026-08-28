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

#endif
