/* Durable task_id registry client (agentd side)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TASK_REGISTRY_CLIENT_H
#define TASK_REGISTRY_CLIENT_H

#include <stdbool.h>

/**
 * @brief Outcome of task_registry_check_and_record(): split out of a plain bool so callers
 *        can count a registry failure as a FAILURE, not silently fold it into the
 *        duplicate-discard metric -- the two are otherwise indistinguishable.
 */
typedef enum {
    TASK_REGISTRY_RESULT_NEW,       /**< The id was new and is now durably recorded: dispatch it. */
    TASK_REGISTRY_RESULT_DUPLICATE, /**< agent-info confirmed this exact id was already recorded. */
    TASK_REGISTRY_RESULT_ERROR      /**< Registry unreachable/malformed/timed out: fails closed
                                     *   (same as DUPLICATE, do not dispatch) but is a distinct,
                                     *   real failure for metrics/diagnostics purposes. */
} task_registry_result_t;

/**
 * @brief Atomically check-and-record a /control task_id against the durable
 *        registry owned by the agent-info module.
 *
 * On Linux/macOS, agent-info lives in a separate process (wazuh-modulesd),
 * so this is a local IPC round-trip over the existing wmcom request socket
 * (WM_LOCAL_SOCK, "query agent-info {...}") -- no new socket. On Windows,
 * agent-info runs in the same process as agentd, so this calls straight into
 * wm_module_query_json_ex() in-process, no socket involved.
 *
 * Fails CLOSED: any error (agent-info unreachable, malformed/missing
 * response, timeout) returns TASK_REGISTRY_RESULT_ERROR, which the caller must
 * treat as "do not dispatch" exactly like a genuine duplicate. Re-dispatching a
 * task whose durable record we could not confirm risks double-executing a
 * remote_upgrade across the restart it triggers, which is worse than
 * occasionally dropping a task that at-least-once delivery will simply
 * redeliver -- ERROR vs DUPLICATE only changes what gets counted, not the
 * dispatch decision.
 *
 * @param task_id NUL-terminated task_id, as received in a /control Notify
 *        response's tasks[] array.
 * @return TASK_REGISTRY_RESULT_NEW, _DUPLICATE, or _ERROR (also returned for a
 *         null/empty task_id).
 */
task_registry_result_t task_registry_check_and_record(const char *task_id);

#endif /* TASK_REGISTRY_CLIENT_H */
