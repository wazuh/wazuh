/*
 * Wazuh Module for Task management: manager task wazuh-db client.
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
#include "wazuhdb_op.h"
#include "wm_task_manager.h"
#include "wm_manager_task_client.h"

/// Default deadline on every call to wazuh-db, overridable through internal options.
#define WM_MANAGER_TASK_DEFAULT_WDB_TIMEOUT 10

void wm_manager_task_client_init(wm_manager_task_client *client) {
    if (!client) {
        return;
    }

    client->sock = -1;

    // Bounded, unlike the wdbc_query_ex every other caller uses. A lane's claim, re-queue and
    // outcome writes all go over this socket, so a wedged wazuh-db would hang the lane before
    // any handler runs -- and the watchdog would then report a stall with no handler to blame.
    client->timeout = getDefine_Int_default("wazuh_modules", "manager_task_wdb_timeout", 1, 600,
                                            WM_MANAGER_TASK_DEFAULT_WDB_TIMEOUT);
}

void wm_manager_task_client_close(wm_manager_task_client *client) {
    if (client) {
        wdbc_close(&client->sock);
        client->sock = -1;
    }
}

int wm_manager_task_client_call(wm_manager_task_client *client,
                                const char *command,
                                cJSON *parameters,
                                cJSON **response) {
    char *parameters_str = NULL;
    char *query = NULL;
    char *payload = NULL;
    char output[WDBOUTPUT_SIZE] = "";
    size_t query_len = 0;
    cJSON *parsed = NULL;
    cJSON *error = NULL;
    int retval = -1;

    if (response) {
        *response = NULL;
    }

    if (!client || !command) {
        cJSON_Delete(parameters);
        return -1;
    }

    // Every sub-command takes a parameters object, including those that read nothing from it, so
    // that the dispatch on the wazuh-db side stays uniform.
    if (!parameters) {
        parameters = cJSON_CreateObject();
    }

    parameters_str = cJSON_PrintUnformatted(parameters);
    cJSON_Delete(parameters);

    if (!parameters_str) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Cannot serialise parameters for '%s'.", command);
        return -1;
    }

    // Sized to the payload rather than snprintf'd into a fixed buffer: a task payload can be up
    // to 16 KB escaped, and a fixed buffer would truncate it into a query wazuh-db then rejects
    // as malformed, which reads as a protocol bug rather than an oversized payload.
    query_len = strlen("task ") + strlen(command) + 1 + strlen(parameters_str) + 1;
    os_calloc(query_len, sizeof(char), query);
    snprintf(query, query_len, "task %s %s", command, parameters_str);
    os_free(parameters_str);

    if (wdbc_query_ex_timeout(&client->sock, query, output, sizeof(output), client->timeout) != 0) {
        if (wm_shutdown_requested) {
            // Expected, not a fault: wazuh-db is a separate daemon with no ordering guarantee
            // against this one, so a manager stop routinely closes its socket while a lane is
            // mid-call. The row stays claimed and the next start's ownership sweep reclaims it,
            // which is the same recovery a crash would get -- so reporting it as an error would
            // put a red line in the log of every clean shutdown.
            mtdebug1(WM_TASK_MANAGER_LOGTAG, "Could not send '%s' to the tasks database while shutting down.",
                     command);
        } else {
            mterror(WM_TASK_MANAGER_LOGTAG, "Cannot send '%s' to the tasks database.", command);
        }

        os_free(query);

        // The connection's state is unknown after a failed or timed-out call, so it is dropped
        // rather than reused. The next call reconnects.
        wm_manager_task_client_close(client);
        return -1;
    }

    os_free(query);

    if (wdbc_parse_result(output, &payload) != WDBC_OK) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Tasks database rejected '%s': %s", command,
                payload ? payload : "no detail");
        return -1;
    }

    if (parsed = cJSON_Parse(payload), !parsed) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Cannot parse the tasks database response to '%s'.", command);
        return -1;
    }

    // The task actor answers "ok" even for a database error, carrying the outcome in this field,
    // so a caller that only checked the ok prefix would treat a failed write as a success.
    error = cJSON_GetObjectItem(parsed, "error");

    if (!error || !cJSON_IsNumber(error) || error->valueint != 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Tasks database reported an error for '%s'.", command);
        cJSON_Delete(parsed);
        return -1;
    }

    cJSON_DeleteItemFromObject(parsed, "error");

    retval = 0;

    if (response) {
        *response = parsed;
    } else {
        cJSON_Delete(parsed);
    }

    return retval;
}

int wm_manager_task_client_claim(wm_manager_task_client *client,
                                 const char *task_type,
                                 const char *owner,
                                 cJSON **task) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *claimed = NULL;

    if (!task_type || !owner || !task) {
        return -1;
    }

    *task = NULL;

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "owner", owner);
    cJSON_AddNumberToObject(parameters, "now", (double)time(NULL));

    if (wm_manager_task_client_call(client, "claim_manager_task", parameters, &response) != 0) {
        return -1;
    }

    // An empty queue is the common answer and not an error: the field is simply absent.
    if (claimed = cJSON_DetachItemFromObject(response, "task"), claimed) {
        *task = claimed;
    }

    cJSON_Delete(response);

    return 0;
}

int wm_manager_task_client_apply(wm_manager_task_client *client,
                                 const wm_manager_task_descriptor *desc,
                                 const char *task_id,
                                 const char *agent_id,
                                 const wm_manager_task_transition_t *transition,
                                 const char *last_error) {
    cJSON *parameters = NULL;

    if (!desc || !task_id || !transition) {
        return -1;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddNumberToObject(parameters, "attempts", transition->attempts);
    cJSON_AddNumberToObject(parameters, "defer_count", transition->defer_count);

    if (last_error && *last_error) {
        cJSON_AddStringToObject(parameters, "last_error", last_error);
    }

    if (transition->status) {
        cJSON_AddStringToObject(parameters, "status", transition->status);

        // The terminal write deliberately does not commit. If wazuh-db dies before it lands the
        // row stays claimed, the sweep reclaims it, and the handler -- which every manager task
        // handler is required to be -- absorbs the re-run. Committing would double the fsync
        // budget to buy nothing idempotency is not already paying for.
        return wm_manager_task_client_call(client, "set_manager_task_result", parameters, NULL);
    }

    cJSON_AddNumberToObject(parameters, "next_attempt_at", (double)transition->next_attempt_at);

    // Only a coalescing type can have had its slot taken by a newer pending row, so only it needs
    // the competing-row check. Sending the flag for every type would make the re-queue of a
    // deletion look for a competitor that cannot exist.
    if (desc->coalesce) {
        cJSON_AddBoolToObject(parameters, "coalesce", true);
        cJSON_AddStringToObject(parameters, "task_type", desc->name);

        if (agent_id) {
            cJSON_AddStringToObject(parameters, "agent_id", agent_id);
        }
    }

    return wm_manager_task_client_call(client, "requeue_manager_task", parameters, NULL);
}

int wm_manager_task_client_poll(wm_manager_task_client *client, cJSON **types) {
    cJSON *response = NULL;

    if (!types) {
        return -1;
    }

    *types = NULL;

    if (wm_manager_task_client_call(client, "poll_manager_tasks", NULL, &response) != 0) {
        return -1;
    }

    *types = cJSON_DetachItemFromObject(response, "types");

    cJSON_Delete(response);

    return *types ? 0 : -1;
}

int wm_manager_task_client_claimed(wm_manager_task_client *client,
                                   const char *owner,
                                   const char *last_task_id,
                                   cJSON **tasks) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;

    if (!tasks) {
        return -1;
    }

    *tasks = NULL;

    parameters = cJSON_CreateObject();

    // An absent owner enumerates every claimed row, whoever holds it. That is the startup form,
    // whose result set is bounded by nothing after repeated crashes, hence the paging.
    if (owner) {
        cJSON_AddStringToObject(parameters, "owner", owner);
    }

    if (last_task_id) {
        cJSON_AddStringToObject(parameters, "last_task_id", last_task_id);
    }

    if (wm_manager_task_client_call(client, "get_claimed_manager_tasks", parameters, &response) != 0) {
        return -1;
    }

    *tasks = cJSON_DetachItemFromObject(response, "tasks");

    cJSON_Delete(response);

    return *tasks ? 0 : -1;
}

int wm_manager_task_client_create(wm_manager_task_client *client,
                                  const wm_manager_task_descriptor *desc,
                                  const char *task_id,
                                  const char *agent_id,
                                  const char *payload,
                                  long long next_attempt_at,
                                  char **outcome,
                                  char **surviving_task_id) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *item = NULL;

    if (outcome) {
        *outcome = NULL;
    }

    if (surviving_task_id) {
        *surviving_task_id = NULL;
    }

    if (!desc || !task_id || !payload) {
        return -1;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "task_type", desc->name);
    cJSON_AddStringToObject(parameters, "payload", payload);
    cJSON_AddNumberToObject(parameters, "create_time", (double)time(NULL));

    if (agent_id) {
        cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    }

    // Seeded by the creator and never left to default to zero. Ordering the claim by this column
    // would otherwise put every never-attempted row ahead of every retried one, whose value is a
    // real past timestamp, starving retries under sustained admission.
    if (next_attempt_at > 0) {
        cJSON_AddNumberToObject(parameters, "next_attempt_at", (double)next_attempt_at);
    }

    // Both policies travel with the request rather than being inferred from the type, because
    // wazuh-db has no notion of which task types exist.
    if (desc->coalesce) {
        cJSON_AddBoolToObject(parameters, "coalesce", true);
    }

    if (desc->max_pending != WM_MANAGER_TASK_UNBOUNDED) {
        cJSON_AddNumberToObject(parameters, "max_pending", desc->max_pending);
    }

    if (wm_manager_task_client_call(client, "create_manager_task", parameters, &response) != 0) {
        return -1;
    }

    if (item = cJSON_GetObjectItem(response, "result"), item && cJSON_IsString(item)) {
        if (outcome) {
            os_strdup(item->valuestring, *outcome);
        }
    }

    // Always the surviving row's id, which on a coalesce or a collision is not the one that was
    // asked for. A caller that tracked its own id would be holding one with no row behind it.
    if (item = cJSON_GetObjectItem(response, "task_id"), item && cJSON_IsString(item)) {
        if (surviving_task_id) {
            os_strdup(item->valuestring, *surviving_task_id);
        }
    }

    cJSON_Delete(response);

    return 0;
}

int wm_manager_task_client_spawn(wm_manager_task_client *client,
                                 const wm_manager_task_descriptor *desc,
                                 const char *task_id,
                                 const char *schedule_id,
                                 long long scheduled_run_at,
                                 char **outcome) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *item = NULL;
    char payload[OS_SIZE_256];

    if (outcome) {
        *outcome = NULL;
    }

    if (!desc || !task_id || !schedule_id) {
        return -1;
    }

    /* The payload a schedule-spawned row carries. Small and fixed, because the consumer of these
     * types is a local handler in this same process rather than an HTTP route: there is no request
     * body to author, only the two facts a handler might want about why it is running.
     *
     * The slot is what agent_delete_old keys its resume cursor on, so it is not decoration. */
    snprintf(payload, sizeof(payload), "{\"schedule_id\":\"%s\",\"scheduled_run_at\":%lld}", schedule_id,
             scheduled_run_at);

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "task_type", desc->name);
    cJSON_AddStringToObject(parameters, "payload", payload);
    cJSON_AddNumberToObject(parameters, "create_time", (double)time(NULL));
    cJSON_AddStringToObject(parameters, "schedule_id", schedule_id);
    cJSON_AddNumberToObject(parameters, "scheduled_run_at", (double)scheduled_run_at);

    /* Eligible from its slot, not from now. They are the same thing on a punctual spawn and differ
     * after downtime, where the slot is in the past -- and the slot is the honest answer: the run
     * was due then, and dating it from the catch-up would make a late instance look like a
     * punctual one in the history the SCHEDULED_RUN_AT index exists to serve. */
    cJSON_AddNumberToObject(parameters, "next_attempt_at", (double)scheduled_run_at);

    if (wm_manager_task_client_call(client, "create_manager_task", parameters, &response) != 0) {
        return -1;
    }

    if (item = cJSON_GetObjectItem(response, "result"), item && cJSON_IsString(item)) {
        if (outcome) {
            os_strdup(item->valuestring, *outcome);
        }
    }

    cJSON_Delete(response);

    return 0;
}

int wm_manager_task_client_schedule_upsert(wm_manager_task_client *client,
                                           const char *schedule_id,
                                           long long next_run_at,
                                           bool enabled,
                                           cJSON **previous) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;

    if (previous) {
        *previous = NULL;
    }

    if (!schedule_id) {
        return -1;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "schedule_id", schedule_id);
    cJSON_AddNumberToObject(parameters, "next_run_at", (double)next_run_at);
    cJSON_AddBoolToObject(parameters, "enabled", enabled);

    if (wm_manager_task_client_call(client, "upsert_manager_task_schedule", parameters, &response) != 0) {
        return -1;
    }

    // Absent when the schedule is new, which is the distinction the caller needs: only a schedule
    // that was already there and disabled can be undergoing a disabled-to-enabled transition.
    if (previous) {
        *previous = cJSON_DetachItemFromObject(response, "previous");
    }

    cJSON_Delete(response);

    return 0;
}

int wm_manager_task_client_schedule_advance(wm_manager_task_client *client,
                                            const char *schedule_id,
                                            long long next_run_at) {
    cJSON *parameters = NULL;

    if (!schedule_id) {
        return -1;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "schedule_id", schedule_id);
    cJSON_AddNumberToObject(parameters, "next_run_at", (double)next_run_at);

    return wm_manager_task_client_call(client, "set_manager_task_schedule_next_run", parameters, NULL);
}

int wm_manager_task_client_schedule_due(wm_manager_task_client *client, long long now, cJSON **schedules) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;

    if (!schedules) {
        return -1;
    }

    *schedules = NULL;

    parameters = cJSON_CreateObject();
    cJSON_AddNumberToObject(parameters, "now", (double)now);

    if (wm_manager_task_client_call(client, "get_due_manager_task_schedules", parameters, &response) != 0) {
        return -1;
    }

    *schedules = cJSON_DetachItemFromObject(response, "schedules");

    cJSON_Delete(response);

    return *schedules ? 0 : -1;
}

int wm_manager_task_client_schedule_active(wm_manager_task_client *client, const char *schedule_id, bool *active) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    const cJSON *item = NULL;

    if (!schedule_id || !active) {
        return -1;
    }

    *active = false;

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "schedule_id", schedule_id);

    if (wm_manager_task_client_call(client, "manager_task_schedule_has_active", parameters, &response) != 0) {
        return -1;
    }

    if (item = cJSON_GetObjectItem(response, "active"), item && cJSON_IsBool(item)) {
        *active = cJSON_IsTrue(item);
    }

    cJSON_Delete(response);

    return 0;
}
