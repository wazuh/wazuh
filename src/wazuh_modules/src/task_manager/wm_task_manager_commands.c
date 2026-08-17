/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "defs.h"
#include "wazuhdb_op.h"
#include "wm_task_manager_tasks.h"

// External references from wm_task_manager.c
extern const char *task_type_names[];

/**
 * Send messages to Wazuh DB.
 * @param command Command to be send.
 * @param parameters cJSON with the parameters
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_send_message_to_wdb(const char *command, cJSON *parameters, int *error_code) __attribute__((nonnull));

void* wm_task_manager_clean_tasks(void *arg) {
    wm_task_manager *config = (wm_task_manager *)arg;
    time_t next_cleanup = time(0);
    time_t next_vacuum = time(0) + 86400;

    int cleanup_interval = (config->cleanup_interval > 0) ? config->cleanup_interval : WM_TASK_DEFAULT_CLEANUP_INTERVAL;
    int task_ttl = (config->task_ttl > 0) ? config->task_ttl : WM_TASK_DEFAULT_TTL;

    while (1) {
        time_t now = time(0);
        time_t sleep_time = 0;

        if (now >= next_cleanup) {
            cJSON *parameters = cJSON_CreateObject();
            cJSON *wdb_response = NULL;
            int error_code = WM_TASK_SUCCESS;

            cJSON_AddNumberToObject(parameters, "ttl", task_ttl);

            if (wdb_response = wm_task_manager_send_message_to_wdb("cleanup_expired", parameters, &error_code), wdb_response) {
                cJSON_Delete(wdb_response);
            }

            cJSON_Delete(parameters);

            parameters = cJSON_CreateObject();
            cJSON_AddNumberToObject(parameters, "timestamp", (now - 86400));

            if (wdb_response = wm_task_manager_send_message_to_wdb("delete_old", parameters, &error_code), wdb_response) {
                cJSON_Delete(wdb_response);
            }

            cJSON_Delete(parameters);

            next_cleanup = now + cleanup_interval;

            mtdebug2(WM_TASK_MANAGER_LOGTAG, "Task cleanup completed (TTL: %d seconds, interval: %d seconds)",
                     task_ttl, cleanup_interval);
        }

        if (now >= next_vacuum) {
            char response[OS_MAXSTR + 1] = "";
            int socket = -1;
            int result = wdbc_query_ex(&socket, "task sql VACUUM;", response, sizeof(response));
            wdbc_close(&socket);

            if (result == OS_SUCCESS) {
                mtdebug1(WM_TASK_MANAGER_LOGTAG, "Task database VACUUM completed successfully");
            } else {
                mterror(WM_TASK_MANAGER_LOGTAG, "Task database VACUUM failed: %s",
                        response[0] ? response : "no response");
            }

            next_vacuum = now + 86400;
        }

        sleep_time = (next_cleanup < next_vacuum) ? next_cleanup : next_vacuum;

        w_sleep_until(sleep_time);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    return NULL;
}

STATIC cJSON* wm_task_manager_send_message_to_wdb(const char *command, cJSON *parameters, int *error_code) {
    cJSON *response = NULL;
    const char *json_err;
    int result = 0;
    char *parameters_in_str = NULL;
    char *wdbquery = NULL;
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int socket = -1;

    parameters_in_str = cJSON_PrintUnformatted(parameters);

    // Size the query buffer to fit the parameters instead of a fixed size,
    // otherwise large payloads (e.g. Active Response) get silently truncated by snprintf.
    size_t wdbquery_size = strlen("task ") + strlen(command) + strlen(" ") + strlen(parameters_in_str) + 1;
    os_calloc(wdbquery_size, sizeof(char), wdbquery);
    snprintf(wdbquery, wdbquery_size, "task %s %s", command, parameters_in_str);
    os_free(parameters_in_str);

    result = wdbc_query_ex(&socket, wdbquery, wdboutput, sizeof(wdboutput));
    wdbc_close(&socket);
    os_free(wdbquery);

    if (result == OS_SUCCESS) {
        if (WDBC_OK == wdbc_parse_result(wdboutput, &payload)) {
            if (response = cJSON_ParseWithOpts(payload, &json_err, 0), !response) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_JSON_ERROR, payload);
                *error_code = WM_TASK_DATABASE_PARSE_ERROR;
            }
        } else {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_TASKS_DB_ERROR_IN_QUERY, payload);
            *error_code = WM_TASK_DATABASE_REQUEST_ERROR;
        }
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_TASKS_DB_ERROR_EXECUTE, WDB_TASK_DIR, WDB_TASK_NAME);
        *error_code = WM_TASK_DATABASE_ERROR;
    }

    return response;
}

// Create a new generic task
char* wm_task_manager_create_task(
    const char *agent_id,
    wm_task_type task_type,
    const char *payload_json,
    const char *source_id,
    time_t create_time,
    int max_payload_bytes
) {
    char *task_id = NULL;
    int error_code = WM_TASK_SUCCESS;

    // Validate payload size
    int max_size = (max_payload_bytes > 0) ? max_payload_bytes : WM_TASK_DEFAULT_MAX_PAYLOAD_BYTES;
    size_t payload_len = strlen(payload_json);
    if (payload_len > (size_t)max_size) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Task payload too large: %zu bytes (max: %d)",
                payload_len, max_size);
        return NULL;
    }

    // Validate JSON format
    cJSON *payload_test = cJSON_Parse(payload_json);
    if (!payload_test) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Invalid JSON payload");
        return NULL;
    }
    cJSON_Delete(payload_test);

    // Generate deterministic task ID
    task_id = wm_task_manager_generate_task_id(source_id, agent_id,
                                                task_type_names[task_type],
                                                create_time);
    if (!task_id) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to generate task ID");
        return NULL;
    }

    // Store in database using centralized function
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "task_id", task_id);
    cJSON_AddStringToObject(params, "agent_id", agent_id);
    cJSON_AddStringToObject(params, "task_type", task_type_names[task_type]);
    cJSON_AddStringToObject(params, "payload", payload_json);

    cJSON *response = wm_task_manager_send_message_to_wdb("create", params, &error_code);

    cJSON_Delete(params);

    if (!response || error_code != WM_TASK_SUCCESS) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to create task in database");
        if (response) {
            cJSON_Delete(response);
        }
        os_free(task_id);
        return NULL;
    }

    cJSON_Delete(response);

    // Invalidate cache for this agent
    wm_task_cache_invalidate(agent_id);

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Created task %s for agent %s (type: %s)",
             task_id, agent_id, task_type_names[task_type]);

    return task_id;
}

// Get pending tasks for an agent
cJSON* wm_task_manager_get_pending_tasks(const char *agent_id, int max_tasks) {
    cJSON *tasks = NULL;
    int error_code = WM_TASK_SUCCESS;

    // Use default if not specified
    int limit = (max_tasks > 0) ? max_tasks : WM_TASK_DEFAULT_MAX_TASKS_PER_POLL;

    // Check cache first (only caches "no pending tasks" state)
    tasks = wm_task_cache_get(agent_id);
    if (tasks) {
        mtdebug2(WM_TASK_MANAGER_LOGTAG, "Cache hit for agent %s (no pending tasks)", agent_id);
        return tasks;
    }

    mtdebug2(WM_TASK_MANAGER_LOGTAG, "Cache miss for agent %s, querying database", agent_id);

    // Query database using centralized function
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "agent_id", agent_id);
    cJSON_AddNumberToObject(params, "max_tasks", limit);

    cJSON *response = wm_task_manager_send_message_to_wdb("get_pending", params, &error_code);

    cJSON_Delete(params);

    if (!response || error_code != WM_TASK_SUCCESS) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to get pending tasks from database");
        if (response) {
            cJSON_Delete(response);
        }
        return cJSON_CreateArray();
    }

    cJSON *tasks_json = cJSON_GetObjectItem(response, "tasks");
    if (!tasks_json || !cJSON_IsArray(tasks_json)) {
        cJSON_Delete(response);
        return cJSON_CreateArray();
    }

    // Duplicate tasks array
    tasks = cJSON_Duplicate(tasks_json, 1);
    int task_count = cJSON_GetArraySize(tasks);

    // If there are tasks, mark them as delivered
    // IMPORTANT: Do NOT cache tasks - they should only be delivered once
    if (task_count > 0) {
        cJSON *task = NULL;
        time_t delivery_time = time(NULL);

        cJSON_ArrayForEach(task, tasks) {
            cJSON *task_id_json = cJSON_GetObjectItem(task, "task_id");
            if (task_id_json && cJSON_IsString(task_id_json)) {
                cJSON *mark_params = cJSON_CreateObject();
                cJSON_AddStringToObject(mark_params, "task_id", task_id_json->valuestring);
                cJSON_AddNumberToObject(mark_params, "delivery_time", delivery_time);

                int mark_error = WM_TASK_SUCCESS;
                cJSON *mark_response = wm_task_manager_send_message_to_wdb("mark_delivered", mark_params, &mark_error);

                cJSON_Delete(mark_params);
                if (mark_response) {
                    cJSON_Delete(mark_response);
                }
            }
        }

        mtdebug1(WM_TASK_MANAGER_LOGTAG, "Retrieved %d pending tasks for agent %s",
                 task_count, agent_id);
    } else {
        // No tasks - cache this "empty" state to reduce DB queries
        wm_task_cache_set(agent_id, tasks);
        mtdebug2(WM_TASK_MANAGER_LOGTAG, "No pending tasks for agent %s, cached empty state", agent_id);
    }

    cJSON_Delete(response);

    return tasks;
}
