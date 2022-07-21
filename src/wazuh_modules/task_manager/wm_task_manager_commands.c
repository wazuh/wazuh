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

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_parsing.h"
#include "defs.h"
#include "wazuhdb_op.h"

/**
 * Analyze an upgrade or upgrade_custom command. Update the tasks DB when necessary.
 * @param task Upgrade task to be processed.
 * @param command Command of the task to be executed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade(wm_task_manager_upgrade *task, int command, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_get_status command.
 * @param task Upgrade get status task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_get_status(wm_task_manager_upgrade_get_status *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_update_status command. Update the tasks DB when necessary.
 * @param task Upgrade update status task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_update_status(wm_task_manager_upgrade_update_status *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_result command.
 * @param task Upgrade result task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_result(wm_task_manager_upgrade_result *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_cancel_tasks command. Update the tasks DB when necessary.
 * @param task Upgrade cancel tasks task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_cancel_tasks(wm_task_manager_upgrade_cancel_tasks *task, int *error_code) __attribute__((nonnull));

/**
 * Send messages to Wazuh DB.
 * @param command Command to be send.
 * @param parameters cJSON with the parameters
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_send_message_to_wdb(const char *command, cJSON *parameters, int *error_code) __attribute__((nonnull));

cJSON* wm_task_manager_process_task(const wm_task_manager_task *task, int *error_code) {
    cJSON *response = NULL;

    switch (task->command) {
    case WM_TASK_UPGRADE:
    case WM_TASK_UPGRADE_CUSTOM:
        response = wm_task_manager_command_upgrade((wm_task_manager_upgrade *)task->parameters, task->command, error_code);
        break;
    case WM_TASK_UPGRADE_GET_STATUS:
        response = wm_task_manager_command_upgrade_get_status((wm_task_manager_upgrade_get_status *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_UPDATE_STATUS:
        response = wm_task_manager_command_upgrade_update_status((wm_task_manager_upgrade_update_status *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_RESULT:
        response = wm_task_manager_command_upgrade_result((wm_task_manager_upgrade_result *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_CANCEL_TASKS:
        response = wm_task_manager_command_upgrade_cancel_tasks((wm_task_manager_upgrade_cancel_tasks *)task->parameters, error_code);
        break;
    default:
        *error_code = WM_TASK_INVALID_COMMAND;
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade(wm_task_manager_upgrade *task, int command, int *error_code) {
    cJSON *response = cJSON_CreateArray();
    int agent_it = 0;
    int agent_id = 0;

    while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
        cJSON *parameters = cJSON_CreateObject();
        cJSON *wdb_response = NULL;

        cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_NODE], task->node);
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_MODULE], task->module);

        if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[command], parameters, error_code), wdb_response) {

            cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

            if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
                int task_id = OS_INVALID;

                cJSON *task_id_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_TASK_ID]);

                if (task_id_json && (task_id_json->type == cJSON_Number)) {
                    task_id = task_id_json->valueint;
                }

                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, task_id, NULL));

            } else {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(wdb_response);
                cJSON_Delete(parameters);
                cJSON_Delete(response);
                return NULL;
            }

            cJSON_Delete(wdb_response);

        } else {
            cJSON_Delete(parameters);
            cJSON_Delete(response);
            return NULL;
        }

        cJSON_Delete(parameters);
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_get_status(wm_task_manager_upgrade_get_status *task, int *error_code) {
    cJSON *response = cJSON_CreateArray();
    int agent_it = 0;
    int agent_id = 0;

    while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
        cJSON *parameters = cJSON_CreateObject();
        cJSON *wdb_response = NULL;

        cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_NODE], task->node);

        if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_UPGRADE_GET_STATUS], parameters, error_code), wdb_response) {

            cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

            if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
                char *status_result = NULL;

                cJSON *status_result_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_STATUS]);

                if (status_result_json && (status_result_json->type == cJSON_String)) {
                    status_result = status_result_json->valuestring;
                }

                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, OS_INVALID, status_result));

            } else {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(wdb_response);
                cJSON_Delete(parameters);
                cJSON_Delete(response);
                return NULL;
            }

            cJSON_Delete(wdb_response);

        } else {
            cJSON_Delete(parameters);
            cJSON_Delete(response);
            return NULL;
        }

        cJSON_Delete(parameters);
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_update_status(wm_task_manager_upgrade_update_status *task, int *error_code) {
    cJSON *response = cJSON_CreateArray();
    int agent_it = 0;
    int agent_id = 0;

    while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
        cJSON *parameters = cJSON_CreateObject();
        cJSON *wdb_response = NULL;

        cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_NODE], task->node);
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_STATUS], task->status);
        if (task->error_msg) {
            cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_ERROR_MSG], task->error_msg);
        }

        // Update upgrade task status
        if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_UPGRADE_UPDATE_STATUS], parameters, error_code), wdb_response) {

            cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

            if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, OS_INVALID, NULL));
            } else if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_NOTFOUND)) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_DATABASE_NO_TASK, agent_id, OS_INVALID, NULL));
            } else {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(wdb_response);
                cJSON_Delete(parameters);
                cJSON_Delete(response);
                return NULL;
            }

            cJSON_Delete(wdb_response);

        } else {
            cJSON_Delete(parameters);
            cJSON_Delete(response);
            return NULL;
        }

        cJSON_Delete(parameters);
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_result(wm_task_manager_upgrade_result *task, int *error_code) {
    cJSON *response = cJSON_CreateArray();
    int agent_it = 0;
    int agent_id = 0;

    while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
        cJSON *parameters = cJSON_CreateObject();
        cJSON *wdb_response = NULL;

        cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);

        // Upgrade result task
        if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_UPGRADE_RESULT], parameters, error_code), wdb_response) {

            cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

            if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
                int task_id = OS_INVALID;
                char *node_result = NULL;
                char *module_result = NULL;
                char *command_result = NULL;
                char *status = NULL;
                char *error = NULL;
                int create_time = OS_INVALID;
                int last_update_time = OS_INVALID;

                cJSON *task_id_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_TASK_ID]);
                cJSON *node_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_NODE]);
                cJSON *module_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_MODULE]);
                cJSON *command_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_COMMAND]);
                cJSON *status_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_STATUS]);
                cJSON *error_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR_MSG]);
                cJSON *create_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_CREATE_TIME]);
                cJSON *update_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_LAST_UPDATE_TIME]);

                if (task_id_json && (task_id_json->type == cJSON_Number)) {
                    task_id = task_id_json->valueint;
                }
                if (node_json && (node_json->type == cJSON_String)) {
                    node_result = node_json->valuestring;
                }
                if (module_json && (module_json->type == cJSON_String)) {
                    module_result = module_json->valuestring;
                }
                if (command_json && (command_json->type == cJSON_String)) {
                    command_result = command_json->valuestring;
                }
                if (status_json && (status_json->type == cJSON_String)) {
                    status = status_json->valuestring;
                }
                if (error_json && (error_json->type == cJSON_String)) {
                    error = error_json->valuestring;
                }
                if (create_json && (create_json->type == cJSON_Number)) {
                    create_time = create_json->valueint;
                }
                if (update_json && (update_json->type == cJSON_Number)) {
                    last_update_time = update_json->valueint;
                }

                cJSON *tmp = wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, task_id, NULL);
                wm_task_manager_parse_data_result(tmp, node_result, module_result, command_result, status, error, create_time, last_update_time, task_manager_commands_list[WM_TASK_UPGRADE_RESULT]);
                cJSON_AddItemToArray(response, tmp);

            } else if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_NOTFOUND)) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_DATABASE_NO_TASK, agent_id, OS_INVALID, NULL));
            } else {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(wdb_response);
                cJSON_Delete(parameters);
                cJSON_Delete(response);
                return NULL;
            }

            cJSON_Delete(wdb_response);

        } else {
            cJSON_Delete(parameters);
            cJSON_Delete(response);
            return NULL;
        }

        cJSON_Delete(parameters);
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_cancel_tasks(wm_task_manager_upgrade_cancel_tasks *task, int *error_code) {
    cJSON *response = NULL;
    cJSON *parameters = cJSON_CreateObject();
    cJSON *wdb_response = NULL;

    cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_NODE], task->node);

    // Cancel pending tasks for this node
    if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_UPGRADE_CANCEL_TASKS], parameters, error_code), wdb_response) {

        cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

        if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
            response = wm_task_manager_parse_data_response(WM_TASK_SUCCESS, OS_INVALID, OS_INVALID, NULL);
        } else {
            *error_code = WM_TASK_DATABASE_ERROR;
        }

        cJSON_Delete(wdb_response);
    }

    cJSON_Delete(parameters);

    return response;
}

void* wm_task_manager_clean_tasks(void *arg) {
    wm_task_manager *config = (wm_task_manager *)arg;
    time_t next_clean = time(0);
    time_t next_timeout = time(0);

    while (1) {
        time_t now = time(0);
        time_t sleep_time = 0;

        if (now >= next_timeout) {
            // Set the status of old tasks IN PROGRESS to TIMEOUT
            cJSON *parameters = cJSON_CreateObject();
            cJSON *wdb_response = NULL;
            int error_code = WM_TASK_SUCCESS;

            cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_NOW], now);
            cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_INTERVAL], config->task_timeout);

            // Set next timeout
            next_timeout = now + config->task_timeout;

            if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_SET_TIMEOUT], parameters, &error_code), wdb_response) {

                cJSON *wdb_error = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_ERROR]);

                if (wdb_error && (wdb_error->type == cJSON_Number) && (wdb_error->valueint == OS_SUCCESS)) {
                    cJSON *timeout_json = cJSON_GetObjectItem(wdb_response, task_manager_json_keys[WM_TASK_TIMESTAMP]);

                    if (timeout_json && (timeout_json->type == cJSON_Number)) {
                        // Update next timeout
                        next_timeout = timeout_json->valueint;
                    }
                }

                cJSON_Delete(wdb_response);
            }

            cJSON_Delete(parameters);
        }

        if (now >= next_clean) {
            // Delete entries older than cleanup_time
            cJSON *parameters = cJSON_CreateObject();
            cJSON *wdb_response = NULL;
            int error_code = WM_TASK_SUCCESS;

            cJSON_AddNumberToObject(parameters, task_manager_json_keys[WM_TASK_TIMESTAMP], (now - config->cleanup_time));

            // Set next clean time
            next_clean = now + WM_TASK_CLEANUP_DB_SLEEP_TIME;

            if (wdb_response = wm_task_manager_send_message_to_wdb(task_manager_commands_list[WM_TASK_DELETE_OLD], parameters, &error_code), wdb_response) {
                cJSON_Delete(wdb_response);
            }

            cJSON_Delete(parameters);
        }

        if (next_timeout < next_clean) {
            sleep_time = next_timeout;
        } else {
            sleep_time = next_clean;
        }

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
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int socket = -1;

    parameters_in_str = cJSON_PrintUnformatted(parameters);
    snprintf(wdbquery, sizeof(wdbquery), "task %s %s", command, parameters_in_str);
    os_free(parameters_in_str);

    result = wdbc_query_ex(&socket, wdbquery, wdboutput, sizeof(wdboutput));
    wdbc_close(&socket);

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

#endif
