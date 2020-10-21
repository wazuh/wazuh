/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015-2020, Wazuh Inc.
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

STATIC const char* wm_task_manager_decode_status(char *status) __attribute__((nonnull));

static const char *upgrade_statuses[] = {
    [WM_TASK_UPGRADE_IN_QUEUE]= "In queue",
    [WM_TASK_UPGRADE_UPDATING] = "Updating",
    [WM_TASK_UPGRADE_UPDATED] = "Updated",
    [WM_TASK_UPGRADE_ERROR] = "Error",
    [WM_TASK_UPGRADE_CANCELLED] = "Task cancelled since the manager was restarted",
    [WM_TASK_UPGRADE_TIMEOUT] = "Timeout reached while waiting for the response from the agent",
    [WM_TASK_UPGRADE_LEGACY] = "Legacy upgrade: check the result manually since the agent cannot report the result of the task"
};

static const char *error_codes[] = {
    [WM_TASK_SUCCESS] = "Success",
    [WM_TASK_INVALID_MESSAGE] = "Invalid message",
    [WM_TASK_INVALID_NODE] = "Invalid node",
    [WM_TASK_INVALID_MODULE] = "Invalid module",
    [WM_TASK_INVALID_COMMAND] = "Invalid command",
    [WM_TASK_INVALID_AGENT_ID] = "Invalid agent ID",
    [WM_TASK_INVALID_TASK_ID] = "Invalid task ID",
    [WM_TASK_INVALID_STATUS] = "Invalid status",
    [WM_TASK_DATABASE_NO_TASK] = "No task in DB",
    [WM_TASK_DATABASE_ERROR] = "Database error",
    [WM_TASK_UNKNOWN_ERROR] = "Unknown error"
};

cJSON* wm_task_manager_parse_message(const char *msg) {
    cJSON *response_array = NULL;
    cJSON *event_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *origin_json = NULL;
    const char *error;

    // Parsing event
    if (event_json = cJSON_ParseWithOpts(msg, &error, 0), !event_json) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_JSON_ERROR, msg);
        return NULL;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_ORIGIN]), !origin_json || (origin_json->type != cJSON_Object)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_ORIGIN], 0);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Detect command
    if (command_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_COMMAND]), !command_json || command_json->type != cJSON_String) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_COMMAND], 0);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_PARAMETERS]), !parameters_json || (parameters_json->type != cJSON_Object)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_PARAMETERS], 0);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Create response JSON array
    response_array = cJSON_CreateArray();

    cJSON *name_json = cJSON_GetObjectItem(origin_json, task_manager_json_keys[WM_TASK_NAME]);
    cJSON *module_json = cJSON_GetObjectItem(origin_json, task_manager_json_keys[WM_TASK_MODULE]);
    cJSON *agents_json = cJSON_GetObjectItem(parameters_json, task_manager_json_keys[WM_TASK_AGENTS]);
    cJSON *tasks_json = cJSON_GetObjectItem(parameters_json, task_manager_json_keys[WM_TASK_TASKS]);
    cJSON *status_json = cJSON_GetObjectItem(parameters_json, task_manager_json_keys[WM_TASK_STATUS]);
    cJSON *error_msg_json = cJSON_GetObjectItem(parameters_json, task_manager_json_keys[WM_TASK_ERROR_MSG]);

    if (agents_json && (agents_json->type == cJSON_Array)) {
        cJSON *agent_json = NULL;
        int agent_index = 0;

        while(agent_json = cJSON_GetArrayItem(agents_json, agent_index), agent_json) {

            if (agent_json->type == cJSON_Number) {
                cJSON *task = cJSON_CreateObject();

                cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_COMMAND], command_json->valuestring);
                cJSON_AddNumberToObject(task, task_manager_json_keys[WM_TASK_AGENT_ID], agent_json->valueint);
                if (name_json && (name_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_NODE], name_json->valuestring);
                }
                if (module_json && (module_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_MODULE], module_json->valuestring);
                }
                if (status_json && (status_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_STATUS], status_json->valuestring);
                }
                if (error_msg_json && (error_msg_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_ERROR_MSG], error_msg_json->valuestring);
                }

                cJSON_AddItemToArray(response_array, task);

            } else {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_UNKNOWN_VALUE_ERROR, task_manager_json_keys[WM_TASK_AGENTS], agent_index);
            }

            agent_index++;
        }

    } else if (tasks_json && (tasks_json->type == cJSON_Array)) {
        cJSON *task_json = NULL;
        int task_index = 0;

        while(task_json = cJSON_GetArrayItem(tasks_json, task_index), task_json) {

            if (task_json->type == cJSON_Number) {
                cJSON *task = cJSON_CreateObject();

                cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_COMMAND], command_json->valuestring);
                cJSON_AddNumberToObject(task, task_manager_json_keys[WM_TASK_TASK_ID], task_json->valueint);
                if (name_json && (name_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_NODE], name_json->valuestring);
                }
                if (module_json && (module_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_MODULE], module_json->valuestring);
                }
                if (status_json && (status_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_STATUS], status_json->valuestring);
                }
                if (error_msg_json && (error_msg_json->type == cJSON_String)) {
                    cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_ERROR_MSG], error_msg_json->valuestring);
                }

                cJSON_AddItemToArray(response_array, task);

            } else {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_UNKNOWN_VALUE_ERROR, task_manager_json_keys[WM_TASK_TASKS], task_index);
            }

            task_index++;
        }

    } else if (!agents_json && !tasks_json) {
        cJSON *task = cJSON_CreateObject();

        cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_COMMAND], command_json->valuestring);
        if (name_json && (name_json->type == cJSON_String)) {
            cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_NODE], name_json->valuestring);
        }
        if (module_json && (module_json->type == cJSON_String)) {
            cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_MODULE], module_json->valuestring);
        }
        if (status_json && (status_json->type == cJSON_String)) {
            cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_STATUS], status_json->valuestring);
        }
        if (error_msg_json && (error_msg_json->type == cJSON_String)) {
            cJSON_AddStringToObject(task, task_manager_json_keys[WM_TASK_ERROR_MSG], error_msg_json->valuestring);
        }

        cJSON_AddItemToArray(response_array, task);
    }

    cJSON_Delete(event_json);

    return response_array;
}

void wm_task_manager_parse_data_result(cJSON *response, const char *node, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command) {

    if (node != NULL) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_NODE], node);
    }

    if (module != NULL) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_MODULE], module);
    }

    if (command != NULL) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_COMMAND], command);
    }

    if (status != NULL) {
        if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_RESULT], request_command)) {
            cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_STATUS], wm_task_manager_decode_status(status));
        } else {
            cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_STATUS], status);
        }
    }

    if (error != NULL) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_MSG], error);
    }

    if (create_time != OS_INVALID) {
        char *timestamp = NULL;
        time_t tmp = create_time;
        timestamp = w_get_timestamp(tmp);
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_CREATE_TIME], timestamp);
        os_free(timestamp);
    }

    if (last_update_time != OS_INVALID) {
        if (last_update_time > 0) {
            char *timestamp = NULL;
            time_t tmp = last_update_time;
            timestamp = w_get_timestamp(tmp);
            cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_LAST_UPDATE_TIME], timestamp);
            os_free(timestamp);
        } else {
            cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_LAST_UPDATE_TIME], "0");
        }
    }
}

cJSON* wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char *status) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_ERROR], error_code);
    cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], error_codes[error_code]);
    if (agent_id != OS_INVALID) {
        cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);
    }
    if (task_id != OS_INVALID) {
        cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_TASK_ID], task_id);
    }
    if (status) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_STATUS], status);
    }

    return response;
}

cJSON* wm_task_manager_parse_response(int error_code, cJSON *data) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_ERROR], error_code);
    if (data && (data->type == cJSON_Array)) {
        cJSON_AddItemToObject(response, task_manager_json_keys[WM_TASK_DATA], data);
    } else {
        cJSON *data_array = cJSON_CreateArray();
        cJSON_AddItemToArray(data_array, data);
        cJSON_AddItemToObject(response, task_manager_json_keys[WM_TASK_DATA], data_array);
    }
    cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], error_codes[error_code]);

    return response;
}

STATIC const char* wm_task_manager_decode_status(char *status) {
    if (!strcmp(task_statuses[WM_TASK_PENDING], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_IN_QUEUE];
    } else if (!strcmp(task_statuses[WM_TASK_IN_PROGRESS], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_UPDATING];
    } else if (!strcmp(task_statuses[WM_TASK_DONE], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_UPDATED];
    } else if (!strcmp(task_statuses[WM_TASK_FAILED], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_ERROR];
    } else if (!strcmp(task_statuses[WM_TASK_CANCELLED], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_CANCELLED];
    } else if (!strcmp(task_statuses[WM_TASK_TIMEOUT], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_TIMEOUT];
    } else if (!strcmp(task_statuses[WM_TASK_LEGACY], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_LEGACY];
    }
    return error_codes[WM_TASK_INVALID_STATUS];
}

#endif
