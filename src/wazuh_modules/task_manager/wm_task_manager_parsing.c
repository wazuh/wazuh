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
    [WM_TASK_UPGRADE_ERROR] = "Error",
    [WM_TASK_UPGRADE_UPDATING] = "Updating",
    [WM_TASK_UPGRADE_UPDATED] = "Updated",
    [WM_TASK_UPGRADE_OUTDATED] = "The agent is outdated since the task could not start",
    [WM_TASK_UPGRADE_TIMEOUT] = "Timeout reached while waiting for the response from the agent",
    [WM_TASK_UPGRADE_LEGACY] = "Legacy upgrade: check the result manually since the agent cannot report the result of the task"
};

static const char *error_codes[] = {
    [WM_TASK_SUCCESS] = "Success",
    [WM_TASK_INVALID_MESSAGE] = "Invalid message",
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
    cJSON *event_array = NULL;
    cJSON *task_object = NULL;
    cJSON *module_json = NULL;
    cJSON *command_json = NULL;
    const char *error;
    int task = 0;
    int tasks = 0;

    // Parsing event
    if (event_array = cJSON_ParseWithOpts(msg, &error, 0), !event_array) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_JSON_ERROR, msg);
        return NULL;
    }

    // Getting array size
    if (tasks = cJSON_GetArraySize(event_array), !tasks) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_EMPTY_ERROR);
        cJSON_Delete(event_array);
        return NULL;
    }

    for (task = 0; task < tasks; ++task) {
        // Getting task
        task_object = cJSON_GetArrayItem(event_array, task);

        // Detect module
        if (module_json = cJSON_GetObjectItem(task_object, task_manager_json_keys[WM_TASK_MODULE]), !module_json || module_json->type != cJSON_String) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_MODULE], task);
            cJSON_Delete(event_array);
            return NULL;
        }

        // Detect command
        if (command_json = cJSON_GetObjectItem(task_object, task_manager_json_keys[WM_TASK_COMMAND]), !command_json || command_json->type != cJSON_String) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_COMMAND], task);
            cJSON_Delete(event_array);
            return NULL;
        }
    }

    return event_array;
}

void wm_task_manager_parse_response_result(cJSON *response, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command) {

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
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_DATA], error);
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

cJSON* wm_task_manager_parse_response(int error_code, int agent_id, int task_id, char *status) {
    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, task_manager_json_keys[WM_TASK_ERROR], error_code);
    cJSON_AddStringToObject(response_json, task_manager_json_keys[WM_TASK_ERROR_DATA], error_codes[error_code]);
    if (agent_id != OS_INVALID) {
        cJSON_AddNumberToObject(response_json, task_manager_json_keys[WM_TASK_AGENT_ID], agent_id);
    }
    if (task_id != OS_INVALID) {
        cJSON_AddNumberToObject(response_json, task_manager_json_keys[WM_TASK_TASK_ID], task_id);
    }
    if (status) {
        cJSON_AddStringToObject(response_json, task_manager_json_keys[WM_TASK_STATUS], status);
    }

    return response_json;
}

STATIC const char* wm_task_manager_decode_status(char *status) {
    if (!strcmp(task_statuses[WM_TASK_DONE], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_UPDATED];
    } else if (!strcmp(task_statuses[WM_TASK_IN_PROGRESS], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_UPDATING];
    } else if (!strcmp(task_statuses[WM_TASK_FAILED], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_ERROR];
    } else if (!strcmp(task_statuses[WM_TASK_NEW], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_OUTDATED];
    } else if (!strcmp(task_statuses[WM_TASK_TIMEOUT], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_TIMEOUT];
    } else if (!strcmp(task_statuses[WM_TASK_LEGACY], status)){
        return upgrade_statuses[WM_TASK_UPGRADE_LEGACY];
    }
    return error_codes[WM_TASK_INVALID_STATUS];
}

#endif
