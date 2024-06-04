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
#include "wm_task_manager_tasks.h"

/**
 * Parses agents/tasks array and returns an array of agent/tasks ids
 * @param ids array of agents/tasks
 * @return pointer to array of agent/tasks ids
 * */
STATIC int* wm_task_manager_parse_ids(const cJSON* ids);

/**
 * Parses task parameters and returns an upgrade task from the information
 * Example:
 * {
 *      "node" : "node01",
 *      "module"    : "api",
 *      "agents"   : [1, 2, 3, 4],
 * }
 * @param origin JSON with the origin information
 * @param parameters JSON with the parameters
 * @return upgrade task if there is no error, NULL otherwise
 * */
STATIC wm_task_manager_upgrade* wm_task_manager_parse_upgrade_parameters(const cJSON* origin, const cJSON* parameters);

/**
 * Parses task parameters and returns an upgrade get status task from the information
 * Example:
 * {
 *      "node" : "node02",
 *      "agents"   : [5],
 * }
 * @param origin JSON with the origin information
 * @param parameters JSON with the parameters
 * @return upgrade get status task if there is no error, NULL otherwise
 * */
STATIC wm_task_manager_upgrade_get_status* wm_task_manager_parse_upgrade_get_status_parameters(const cJSON* origin, const cJSON* parameters);

/**
 * Parses task parameters and returns an upgrade update status task from the information
 * Example:
 * {
 *      "node" : "node02",
 *      "agents"   : [5],
 *      "status"   : "Failed",
 *      "error_msg"   : "SHA1 verification error"
 * }
 * @param origin JSON with the origin information
 * @param parameters JSON with the parameters
 * @return upgrade update status task if there is no error, NULL otherwise
 * */
STATIC wm_task_manager_upgrade_update_status* wm_task_manager_parse_upgrade_update_status_parameters(const cJSON* origin, const cJSON* parameters);

/**
 * Parses task parameters and returns an upgrade result task from the information
 * Example:
 * {
 *      "agents"   : [15, 33, 87]
 * }
 * @param parameters JSON with the parameters
 * @return upgrade result task if there is no error, NULL otherwise
 * */
STATIC wm_task_manager_upgrade_result* wm_task_manager_parse_upgrade_result_parameters(const cJSON* parameters);

/**
 * Parses task parameters and returns an upgrade cancel tasks task from the information
 * Example:
 * {
 *      "node"   : "node06"
 * }
 * @param origin JSON with the origin information
 * @return upgrade cancel tasks task if there is no error, NULL otherwise
 * */
STATIC wm_task_manager_upgrade_cancel_tasks* wm_task_manager_parse_upgrade_cancel_tasks_parameters(const cJSON* origin);

/**
 * Decode status to a more understandable string
 * @param status status string
 * @return status conversion
 */
STATIC const char* wm_task_manager_decode_status(char *status) __attribute__((nonnull));

static const char *upgrade_statuses[] = {
    [WM_TASK_UPGRADE_IN_QUEUE]= "In queue",
    [WM_TASK_UPGRADE_UPDATING] = "Updating",
    [WM_TASK_UPGRADE_UPDATED] = "Updated",
    [WM_TASK_UPGRADE_ERROR] = "Error",
    [WM_TASK_UPGRADE_CANCELLED] = "Task cancelled since the manager was restarted",
    [WM_TASK_UPGRADE_TIMEOUT] = "Timeout reached while waiting for the response from the agent, check the result manually on the agent for more information",
    [WM_TASK_UPGRADE_LEGACY] = "Legacy upgrade: check the result manually since the agent cannot report the result of the task"
};

static const char *error_codes[] = {
    [WM_TASK_SUCCESS] = "Success",
    [WM_TASK_INVALID_MESSAGE] = "Invalid message",
    [WM_TASK_INVALID_COMMAND] = "Invalid command",
    [WM_TASK_DATABASE_NO_TASK] = "No task in DB",
    [WM_TASK_DATABASE_ERROR] = "Database error",
    [WM_TASK_DATABASE_PARSE_ERROR] = "Parse DB response error",
    [WM_TASK_DATABASE_REQUEST_ERROR] = "Error in DB request",
    [WM_TASK_UNKNOWN_ERROR] = "Unknown error"
};

wm_task_manager_task* wm_task_manager_parse_message(const char *msg) {
    cJSON *event_json = NULL;
    cJSON *origin_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    wm_task_manager_task *task = NULL;
    const char *json_err;

    // Parsing event
    if (event_json = cJSON_ParseWithOpts(msg, &json_err, 0), !event_json) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_JSON_ERROR, msg);
        return NULL;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_ORIGIN]), !origin_json || (origin_json->type != cJSON_Object)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_ORIGIN]);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Detect command
    if (command_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_COMMAND]), !command_json || command_json->type != cJSON_String) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_COMMAND]);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(event_json, task_manager_json_keys[WM_TASK_PARAMETERS]), !parameters_json || (parameters_json->type != cJSON_Object)) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_PARAMETERS]);
        cJSON_Delete(event_json);
        return NULL;
    }

    // Create task
    task = wm_task_manager_init_task();

    if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE;
        task->parameters = wm_task_manager_parse_upgrade_parameters(origin_json, parameters_json);
    } else if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_CUSTOM], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE_CUSTOM;
        task->parameters = wm_task_manager_parse_upgrade_parameters(origin_json, parameters_json);
    } else if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_GET_STATUS], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE_GET_STATUS;
        task->parameters = wm_task_manager_parse_upgrade_get_status_parameters(origin_json, parameters_json);
    } else if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_UPDATE_STATUS], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE_UPDATE_STATUS;
        task->parameters = wm_task_manager_parse_upgrade_update_status_parameters(origin_json, parameters_json);
    } else if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_RESULT], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE_RESULT;
        task->parameters = wm_task_manager_parse_upgrade_result_parameters(parameters_json);
    } else if (!strcmp(task_manager_commands_list[WM_TASK_UPGRADE_CANCEL_TASKS], command_json->valuestring)) {
        task->command = WM_TASK_UPGRADE_CANCEL_TASKS;
        task->parameters = wm_task_manager_parse_upgrade_cancel_tasks_parameters(origin_json);
    } else {
        task->command = WM_TASK_UNKNOWN;
        cJSON_Delete(event_json);
        return task;
    }

    if (!task->parameters) {
        wm_task_manager_free_task(task);
        cJSON_Delete(event_json);
        return NULL;
    }

    cJSON_Delete(event_json);

    return task;
}

STATIC int* wm_task_manager_parse_ids(const cJSON* ids) {
    int *ids_array = NULL;
    int size = 0;
    int index = 0;

    size = cJSON_GetArraySize(ids);

    os_calloc(size + 1, sizeof(int), ids_array);
    ids_array[index] = OS_INVALID;

    while(index < size) {
        cJSON *id = cJSON_GetArrayItem(ids, index);
        if (id->type == cJSON_Number) {
            ids_array[index] = id->valueint;
            ids_array[index + 1] = OS_INVALID;
        } else {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_INVALID_ELEMENT_ERROR);
            os_free(ids_array);
            return NULL;
        }
        index++;
    }

    if (ids_array[0] == OS_INVALID) {
        os_free(ids_array);
        return NULL;
    }

    return ids_array;
}

STATIC wm_task_manager_upgrade* wm_task_manager_parse_upgrade_parameters(const cJSON* origin, const cJSON* parameters) {

    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();

    cJSON *name_json = cJSON_GetObjectItem(origin, task_manager_json_keys[WM_TASK_NAME]);
    cJSON *module_json = cJSON_GetObjectItem(origin, task_manager_json_keys[WM_TASK_MODULE]);
    cJSON *agents_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_AGENTS]);

    if (name_json && (name_json->type == cJSON_String)) {
        os_strdup(name_json->valuestring, task_parameters->node);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_NAME]);
        wm_task_manager_free_upgrade_parameters(task_parameters);
        return NULL;
    }

    if (module_json && (module_json->type == cJSON_String)) {
        os_strdup(module_json->valuestring, task_parameters->module);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_MODULE]);
        wm_task_manager_free_upgrade_parameters(task_parameters);
        return NULL;
    }

    task_parameters->agent_ids = wm_task_manager_parse_ids(agents_json);
    if (!task_parameters->agent_ids) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_AGENTS]);
        wm_task_manager_free_upgrade_parameters(task_parameters);
        return NULL;
    }

    return task_parameters;
}

STATIC wm_task_manager_upgrade_get_status* wm_task_manager_parse_upgrade_get_status_parameters(const cJSON* origin, const cJSON* parameters) {

    wm_task_manager_upgrade_get_status *task_parameters = wm_task_manager_init_upgrade_get_status_parameters();

    cJSON *name_json = cJSON_GetObjectItem(origin, task_manager_json_keys[WM_TASK_NAME]);
    cJSON *agents_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_AGENTS]);

    if (name_json && (name_json->type == cJSON_String)) {
        os_strdup(name_json->valuestring, task_parameters->node);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_NAME]);
        wm_task_manager_free_upgrade_get_status_parameters(task_parameters);
        return NULL;
    }

    task_parameters->agent_ids = wm_task_manager_parse_ids(agents_json);
    if (!task_parameters->agent_ids) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_AGENTS]);
        wm_task_manager_free_upgrade_get_status_parameters(task_parameters);
        return NULL;
    }

    return task_parameters;
}

STATIC wm_task_manager_upgrade_update_status* wm_task_manager_parse_upgrade_update_status_parameters(const cJSON* origin, const cJSON* parameters) {

    wm_task_manager_upgrade_update_status *task_parameters = wm_task_manager_init_upgrade_update_status_parameters();

    cJSON *name_json = cJSON_GetObjectItem(origin, task_manager_json_keys[WM_TASK_NAME]);
    cJSON *agents_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_AGENTS]);
    cJSON *status_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_STATUS]);
    cJSON *error_msg_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_ERROR_MSG]);

    if (name_json && (name_json->type == cJSON_String)) {
        os_strdup(name_json->valuestring, task_parameters->node);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_NAME]);
        wm_task_manager_free_upgrade_update_status_parameters(task_parameters);
        return NULL;
    }

    if (status_json && (status_json->type == cJSON_String)) {
        os_strdup(status_json->valuestring, task_parameters->status);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_STATUS]);
        wm_task_manager_free_upgrade_update_status_parameters(task_parameters);
        return NULL;
    }

    if (error_msg_json && (error_msg_json->type == cJSON_String)) {
        os_strdup(error_msg_json->valuestring, task_parameters->error_msg);
    }

    task_parameters->agent_ids = wm_task_manager_parse_ids(agents_json);
    if (!task_parameters->agent_ids) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_AGENTS]);
        wm_task_manager_free_upgrade_update_status_parameters(task_parameters);
        return NULL;
    }

    return task_parameters;
}

STATIC wm_task_manager_upgrade_result* wm_task_manager_parse_upgrade_result_parameters(const cJSON* parameters) {

    wm_task_manager_upgrade_result *task_parameters = wm_task_manager_init_upgrade_result_parameters();

    cJSON *agents_json = cJSON_GetObjectItem(parameters, task_manager_json_keys[WM_TASK_AGENTS]);

    task_parameters->agent_ids = wm_task_manager_parse_ids(agents_json);
    if (!task_parameters->agent_ids) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_AGENTS]);
        wm_task_manager_free_upgrade_result_parameters(task_parameters);
        return NULL;
    }

    return task_parameters;
}

STATIC wm_task_manager_upgrade_cancel_tasks* wm_task_manager_parse_upgrade_cancel_tasks_parameters(const cJSON* origin) {

    wm_task_manager_upgrade_cancel_tasks *task_parameters = wm_task_manager_init_upgrade_cancel_tasks_parameters();

    cJSON *name_json = cJSON_GetObjectItem(origin, task_manager_json_keys[WM_TASK_NAME]);

    if (name_json && (name_json->type == cJSON_String)) {
        os_strdup(name_json->valuestring, task_parameters->node);
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, task_manager_json_keys[WM_TASK_NAME]);
        wm_task_manager_free_upgrade_cancel_tasks_parameters(task_parameters);
        return NULL;
    }

    return task_parameters;
}

void wm_task_manager_parse_data_result(cJSON *response, const char *node, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, const char *request_command) {

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
        if (request_command && !strcmp(task_manager_commands_list[WM_TASK_UPGRADE_RESULT], request_command)) {
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
    return NULL;
}

#endif
