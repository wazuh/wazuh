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

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_db.h"
#include "../os_net/os_net.h"

static int wm_task_manager_init(wm_task_manager *task_config);
static void* wm_task_manager_main(wm_task_manager* task_config);    // Module main function. It won't return
static void wm_task_manager_destroy(wm_task_manager* task_config);
static cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

/* Context definition */
const wm_context WM_TASK_MANAGER_CONTEXT = {
    TASK_MANAGER_WM_NAME,
    (wm_routine)wm_task_manager_main,
    (wm_routine)(void *)wm_task_manager_destroy,
    (cJSON * (*)(const void *))wm_task_manager_dump
};

static const char *json_keys[] = {
    [WM_TASK_MODULE] = "module",
    [WM_TASK_COMMAND] = "command",
    [WM_TASK_AGENT_ID] = "agent",
    [WM_TASK_TASK_ID] = "task_id",
    [WM_TASK_STATUS] = "status",
    [WM_TASK_ERROR] = "error",
    [WM_TASK_ERROR_DATA] = "data"
};

static const char *modules_list[] = {
    [WM_TASK_UPGRADE_MODULE] = "upgrade_module"
};

static const char *commands_list[] = {
    [WM_TASK_UPGRADE] = "upgrade",
    [WM_TASK_UPGRADE_CUSTOM] = "upgrade_custom",
    [WM_TASK_UPGRADE_GET_STATUS] = "upgrade_get_status",
    [WM_TASK_UPGRADE_UPDATE_STATUS] = "upgrade_update_status"
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

size_t wm_task_manager_dispatch(const char *msg, char **response) {
    cJSON *event_array = NULL;
    cJSON *response_array = NULL;
    cJSON *task_object = NULL;
    cJSON *task_response = NULL;
    int task = 0;
    int tasks = 0;
    int error_code = WM_TASK_SUCCESS;

    mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_INCOMMING_MESSAGE, msg);

    // Parse message
    if (event_array = wm_task_manager_parse_message(msg), !event_array) {
        *response = cJSON_PrintUnformatted(wm_task_manager_build_response(WM_TASK_INVALID_MESSAGE, OS_INVALID, OS_INVALID, NULL));
        return strlen(*response);
    }

    response_array = cJSON_CreateArray();

    tasks = cJSON_GetArraySize(event_array);

    // Iterate all the tasks of the request
    for (task = 0; task < tasks; ++task) {
        // Getting task
        task_object = cJSON_GetArrayItem(event_array, task);

        // Analyze task, update tasks DB and generate JSON response
        task_response = wm_task_manager_analyze_task(task_object, &error_code);

        switch (error_code) {
        case WM_TASK_INVALID_MODULE:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_UNKNOWN_VALUE_ERROR, json_keys[WM_TASK_MODULE], task);
            break;
        case WM_TASK_INVALID_COMMAND:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_UNKNOWN_VALUE_ERROR, json_keys[WM_TASK_COMMAND], task);
            break;
        case WM_TASK_INVALID_AGENT_ID:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, json_keys[WM_TASK_AGENT_ID], task);
            break;
        case WM_TASK_INVALID_TASK_ID:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, json_keys[WM_TASK_TASK_ID], task);
            break;
        case WM_TASK_INVALID_STATUS:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, json_keys[WM_TASK_STATUS], task);
            break;
        case WM_TASK_DATABASE_NO_TASK:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_COULD_NOT_FIND_TASK, task);
            break;
        case WM_TASK_DATABASE_ERROR:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DB_ERROR, task);
            cJSON_Delete(event_array);
            cJSON_Delete(response_array);
            *response = cJSON_PrintUnformatted(wm_task_manager_build_response(WM_TASK_DATABASE_ERROR, OS_INVALID, OS_INVALID, NULL));
            return strlen(*response);
        default:
            break;
        }

        if (task_response) {
            cJSON_AddItemToArray(response_array, task_response);
        }
        error_code = WM_TASK_SUCCESS;
    }

    *response = cJSON_PrintUnformatted(response_array);

    mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_RESPONSE_MESSAGE, *response);

    cJSON_Delete(event_array);
    cJSON_Delete(response_array);

    return strlen(*response);
}

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
        if (module_json = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_MODULE]), !module_json || module_json->type != cJSON_String) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, json_keys[WM_TASK_MODULE], task);
            cJSON_Delete(event_array);
            return NULL;
        }

        // Detect command
        if (command_json = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_COMMAND]), !command_json || command_json->type != cJSON_String) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_PARSE_KEY_ERROR, json_keys[WM_TASK_COMMAND], task);
            cJSON_Delete(event_array);
            return NULL;
        }
    }

    return event_array;
}

cJSON* wm_task_manager_analyze_task(const cJSON *task_object, int *error_code) {
    cJSON *response = NULL;
    cJSON *tmp = NULL;
    int result = 0;

    char *module = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_MODULE])->valuestring;
    char *command = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_COMMAND])->valuestring;

    int agent_id = OS_INVALID;
    int task_id = OS_INVALID;
    char *status = NULL;

    if (tmp = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_AGENT_ID]), tmp && tmp->type == cJSON_Number) {
        agent_id = tmp->valueint;
    }
    if (tmp = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_TASK_ID]), tmp && tmp->type == cJSON_Number) {
        task_id = tmp->valueint;
    }
    if (tmp = cJSON_GetObjectItem(task_object, json_keys[WM_TASK_STATUS]), tmp && tmp->type == cJSON_String) {
        os_strdup(tmp->valuestring, status);
    }

    if (!strcmp(modules_list[WM_TASK_UPGRADE_MODULE], module)) {

        if (!strcmp(commands_list[WM_TASK_UPGRADE], command) || !strcmp(commands_list[WM_TASK_UPGRADE_CUSTOM], command)) {

            if (agent_id != OS_INVALID) {
                // Insert upgrade task into DB
                if (task_id = wm_task_manager_insert_task(agent_id, module, command), task_id == OS_INVALID) {
                    *error_code = WM_TASK_DATABASE_ERROR;
                } else {
                    response = wm_task_manager_build_response(WM_TASK_SUCCESS, agent_id, task_id, status);
                }
            } else {
                *error_code = WM_TASK_INVALID_AGENT_ID;
                response = wm_task_manager_build_response(WM_TASK_INVALID_AGENT_ID, agent_id, task_id, status);
            }

        } else if (!strcmp(commands_list[WM_TASK_UPGRADE_GET_STATUS], command)) {

            if (agent_id != OS_INVALID) {
                // Get upgrade task status
                if (result = wm_task_manager_get_task_status(agent_id, module, &status), result == OS_INVALID) {
                    *error_code = WM_TASK_DATABASE_ERROR;
                } else if (result) {
                    *error_code = result;
                    response = wm_task_manager_build_response(result, agent_id, task_id, status);
                } else {
                    response = wm_task_manager_build_response(WM_TASK_SUCCESS, agent_id, task_id, status);
                }
            } else {
                *error_code = WM_TASK_INVALID_AGENT_ID;
                response = wm_task_manager_build_response(WM_TASK_INVALID_AGENT_ID, agent_id, task_id, status);
            }

        } else if (!strcmp(commands_list[WM_TASK_UPGRADE_UPDATE_STATUS], command)) {

            if (agent_id != OS_INVALID) {
                // Update upgrade task status
                if (result = wm_task_manager_update_task_status(agent_id, module, status), result == OS_INVALID) {
                    *error_code = WM_TASK_DATABASE_ERROR;
                } else if (result) {
                    *error_code = result;
                    response = wm_task_manager_build_response(result, agent_id, task_id, status);
                } else {
                    response = wm_task_manager_build_response(WM_TASK_SUCCESS, agent_id, task_id, status);
                }
            } else {
                *error_code = WM_TASK_INVALID_AGENT_ID;
                response = wm_task_manager_build_response(WM_TASK_INVALID_AGENT_ID, agent_id, task_id, status);
            }

        } else {
            *error_code = WM_TASK_INVALID_COMMAND;
            response = wm_task_manager_build_response(WM_TASK_INVALID_COMMAND, agent_id, task_id, status);
        }

    } else {
        *error_code = WM_TASK_INVALID_MODULE;
        response = wm_task_manager_build_response(WM_TASK_INVALID_MODULE, agent_id, task_id, status);
    }

    os_free(status);

    return response;
}

cJSON* wm_task_manager_build_response(int error_code, int agent_id, int task_id, char *status) {
    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, json_keys[WM_TASK_ERROR], error_code);
    cJSON_AddStringToObject(response_json, json_keys[WM_TASK_ERROR_DATA], error_codes[error_code]);
    if (agent_id != OS_INVALID) {
        cJSON_AddNumberToObject(response_json, json_keys[WM_TASK_AGENT_ID], agent_id);
    }
    if (task_id != OS_INVALID) {
        cJSON_AddNumberToObject(response_json, json_keys[WM_TASK_TASK_ID], task_id);
    }
    if (status) {
        cJSON_AddStringToObject(response_json, json_keys[WM_TASK_STATUS], status);
    }

    return response_json;
}

int wm_task_manager_init(wm_task_manager *task_config) {
    int sock = 0;

    // Check if module is enabled
    if (!task_config->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DISABLED);
        pthread_exit(NULL);
    }

    // Check or create tasks DB
    if (wm_task_manager_check_db()) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_CHECK_DB_ERROR);
        pthread_exit(NULL);
    }

    /* Set the queue */
    if (sock = OS_BindUnixDomain(DEFAULTDIR TASK_QUEUE, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_CREATE_SOCK_ERROR, TASK_QUEUE, strerror(errno));
        pthread_exit(NULL);
    }

    return sock;
}

void* wm_task_manager_main(wm_task_manager* task_config) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    // Initial configuration
    sock = wm_task_manager_init(task_config);

    mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_START);

    while (1) {
        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SELECT_ERROR, strerror(errno));
                pthread_exit(NULL);
            }
            continue;
        case 0:
            continue;
        default:
            break;
        }

        // Accept incomming connection
        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_ACCEPT_ERROR, strerror(errno));
            }
            continue;
        }

        // Receive message from connection
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SOCKTERR_ERROR);
            break;
        case -1:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_RECV_ERROR, strerror(errno));
            break;
        case 0:
            mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_EMPTY_MESSAGE);
            close(peer);
            break;
        case OS_MAXLEN:
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_LENGTH_ERROR, MAX_DYN_STR);
            close(peer);
            break;
        default:
            length = wm_task_manager_dispatch(buffer, &response);
            // Send message to connection
            OS_SendSecureTCP(peer, length, response);
            os_free(response);
            close(peer);
        }
        os_free(buffer);
    }

    close(sock);
    return NULL;
}

void wm_task_manager_destroy(wm_task_manager* task_config) {
    mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_FINISH);
    os_free(task_config);
}

cJSON* wm_task_manager_dump(const wm_task_manager* task_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (task_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes"); 
    } else { 
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    cJSON_AddItemToObject(root, "task-manager", wm_info);

    return root;
}

#endif
