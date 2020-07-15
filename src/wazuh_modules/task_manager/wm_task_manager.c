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
    [MODULE] = "module",
    [COMMAND] = "command",
    [AGENT_ID] = "agent",
    [TASK_ID] = "task_id",
    [ERROR] = "error",
    [ERROR_DATA] = "data"
};

static const char *modules_list[] = {
    [UPGRADE_MODULE] = "upgrade_module"
};

static const char *commands_list[] = {
    [UPGRADE] = "upgrade"
};

static const char *error_codes[] = {
    [SUCCESS] = "Success",
    [INVALID_MESSAGE] = "Invalid message",
    [DATABASE_ERROR] = "Database error",
    [UNKNOWN_ERROR] = "Unknown error"
};

size_t wm_task_manager_dispatch(const char *msg, char **response) {
    cJSON *event_array = NULL;
    cJSON *response_array = NULL;
    int task = 0;
    int tasks = 0;
    int error_code = SUCCESS;

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Incomming message: '%s'", msg);

    // Parse message
    if (event_array = wm_task_manager_parse_message(msg), !event_array) {
        *response = wm_task_manager_build_response_error(INVALID_MESSAGE);
        mtdebug1(WM_TASK_MANAGER_LOGTAG, "Response to message: '%s'", *response);
        return strlen(*response);
    }

    response_array = cJSON_CreateArray();

    tasks = cJSON_GetArraySize(event_array);

    for (task = 0; task < tasks; ++task) {
        cJSON *task_object = cJSON_GetArrayItem(event_array, task);
        char *module = cJSON_GetObjectItem(task_object, json_keys[MODULE])->valuestring;
        char *command = cJSON_GetObjectItem(task_object, json_keys[COMMAND])->valuestring;

        if (!strcmp(modules_list[UPGRADE_MODULE], module)) {

            if (!strcmp(commands_list[UPGRADE], command)) {
                cJSON *agent_json = NULL;
                int task_id = 0;

                // Detect agent
                if (agent_json = cJSON_GetObjectItem(task_object, json_keys[AGENT_ID]), !agent_json) {
                    error_code = INVALID_MESSAGE;
                    mterror(WM_TASK_MANAGER_LOGTAG, "Agent not found at index '%d'", task);
                    break;
                }

                // Insert upgrade task into DB
                if (task_id = wm_task_manager_insert_task(agent_json->valueint, module, command), task_id <= 0) {
                    error_code = DATABASE_ERROR;
                    mterror(WM_TASK_MANAGER_LOGTAG, "Database error at index '%d'", task);
                    break;
                }

                // Add upgrade task response
                cJSON_AddItemToArray(response_array, wm_task_manager_build_response_insert(agent_json->valueint, task_id));

            } else {
                error_code = INVALID_MESSAGE;
                mterror(WM_TASK_MANAGER_LOGTAG, "Invalid command '%s' at index '%d'", command, task);
                break;
            }
        } else {
            error_code = INVALID_MESSAGE;
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid module '%s' at index '%d'", module, task);
            break;
        }
    }

    if (error_code) {
        *response = wm_task_manager_build_response_error(error_code);
    } else {
        *response = cJSON_PrintUnformatted(response_array);
    }

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Response to message: '%s'", *response);

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
        mterror(WM_TASK_MANAGER_LOGTAG, "Error parsing JSON event: '%s'", msg);
        return NULL;
    }

    // Getting array size
    if (tasks = cJSON_GetArraySize(event_array), !tasks) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Array of tasks is empty.");
        cJSON_Delete(event_array);
        return NULL;
    }

    for (task = 0; task < tasks; ++task) {
        // Getting task
        task_object = cJSON_GetArrayItem(event_array, task);

        // Detect module
        if (module_json = cJSON_GetObjectItem(task_object, json_keys[MODULE]), !module_json) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Module not found at index '%d'", task);
            cJSON_Delete(event_array);
            return NULL;
        }

        // Detect command
        if (command_json = cJSON_GetObjectItem(task_object, json_keys[COMMAND]), !command_json) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Command not found at index '%d'", task);
            cJSON_Delete(event_array);
            return NULL;
        }
    }

    return event_array;
}

cJSON* wm_task_manager_build_response_insert(int agent_id, int task_id) {
    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, json_keys[ERROR], SUCCESS);
    cJSON_AddStringToObject(response_json, json_keys[ERROR_DATA], error_codes[SUCCESS]);
    cJSON_AddNumberToObject(response_json, json_keys[AGENT_ID], agent_id);
    cJSON_AddNumberToObject(response_json, json_keys[TASK_ID], task_id);

    return response_json;
}

char* wm_task_manager_build_response_error(int error_code) {
    cJSON *error_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(error_json, json_keys[ERROR], error_code);
    cJSON_AddStringToObject(error_json, json_keys[ERROR_DATA], error_codes[error_code]);

    return cJSON_PrintUnformatted(error_json);
}

int wm_task_manager_init(wm_task_manager *task_config) {
    int sock = 0;

    // Check if module is enabled
    if (!task_config->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check or create tasks DB
    if (wm_task_manager_check_db()) {
        mterror(WM_TASK_MANAGER_LOGTAG, "DB integrity is invalid. Exiting...");
        pthread_exit(NULL);
    }

    /* Set the queue */
    if (sock = OS_BindUnixDomain(DEFAULTDIR TASK_QUEUE, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Queue '%s' not accesible: '%s'. Exiting...", TASK_QUEUE, strerror(errno));
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

    mtinfo(WM_TASK_MANAGER_LOGTAG, "Module Task Manager started.");

    while (1) {
        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror(WM_TASK_MANAGER_LOGTAG, "Error in select(): '%s'. Exiting...", strerror(errno));
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
                mterror(WM_TASK_MANAGER_LOGTAG, "Error in accept(): '%s'", strerror(errno));
            }
            continue;
        }

        // Receive message from connection
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            mterror(WM_TASK_MANAGER_LOGTAG, "Response size is bigger than expected.");
            break;
        case -1:
            mterror(WM_TASK_MANAGER_LOGTAG, "Error in recv(): '%s'", strerror(errno));
            break;
        case 0:
            mtdebug1(WM_TASK_MANAGER_LOGTAG, "Empty message from local client.");
            close(peer);
            break;
        case OS_MAXLEN:
            mterror(WM_TASK_MANAGER_LOGTAG, "Received message > %i", MAX_DYN_STR);
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
    mtinfo(WM_TASK_MANAGER_LOGTAG, "Module Task Manager finished.");
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
