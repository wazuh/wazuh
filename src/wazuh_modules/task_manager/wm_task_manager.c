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

size_t wm_task_manager_dispatch(const char *msg, char **response) {
    cJSON *event_json = NULL;

    if (event_json = wm_task_manager_parse_message(msg), !event_json) {
        *response = wm_task_manager_error_message(1);
        return strlen(*response);
    }

    *response = cJSON_PrintUnformatted(event_json);

    cJSON_Delete(event_json);

    return strlen(*response);
}

cJSON* wm_task_manager_parse_message(const char *msg) {
    cJSON *event_json = NULL;
    cJSON *agent_json = NULL;
    cJSON *module_json = NULL;
    cJSON *command_json = NULL;
    cJSON *agentid_json = NULL;
    const char *error;
    int agent = 0;
    int agents = 0;

    // Parsing event
    if (event_json = cJSON_ParseWithOpts(msg, &error, 0), !event_json) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Error parsing JSON event: '%s'", msg);
        return NULL;
    }

    // Getting array size
    if (agents = cJSON_GetArraySize(event_json), !agents) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Array of agents is empty.");
        cJSON_Delete(event_json);
        return NULL;
    }

    for (agent = 0; agent < agents; ++agent) {
        // Getting agent
        agent_json = cJSON_GetArrayItem(event_json, agent);

        // Detect module
        if (module_json = cJSON_GetObjectItem(agent_json, "module"), !module_json) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Module not found at index '%d'", agent);
            cJSON_Delete(event_json);
            return NULL;
        }

        // Detect command
        if (command_json = cJSON_GetObjectItem(agent_json, "command"), !command_json) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Command not found at index '%d'", agent);
            cJSON_Delete(event_json);
            return NULL;
        }

        // Detect agent ID
        if (agentid_json = cJSON_GetObjectItem(agent_json, "agent"), !agentid_json) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Invalid message. Agent ID not found at index '%d'", agent);
            cJSON_Delete(event_json);
            return NULL;
        }
    }

    return event_json;
}

char* wm_task_manager_error_message(int error_code) {
    cJSON *error_json = NULL;
    char *msg = NULL;

    switch (error_code) {
    case 1:
        msg = "Invalid message";
        break;
    case 2:
        msg = "Database error";
        break;
    default:
        msg = "Unknown error";
        break;
    }

    error_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(error_json, "error", error_code);
    cJSON_AddStringToObject(error_json, "message", msg);

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
