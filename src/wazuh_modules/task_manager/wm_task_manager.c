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

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_parsing.h"
#include "wm_task_manager_tasks.h"
#include "../os_net/os_net.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC

/* Replace pthread_exit with mock_assert, we do this to run some death tests on a very precarious way */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#define pthread_exit(x) mock_assert(0, #x, __FILE__, __LINE__)
#else
#define STATIC static
#endif


STATIC int wm_task_manager_init(wm_task_manager *task_config) __attribute__((nonnull));
#ifdef WIN32
STATIC DWORD WINAPI wm_task_manager_main(void *arg);
#else
STATIC void* wm_task_manager_main(wm_task_manager* task_config);    // Module main function. It won't return
#endif
STATIC void wm_task_manager_destroy(wm_task_manager* task_config);
STATIC cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

/* Context definition */
const wm_context WM_TASK_MANAGER_CONTEXT = {
    .name = TASK_MANAGER_WM_NAME,
    .start = (wm_routine)wm_task_manager_main,
    .destroy = (void (*)(void *))wm_task_manager_destroy,
    .dump = (cJSON * (*)(const void *))wm_task_manager_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

size_t wm_task_manager_dispatch(const char *msg, char **response) {
    wm_task_manager_task *task = NULL;
    cJSON *json_response = NULL;
    cJSON *data_array = NULL;
    int error_code = WM_TASK_SUCCESS;

    mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_INCOMMING_MESSAGE, msg);

    // Parse message
    if (task = wm_task_manager_parse_message(msg), !task) {
        cJSON* parse_error = wm_task_manager_parse_data_response(WM_TASK_INVALID_MESSAGE, OS_INVALID, OS_INVALID, NULL);
        json_response = wm_task_manager_parse_response(WM_TASK_INVALID_MESSAGE, parse_error);
        *response = cJSON_PrintUnformatted(json_response);
        cJSON_Delete(json_response);
        return strlen(*response);
    }

    // Analyze task, update tasks DB and generate JSON response
    data_array = wm_task_manager_process_task(task, &error_code);

    switch (error_code) {
    case WM_TASK_INVALID_COMMAND:
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_UNDEFINED_ACTION_ERRROR);
        cJSON_Delete(data_array);
        data_array = wm_task_manager_parse_data_response(WM_TASK_INVALID_COMMAND, OS_INVALID, OS_INVALID, NULL);
        break;
    case WM_TASK_DATABASE_ERROR:
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DB_ERROR);
        cJSON_Delete(data_array);
        data_array = wm_task_manager_parse_data_response(WM_TASK_DATABASE_ERROR, OS_INVALID, OS_INVALID, NULL);
        break;
    case WM_TASK_DATABASE_PARSE_ERROR:
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DB_ERROR);
        cJSON_Delete(data_array);
        data_array = wm_task_manager_parse_data_response(WM_TASK_DATABASE_PARSE_ERROR, OS_INVALID, OS_INVALID, NULL);
        break;
    case WM_TASK_DATABASE_REQUEST_ERROR:
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DB_ERROR);
        cJSON_Delete(data_array);
        data_array = wm_task_manager_parse_data_response(WM_TASK_DATABASE_REQUEST_ERROR, OS_INVALID, OS_INVALID, NULL);
        break;
    default:
        break;
    }

    json_response = wm_task_manager_parse_response(error_code, data_array);
    *response = cJSON_PrintUnformatted(json_response);

    mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_RESPONSE_MESSAGE, *response);

    wm_task_manager_free_task(task);
    cJSON_Delete(json_response);

    return strlen(*response);
}

STATIC int wm_task_manager_init(wm_task_manager *task_config) {
    int sock = 0;

    // Check if module is enabled
    if (!task_config->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DISABLED);
        pthread_exit(NULL);
    }

    // Start clean tasks thread
    w_create_thread(wm_task_manager_clean_tasks, task_config);

    /* Set the queue */
    if (sock = OS_BindUnixDomainWithPerms(TASK_QUEUE, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660), sock < 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_CREATE_SOCK_ERROR, TASK_QUEUE, strerror(errno)); // LCOV_EXCL_LINE
        pthread_exit(NULL);
    }

    return sock;
}

#ifdef WIN32
STATIC DWORD WINAPI wm_task_manager_main(void *arg) {
    wm_task_manager* task_config = (wm_task_manager *)arg;
#else
STATIC void* wm_task_manager_main(wm_task_manager* task_config) {
#endif
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    if (w_is_worker()) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DISABLED_WORKER);
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

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

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    close(sock);
#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

STATIC void wm_task_manager_destroy(wm_task_manager* task_config) {
    mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_FINISH);
    os_free(task_config);
}

STATIC cJSON* wm_task_manager_dump(const wm_task_manager* task_config){
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
