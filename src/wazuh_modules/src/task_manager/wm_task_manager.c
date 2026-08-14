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

#include "wmodules.h"
#include "wm_task_manager_tasks.h"
#include "wm_task_manager_parsing.h"
#include "os_net.h"
#include "notify_op.h"

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
STATIC void* wm_task_manager_main(wm_task_manager* task_config);    // Module main function. It won't return
STATIC void wm_task_manager_destroy(wm_task_manager* task_config);
STATIC void wm_task_manager_stop(wm_task_manager* task_config);
STATIC cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

/* Context definition */
const wm_context WM_TASK_MANAGER_CONTEXT = {
    .name = TASK_MANAGER_WM_NAME,
    .start = (wm_routine)wm_task_manager_main,
    .destroy = (void (*)(void *))wm_task_manager_destroy,
    .dump = (cJSON * (*)(const void *))wm_task_manager_dump,
    .sync = NULL,
    .stop = (void (*)(void *))wm_task_manager_stop,
    .query = NULL,
};

/* Task type names for generic task API */
const char *task_type_names[] = {
    [WM_TASK_TYPE_ACTIVE_RESPONSE] = "active_response",
    [WM_TASK_TYPE_REMOTE_UPGRADE] = "remote_upgrade",
    [WM_TASK_TYPE_AGENT_RESTART] = "agent_restart",
    [WM_TASK_TYPE_AGENT_RELOAD] = "agent_reload"
};

/* Global config for access from dispatch functions */
static wm_task_manager *g_task_manager_config = NULL;

// Global notification queue for worker threads
static wnotify_t *task_notify_queue = NULL;
static pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

STATIC int wm_task_manager_init(wm_task_manager *task_config) {
    // Store config globally
    g_task_manager_config = task_config;
    int sock = 0;

    // Check if module is enabled
    if (!task_config->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_DISABLED);
        pthread_exit(NULL);
    }

    // Initialize task cache
    wm_task_cache_init();
    mtinfo(WM_TASK_MANAGER_LOGTAG, "Task cache initialized");

    // Warn about unsafe interaction with remoted's legacy task delivery poller
    int task_ttl = task_config->task_ttl > 0 ? task_config->task_ttl : WM_TASK_DEFAULT_TTL;
    int legacy_task_polling_interval =
        getDefine_Int_default("remoted", "legacy_task_polling_interval", 300, 86400, 900);

    if (legacy_task_polling_interval >= task_ttl) {
        mtwarn(WM_TASK_MANAGER_LOGTAG, "remoted.legacy_task_polling_interval (%d) is >= task-manager.task_ttl (%d). "
               "A pending task may expire before the legacy task delivery poller ever gets a chance to see it.",
               legacy_task_polling_interval, task_ttl);
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

// Dealer thread: accepts connections and adds to notification queue
STATIC void* wm_task_manager_dealer(__attribute__((unused)) void *args) {
    int sock;
    int peer;
    fd_set fdset;
    struct timeval timeout;
    wm_task_manager *task_config = (wm_task_manager *)args;

    // Initial configuration
    sock = wm_task_manager_init(task_config);

    mtinfo(WM_TASK_MANAGER_LOGTAG, STARTUP_MSG " (dealer thread)", (int)getpid());

    while (!wm_shutdown_requested) {
        // Wait for socket with timeout
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno == EINTR) {
                mtdebug1(WM_TASK_MANAGER_LOGTAG, "Dealer select interrupted");
                continue;
            } else {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SELECT_ERROR, strerror(errno));
                pthread_exit(NULL);
            }
            break;
        case 0:
            continue;
        }

        // Accept incoming connection
        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_ACCEPT_ERROR, strerror(errno));
            }
            continue;
        }

        // Add peer to notification queue for workers
        if (wnotify_add(task_notify_queue, peer, WO_READ) < 0) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Failed to add peer %d to notification queue: %s (%d)", peer, strerror(errno), errno);
            close(peer);
            continue;
        }

        mtdebug1(WM_TASK_MANAGER_LOGTAG, "New client connected (%d)", peer);

    #ifdef WAZUH_UNIT_TESTING
        // Exit after accepting one connection for unit tests
        break;
    #endif
    }

    close(sock);
    return NULL;
}

// Worker thread: processes requests from notification queue
STATIC void* wm_task_manager_worker(__attribute__((unused)) void *args) {
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    int peer;

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Worker thread started");

    while (!wm_shutdown_requested) {
        // Wait for a peer from the notification queue
        w_mutex_lock(&task_queue_mutex);

        switch (wnotify_wait(task_notify_queue, 100)) {
        case -1:
            if (errno != EINTR) {
                mterror(WM_TASK_MANAGER_LOGTAG, "Worker wnotify_wait error: %s", strerror(errno));
            }
            w_mutex_unlock(&task_queue_mutex);
            continue;

        case 0:
            w_mutex_unlock(&task_queue_mutex);
            continue;
        }

        peer = wnotify_get(task_notify_queue, 0, NULL);
        if (wnotify_delete(task_notify_queue, peer, WO_READ) < 0) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Worker wnotify_delete(%d): %s (%d)", peer, strerror(errno), errno);
        }

        w_mutex_unlock(&task_queue_mutex);

        if (peer < 0) {
            continue;
        }

        mtdebug2(WM_TASK_MANAGER_LOGTAG, "Worker processing peer %d", peer);

        // Receive message from connection
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR);

        // Check for socket errors that should terminate the worker
        if (length == OS_SOCKTERR) {
            mterror(WM_TASK_MANAGER_LOGTAG, MOD_TASK_SOCKTERR_ERROR);
            os_free(buffer);
            break;  // Exit worker thread
        }

        switch (length) {
        case -1:
            mtdebug1(WM_TASK_MANAGER_LOGTAG, MOD_TASK_RECV_ERROR, strerror(errno));
            close(peer);
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
            // Process request using JSON-based API
            response = wm_task_manager_dispatch(buffer);
            length = response ? strlen(response) : 0;

            // Send response
            if (response && length > 0) {
                if (OS_SendSecureTCP(peer, length, response) < 0) {
                    mterror(WM_TASK_MANAGER_LOGTAG, "Failed to send response to peer %d: %s (%d)", peer, strerror(errno), errno);
                }
            }
            os_free(response);
            mtdebug2(WM_TASK_MANAGER_LOGTAG, "Worker completed request for peer %d", peer);
            break;
        }

        // Always re-add peer to notification queue (unless it was closed due to error)
        // This matches WazuhDB behavior and keeps the connection alive
        if (length != -1 && length != 0 && length != OS_MAXLEN) {
            if (wnotify_add(task_notify_queue, peer, WO_READ) < 0) {
                mterror(WM_TASK_MANAGER_LOGTAG, "Failed to re-add peer %d to notification queue: %s (%d)", peer, strerror(errno), errno);
                close(peer);
            }
        }

        os_free(buffer);

    #ifdef WAZUH_UNIT_TESTING
        // Exit after one iteration for unit tests
        break;
    #endif
    }

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Worker thread exiting");
    return NULL;
}

// Main thread: starts dealer and worker threads
STATIC void* wm_task_manager_main(wm_task_manager* task_config) {
    pthread_t dealer_thread;
    pthread_t *worker_threads = NULL;
    int worker_count = 8;  // Number of worker threads
    int status;
    int i;

    // Initialize notification queue
    if (task_notify_queue = wnotify_init(1), !task_notify_queue) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to initialize notification queue: %s (%d)", strerror(errno), errno);
        pthread_exit(NULL);
    }

    mtinfo(WM_TASK_MANAGER_LOGTAG, "Starting dealer and %d worker threads", worker_count);

    // Start dealer thread
    if (status = pthread_create(&dealer_thread, NULL, wm_task_manager_dealer, task_config), status != 0) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to create dealer thread: %s", strerror(status));
        wnotify_close(task_notify_queue);
        pthread_exit(NULL);
    }

    // Start worker threads
    os_calloc(worker_count, sizeof(pthread_t), worker_threads);
    for (i = 0; i < worker_count; i++) {
        if (status = pthread_create(&worker_threads[i], NULL, wm_task_manager_worker, NULL), status != 0) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Failed to create worker thread %d: %s", i, strerror(status));
        }
    }

    // Wait for dealer thread
    pthread_join(dealer_thread, NULL);

    // Signal workers to stop and wait for them
    for (i = 0; i < worker_count; i++) {
        if (worker_threads[i]) {
            pthread_join(worker_threads[i], NULL);
        }
    }

    os_free(worker_threads);
    wnotify_close(task_notify_queue);

    mtinfo(WM_TASK_MANAGER_LOGTAG, "Task manager stopped");
    return NULL;
}

STATIC void wm_task_manager_stop(__attribute__((unused)) wm_task_manager* task_config) {
    wm_shutdown_requested = 1;
}

STATIC void wm_task_manager_destroy(wm_task_manager* task_config) {
    mtinfo(WM_TASK_MANAGER_LOGTAG, MOD_TASK_FINISH);
    wm_task_cache_destroy();
    os_free(task_config);
}

STATIC cJSON* wm_task_manager_dump(const wm_task_manager* task_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (task_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
        cJSON_AddNumberToObject(wm_info, "task_ttl",
            task_config->task_ttl > 0 ? task_config->task_ttl : WM_TASK_DEFAULT_TTL);
        cJSON_AddNumberToObject(wm_info, "cleanup_interval",
            task_config->cleanup_interval > 0 ? task_config->cleanup_interval : WM_TASK_DEFAULT_CLEANUP_INTERVAL);
        cJSON_AddNumberToObject(wm_info, "max_payload_bytes",
            task_config->max_payload_bytes > 0 ? task_config->max_payload_bytes : WM_TASK_DEFAULT_MAX_PAYLOAD_BYTES);
        cJSON_AddNumberToObject(wm_info, "max_tasks_per_poll",
            task_config->max_tasks_per_poll > 0 ? task_config->max_tasks_per_poll : WM_TASK_DEFAULT_MAX_TASKS_PER_POLL);
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    cJSON_AddItemToObject(root, "task-manager", wm_info);

    return root;
}

char* wm_task_manager_dispatch(const char *msg) {
    void *params = NULL;
    char *response = NULL;
    int parsing_retval;

    mtdebug1(WM_TASK_MANAGER_LOGTAG, "Incoming message: %s", msg);

    // Parse incoming message
    parsing_retval = wm_task_manager_parse_message(msg, &params, &response);

    switch (parsing_retval) {
    case WM_TASK_MANAGER_CREATE:
        if (params) {
            wm_task_create_params *create_params = (wm_task_create_params *)params;

            int max_payload_bytes = g_task_manager_config ? g_task_manager_config->max_payload_bytes : 0;
            char *task_id = wm_task_manager_create_task(
                create_params->agent_id,
                create_params->task_type,
                create_params->payload_json,
                create_params->source_id,
                create_params->create_time,
                max_payload_bytes
            );

            if (task_id) {
                response = wm_task_manager_parse_create_response(task_id);
                os_free(task_id);
            } else {
                response = wm_task_manager_parse_error_response("create_failed", "Failed to create task");
            }

            os_free(create_params->agent_id);
            os_free(create_params->source_id);
            os_free(create_params->payload_json);
            os_free(create_params);
        }
        break;

    case WM_TASK_MANAGER_GET_PENDING:
        if (params) {
            wm_task_get_pending_params *get_params = (wm_task_get_pending_params *)params;

            int max_tasks_per_poll = g_task_manager_config ? g_task_manager_config->max_tasks_per_poll : 0;
            cJSON *tasks = wm_task_manager_get_pending_tasks(get_params->agent_id, max_tasks_per_poll);

            if (tasks) {
                response = wm_task_manager_parse_get_pending_response(tasks);
            } else {
                response = wm_task_manager_parse_error_response("query_failed", "Failed to get pending tasks");
            }

            os_free(get_params->agent_id);
            os_free(get_params);
        }
        break;

    case OS_INVALID:
    default:
        if (!response) {
            response = wm_task_manager_parse_error_response("parsing_failed", "Unknown error during parsing");
        }
        break;
    }

    return response;
}
