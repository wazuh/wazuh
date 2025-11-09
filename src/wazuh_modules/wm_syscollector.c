/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015, Wazuh Inc.
 * November 11, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdlib.h>
#include "../../wmodules_def.h"
#include "wmodules.h"
#include "module_query_errors.h"
#include "wm_syscollector.h"
#include "syscollector.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"
#include "headers/logging_helper.h"
#include "commonDefs.h"

#define SYS_SYNC_PROTOCOL_DB_PATH "queue/syscollector/db/syscollector_sync.db"
#define SYS_SYNC_RETRIES 3

// Global flag to stop sync module
static volatile int sync_module_running = 0;

#ifdef WIN32
static DWORD WINAPI wm_sys_main(void *arg);         // Module main function. It won't return
static DWORD WINAPI wm_sync_module(__attribute__((unused)) void * args);
#else
static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void * wm_sync_module(__attribute__((unused)) void * args);
#endif
static void wm_sys_destroy(wm_sys_t *data);      // Destroy data
static void wm_sys_stop(wm_sys_t *sys);         // Module stopper
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);
int wm_sync_message(const char *command, size_t command_len);
pthread_cond_t sys_stop_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t sys_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
bool need_shutdown_wait = false;
pthread_mutex_t sys_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;
bool shutdown_process_started = false;

static size_t wm_sys_query_handler(void *data, char *query, char **output); // Query handler

const wm_context WM_SYS_CONTEXT = {
    .name = SYSCOLLECTOR_WM_NAME,
    .start = (wm_routine)wm_sys_main,
    .destroy = (void(*)(void *))wm_sys_destroy,
    .dump = (cJSON * (*)(const void *))wm_sys_dump,
    .sync = (int(*)(const char*, size_t))wm_sync_message,
    .stop = (void(*)(void *))wm_sys_stop,
    .query = wm_sys_query_handler,
};

void *syscollector_module = NULL;

syscollector_init_func syscollector_init_ptr = NULL;
syscollector_start_func syscollector_start_ptr = NULL;
syscollector_stop_func syscollector_stop_ptr = NULL;

// Sync protocol function pointers
syscollector_init_sync_func syscollector_init_sync_ptr = NULL;
syscollector_sync_module_func syscollector_sync_module_ptr = NULL;
syscollector_persist_diff_func syscollector_persist_diff_ptr = NULL;
syscollector_parse_response_func syscollector_parse_response_ptr = NULL;
syscollector_notify_data_clean_func syscollector_notify_data_clean_ptr = NULL;
syscollector_delete_database_func syscollector_delete_database_ptr = NULL;

// Query function pointer
typedef size_t (*syscollector_query_func)(const char* query, char** output);
syscollector_query_func syscollector_query_ptr = NULL;

unsigned int enable_synchronization = 1;     // Database synchronization enabled (default value)
uint32_t sync_interval = 300;                // Database synchronization interval (default value)
uint32_t sync_end_delay = 1;                 // Database synchronization end delay in seconds (default value)
uint32_t sync_response_timeout = 30;         // Database synchronization response timeout (default value)
long sync_max_eps = 10;                      // Database synchronization number of events per second (default value)

long syscollector_max_eps = 50;          // Number of events per second (default value)
int queue_fd = 0;                        // Output queue file descriptor

static bool is_shutdown_process_started() {
    bool ret_val = shutdown_process_started;
    return ret_val;
}

static void wm_sys_send_message(const void* data, const char queue_id) {
    if (!is_shutdown_process_started()) {
        const int eps = 1000000/syscollector_max_eps;
        if (wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
            mtdebug1(WM_SYS_LOGTAG, "Unable to send message to '%s'", DEFAULTQUEUE);

            // Since this method is beign called by multiple threads it's necessary this particular portion of code
            // to be mutually exclusive. When one thread is successfully reconnected, the other ones will make use of it.
            w_mutex_lock(&sys_reconnect_mutex);
            if (!is_shutdown_process_started() && wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
                if (queue_fd = MQReconnectPredicated(DEFAULTQUEUE, &is_shutdown_process_started), 0 <= queue_fd) {
                    mtinfo(WM_SYS_LOGTAG, "Successfully reconnected to '%s'", DEFAULTQUEUE);
                    if (wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
                        mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' after a successfull reconnection...", DEFAULTQUEUE);
                    }
                }
            }
            w_mutex_unlock(&sys_reconnect_mutex);
        }
    }
}

static void wm_sys_send_diff_message(const void* data) {
    wm_sys_send_message(data, SYSCOLLECTOR_MQ);
}

static void wm_sys_persist_diff_message(const char *id, Operation_t operation, const char *index, const void* data, uint64_t version) {
    if (enable_synchronization && syscollector_persist_diff_ptr) {
        const char* msg = (const char*)data;
        mtdebug2(WM_SYS_LOGTAG, "Persisting Inventory event: %s", msg);
        syscollector_persist_diff_ptr(id, operation, index, msg, version);
    } else {
        mtdebug2(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
    }
}

static void wm_sys_log_config(wm_sys_t *sys)
{
    cJSON * config_json = wm_sys_dump(sys);
    if (config_json) {
        char * config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_SYS_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

static int wm_sys_startmq(const char* key, short type, short attempts) {
    return StartMQ(key, type, attempts);
}

static int wm_sys_send_binary_msg(int queue, const void* message, size_t message_len, const char* locmsg, char loc) {
    return SendBinaryMSG(queue, message, message_len, locmsg, loc);
}

static void wm_handle_sys_disabled_and_notify_data_clean(wm_sys_t *sys) {

    if (w_is_file(SYSCOLLECTOR_DB_DISK_PATH)) {
        mtinfo(WM_SYS_LOGTAG, "Syscollector is disabled, Syscollector database file exists. Proceeding with data clean notification.");
    } else {
        mtinfo(WM_SYS_LOGTAG, "Syscollector is disabled, Syscollector database file does not exist. Skipping data clean notification.");
        return;
    }

    if (syscollector_module = so_get_module_handle("syscollector"), syscollector_module) {

        syscollector_init_ptr = so_get_function_sym(syscollector_module, "syscollector_init");

        // Get sync protocol function pointers
        syscollector_init_sync_ptr = so_get_function_sym(syscollector_module, "syscollector_init_sync");
        syscollector_parse_response_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response");
        syscollector_notify_data_clean_ptr = so_get_function_sym(syscollector_module, "syscollector_notify_data_clean");
        syscollector_delete_database_ptr = so_get_function_sym(syscollector_module, "syscollector_delete_database");

        MQ_Functions mq_funcs = {
                .start = wm_sys_startmq,
                .send_binary = wm_sys_send_binary_msg
            };
        syscollector_init_sync_ptr(WM_SYS_LOCATION, SYS_SYNC_PROTOCOL_DB_PATH, &mq_funcs, sync_end_delay, sync_response_timeout, SYS_SYNC_RETRIES, sync_max_eps);

        syscollector_init_ptr(sys->interval,
                               wm_sys_send_diff_message,
                               wm_sys_persist_diff_message,
                               taggedLogFunction,
                               SYSCOLLECTOR_DB_DISK_PATH,
                               SYSCOLLECTOR_NORM_CONFIG_DISK_PATH,
                               SYSCOLLECTOR_NORM_TYPE,
                               sys->flags.scan_on_start,
                               sys->flags.hwinfo,
                               sys->flags.osinfo,
                               sys->flags.netinfo,
                               sys->flags.programinfo,
                               sys->flags.portsinfo,
                               sys->flags.allports,
                               sys->flags.procinfo,
                               sys->flags.hotfixinfo,
                               sys->flags.groups,
                               sys->flags.users,
                               sys->flags.services,
                               sys->flags.browser_extensions,
                               sys->flags.notify_first_scan);

        if (syscollector_notify_data_clean_ptr && syscollector_delete_database_ptr)
        {
            const char* indices[] = {
                SYSCOLLECTOR_SYNC_INDEX_SYSTEM,
                SYSCOLLECTOR_SYNC_INDEX_HARDWARE,
                SYSCOLLECTOR_SYNC_INDEX_HOTFIXES,
                SYSCOLLECTOR_SYNC_INDEX_PACKAGES,
                SYSCOLLECTOR_SYNC_INDEX_PROCESSES,
                SYSCOLLECTOR_SYNC_INDEX_PORTS,
                SYSCOLLECTOR_SYNC_INDEX_INTERFACES,
                SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS,
                SYSCOLLECTOR_SYNC_INDEX_NETWORKS,
                SYSCOLLECTOR_SYNC_INDEX_USERS,
                SYSCOLLECTOR_SYNC_INDEX_GROUPS,
                SYSCOLLECTOR_SYNC_INDEX_SERVICES,
                SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS
            };
            size_t indices_count = sizeof(indices) / sizeof(indices[0]);
            bool ret = false;
            while (!ret && !is_shutdown_process_started())
            {
                ret = syscollector_notify_data_clean_ptr(indices, indices_count);
                if (!ret) {
                    for (uint32_t i = 0; i < sync_interval && !is_shutdown_process_started(); i++) {
                        sleep(1);
                    }
                }
                else
                {
                    mtdebug1(WM_SYS_LOGTAG, "Syscollector data clean notification sent successfully.");
                    syscollector_delete_database_ptr();
                }
            }
        } else {
            mtwarn(WM_SYS_LOGTAG, "Syscollector notify data clean functions not available.");
        }

    }
    else
    {
        mtwarn(WM_SYS_LOGTAG, "Failed to load Syscollector module for data clean notification.");
        return;
    }
}

#ifdef WIN32
DWORD WINAPI wm_sys_main(void *arg) {
    wm_sys_t *sys = (wm_sys_t *)arg;
#else
void* wm_sys_main(wm_sys_t *sys) {
#endif

    if (sys->flags.running) {
        // Already running
        return 0;
    }

    sys->flags.running = true;

    w_cond_init(&sys_stop_condition, NULL);
    w_mutex_init(&sys_stop_mutex, NULL);
    w_mutex_init(&sys_reconnect_mutex, NULL);

    if (!sys->flags.enabled) {
        wm_handle_sys_disabled_and_notify_data_clean(sys);
        mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

#ifndef WIN32
    // Connect to socket
    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }
#endif

    if (syscollector_module = so_get_module_handle("syscollector"), syscollector_module)
    {
        syscollector_init_ptr = so_get_function_sym(syscollector_module, "syscollector_init");
        syscollector_start_ptr = so_get_function_sym(syscollector_module, "syscollector_start");
        syscollector_stop_ptr = so_get_function_sym(syscollector_module, "syscollector_stop");

        // Get sync protocol function pointers
        syscollector_init_sync_ptr = so_get_function_sym(syscollector_module, "syscollector_init_sync");
        syscollector_sync_module_ptr = so_get_function_sym(syscollector_module, "syscollector_sync_module");
        syscollector_persist_diff_ptr = so_get_function_sym(syscollector_module, "syscollector_persist_diff");
        syscollector_parse_response_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response");

        // Get query function pointer
        syscollector_query_ptr = so_get_function_sym(syscollector_module, "syscollector_query");
    } else {
        mterror(WM_SYS_LOGTAG, "Can't load syscollector.");
        pthread_exit(NULL);
    }

    if (syscollector_init_ptr && syscollector_start_ptr) {
        mtdebug1(WM_SYS_LOGTAG, "Starting Syscollector.");
        w_mutex_lock(&sys_stop_mutex);
        need_shutdown_wait = true;
        w_mutex_unlock(&sys_stop_mutex);

        enable_synchronization = sys->sync.enable_synchronization;
        if (enable_synchronization) {
            sync_interval = sys->sync.sync_interval;
            sync_end_delay = sys->sync.sync_end_delay;
            sync_response_timeout = sys->sync.sync_response_timeout;
            sync_max_eps = sys->sync.sync_max_eps;
        }

        if (sys->max_eps) {
            syscollector_max_eps = sys->max_eps;
        }

        wm_sys_log_config(sys);

        // Initialize syscollector FIRST to set up the logger callback
        syscollector_init_ptr(sys->interval,
                               wm_sys_send_diff_message,
                               wm_sys_persist_diff_message,
                               taggedLogFunction,
                               SYSCOLLECTOR_DB_DISK_PATH,
                               SYSCOLLECTOR_NORM_CONFIG_DISK_PATH,
                               SYSCOLLECTOR_NORM_TYPE,
                               sys->flags.scan_on_start,
                               sys->flags.hwinfo,
                               sys->flags.osinfo,
                               sys->flags.netinfo,
                               sys->flags.programinfo,
                               sys->flags.portsinfo,
                               sys->flags.allports,
                               sys->flags.procinfo,
                               sys->flags.hotfixinfo,
                               sys->flags.groups,
                               sys->flags.users,
                               sys->flags.services,
                               sys->flags.browser_extensions,
                               sys->flags.notify_first_scan);

        // Initialize sync protocol AFTER init (so logger is available)
        if (enable_synchronization && syscollector_init_sync_ptr && syscollector_sync_module_ptr) {
            MQ_Functions mq_funcs = {
                .start = wm_sys_startmq,
                .send_binary = wm_sys_send_binary_msg
            };
            syscollector_init_sync_ptr(WM_SYS_LOCATION, SYS_SYNC_PROTOCOL_DB_PATH, &mq_funcs, sync_end_delay, sync_response_timeout, SYS_SYNC_RETRIES, sync_max_eps);
#ifndef WIN32
            // Launch inventory synchronization thread
            sync_module_running = 1;
            w_create_thread(wm_sync_module, NULL);
#else
            sync_module_running = 1;
            if (CreateThread(NULL, 0, wm_sync_module, NULL, 0, NULL) == NULL) {
                mterror(WM_SYS_LOGTAG, THREAD_ERROR);
            }
#endif
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
        }

        syscollector_start_ptr();
    } else {
        mterror(WM_SYS_LOGTAG, "Can't get syscollector_start_ptr.");
        pthread_exit(NULL);
    }
    syscollector_init_ptr = NULL;
    syscollector_start_ptr = NULL;
    syscollector_stop_ptr = NULL;

    if (queue_fd) {
        close(queue_fd);
        queue_fd = 0;
    }

    mtinfo(WM_SYS_LOGTAG, "Module finished.");
    w_mutex_lock(&sys_stop_mutex);
    w_cond_signal(&sys_stop_condition);
    w_mutex_unlock(&sys_stop_mutex);
    return 0;
}

void wm_sys_destroy(wm_sys_t *data) {
    w_cond_destroy(&sys_stop_condition);
    w_mutex_destroy(&sys_stop_mutex);
    w_mutex_destroy(&sys_reconnect_mutex);

    free(data);
}

void wm_sys_stop(__attribute__((unused))wm_sys_t *data) {
    if (!data->flags.running) {
        // Already stopped
        return;
    }

    data->flags.running = false;

    // Stop sync module
    sync_module_running = 0;

    mtinfo(WM_SYS_LOGTAG, "Stop received for Syscollector.");
    if (syscollector_stop_ptr){
        shutdown_process_started = true;
        syscollector_stop_ptr();
    }
}

cJSON *wm_sys_dump(const wm_sys_t *sys) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

    // System provider values
    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys,"disabled","no"); else cJSON_AddStringToObject(wm_sys,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sys,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sys,"interval",sys->interval);
    cJSON_AddNumberToObject(wm_sys, "max_eps", sys->max_eps);
    if (sys->flags.notify_first_scan) cJSON_AddStringToObject(wm_sys,"notify_first_scan","yes"); else cJSON_AddStringToObject(wm_sys,"notify_first_scan","no");
    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sys,"network","yes"); else cJSON_AddStringToObject(wm_sys,"network","no");
    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sys,"os","yes"); else cJSON_AddStringToObject(wm_sys,"os","no");
    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sys,"hardware","yes"); else cJSON_AddStringToObject(wm_sys,"hardware","no");
    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sys,"packages","yes"); else cJSON_AddStringToObject(wm_sys,"packages","no");
    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sys,"ports","yes"); else cJSON_AddStringToObject(wm_sys,"ports","no");
    if (sys->flags.allports) cJSON_AddStringToObject(wm_sys,"ports_all","yes"); else cJSON_AddStringToObject(wm_sys,"ports_all","no");
    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sys,"processes","yes"); else cJSON_AddStringToObject(wm_sys,"processes","no");
    if (sys->flags.groups) cJSON_AddStringToObject(wm_sys,"groups","yes"); else cJSON_AddStringToObject(wm_sys,"groups","no");
    if (sys->flags.users) cJSON_AddStringToObject(wm_sys,"users","yes"); else cJSON_AddStringToObject(wm_sys,"users","no");
    if (sys->flags.services) cJSON_AddStringToObject(wm_sys,"services","yes"); else cJSON_AddStringToObject(wm_sys,"services","no");
    if (sys->flags.browser_extensions) cJSON_AddStringToObject(wm_sys,"browser_extensions","yes"); else cJSON_AddStringToObject(wm_sys,"browser_extensions","no");
#ifdef WIN32
    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sys,"hotfixes","yes"); else cJSON_AddStringToObject(wm_sys,"hotfixes","no");
#endif

    // Database synchronization values
    cJSON * synchronization = cJSON_CreateObject();
    cJSON_AddStringToObject(synchronization, "enabled", sys->sync.enable_synchronization ? "yes" : "no");
    cJSON_AddNumberToObject(synchronization, "interval", sys->sync.sync_interval);
    cJSON_AddNumberToObject(synchronization, "max_eps", sys->sync.sync_max_eps);
    cJSON_AddNumberToObject(synchronization, "response_timeout", sys->sync.sync_response_timeout);
    cJSON_AddNumberToObject(synchronization, "sync_end_delay", sys->sync.sync_end_delay);

    cJSON_AddItemToObject(wm_sys, "synchronization", synchronization);

    cJSON_AddItemToObject(root,"syscollector",wm_sys);

    return root;
}

int wm_sync_message(const char *command, size_t command_len) {
    if (enable_synchronization && syscollector_parse_response_ptr) {
        size_t header_len = strlen(SYSCOLECTOR_SYNC_HEADER);
        const uint8_t *data = (const uint8_t *)(command + header_len);
        size_t data_len = command_len - header_len;

        bool ret = false;
        ret = syscollector_parse_response_ptr(data, data_len);

        if (!ret) {
            mtdebug1(WM_SYS_LOGTAG, "Error syncing module");
            return -1;
        }

        return 0;
    } else {
        mtdebug1(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
        return -1;
    }
}

#ifdef WIN32
DWORD WINAPI wm_sync_module(__attribute__((unused)) void * args) {
#else
void * wm_sync_module(__attribute__((unused)) void * args) {
#endif
    // Initial wait until syscollector is started
    for (uint32_t i = 0; i < sync_interval && sync_module_running; i++) {
        sleep(1);
    }

    while (sync_module_running) {
        mtinfo(WM_SYS_LOGTAG, "Running inventory synchronization.");

        if (syscollector_sync_module_ptr) {
            syscollector_sync_module_ptr(MODE_DELTA);
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Sync function not available");
        }

        mtinfo(WM_SYS_LOGTAG, "Inventory synchronization finished, waiting for %d seconds before next run.", sync_interval);

        // Sleep in small intervals to allow responsive stopping
        for (uint32_t i = 0; i < sync_interval && sync_module_running; i++) {
            sleep(1);
        }
    }

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static size_t wm_sys_query_handler(void *data, char *query, char **output) {
    (void)data;  // Unused parameter

    if (!query || !output) {
        return 0;
    }

    // Call the C++ query function if available
    if (syscollector_query_ptr) {
        return syscollector_query_ptr(query, output);
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }
}
