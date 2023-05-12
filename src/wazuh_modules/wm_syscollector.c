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
#include "wm_syscollector.h"
#include "syscollector.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"
#include "headers/logging_helper.h"
#include "commonDefs.h"

#ifdef WIN32
static DWORD WINAPI wm_sys_main(void *arg);         // Module main function. It won't return
#else
static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
#endif
static void wm_sys_destroy(wm_sys_t *data);      // Destroy data
static void wm_sys_stop(wm_sys_t *sys);         // Module stopper
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);
int wm_sync_message(const char *data);
pthread_cond_t sys_stop_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t sys_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
bool need_shutdown_wait = false;
pthread_mutex_t sys_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;
bool shutdown_process_started = false;

const wm_context WM_SYS_CONTEXT = {
    .name = "syscollector",
    .start = (wm_routine)wm_sys_main,
    .destroy = (void(*)(void *))wm_sys_destroy,
    .dump = (cJSON * (*)(const void *))wm_sys_dump,
    .sync = (int(*)(const char*))wm_sync_message,
    .stop = (void(*)(void *))wm_sys_stop,
    .query = NULL,
};

void *syscollector_module = NULL;
syscollector_start_func syscollector_start_ptr = NULL;
syscollector_stop_func syscollector_stop_ptr = NULL;
syscollector_sync_message_func syscollector_sync_message_ptr = NULL;

long syscollector_sync_max_eps = 10;    // Database syncrhonization number of events per seconds (default value)
int queue_fd = 0;                       // Output queue file descriptor

static bool is_shutdown_process_started() {
    bool ret_val = shutdown_process_started;
    return ret_val;
}

static void wm_sys_send_message(const void* data, const char queue_id) {
    if (!is_shutdown_process_started()) {
        const int eps = 1000000/syscollector_sync_max_eps;
        if (wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
    #ifdef CLIENT
            mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' (wazuh-agentd might be down). Attempting to reconnect.", DEFAULTQUEUE);
    #else
            mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' (wazuh-analysisd might be down). Attempting to reconnect.", DEFAULTQUEUE);
    #endif
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

static void wm_sys_send_dbsync_message(const void* data) {
    wm_sys_send_message(data, DBSYNC_MQ);
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

#ifdef WIN32
DWORD WINAPI wm_sys_main(void *arg) {
    wm_sys_t *sys = (wm_sys_t *)arg;
#else
void* wm_sys_main(wm_sys_t *sys) {
#endif
    w_cond_init(&sys_stop_condition, NULL);
    w_mutex_init(&sys_stop_mutex, NULL);
    w_mutex_init(&sys_reconnect_mutex, NULL);

    if (!sys->flags.enabled) {
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
        syscollector_start_ptr = so_get_function_sym(syscollector_module, "syscollector_start");
        syscollector_stop_ptr = so_get_function_sym(syscollector_module, "syscollector_stop");
        syscollector_sync_message_ptr = so_get_function_sym(syscollector_module, "syscollector_sync_message");

        void* rsync_module = NULL;
        if(rsync_module = so_check_module_loaded("rsync"), rsync_module) {
            rsync_initialize_full_log_func rsync_initialize_log_function_ptr = so_get_function_sym(rsync_module, "rsync_initialize_full_log_function");
            if(rsync_initialize_log_function_ptr) {
                rsync_initialize_log_function_ptr(_mtdebug2, _mtdebug1, _mtinfo, _mtwarn, _mterror);
            }
            // Even when the RTLD_NOLOAD flag was used for dlopen(), we need a matching call to dlclose()
#ifndef WIN32
            so_free_library(rsync_module);
#endif
        }
    } else {
#ifdef __hpux
        mtinfo(WM_SYS_LOGTAG, "Not supported in HP-UX.");
#else
        mterror(WM_SYS_LOGTAG, "Can't load syscollector.");
#endif
        pthread_exit(NULL);
    }
    if (syscollector_start_ptr) {
        mtdebug1(WM_SYS_LOGTAG, "Starting Syscollector.");
        w_mutex_lock(&sys_stop_mutex);
        need_shutdown_wait = true;
        w_mutex_unlock(&sys_stop_mutex);
        const long max_eps = sys->sync.sync_max_eps;
        if (0 != max_eps) {
            syscollector_sync_max_eps = max_eps;
        }
        // else: if max_eps is 0 (from configuration) let's use the default max_eps value (10)
        wm_sys_log_config(sys);
        syscollector_start_ptr(sys->interval,
                               wm_sys_send_diff_message,
                               wm_sys_send_dbsync_message,
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
                               sys->flags.hotfixinfo);
    } else {
        mterror(WM_SYS_LOGTAG, "Can't get syscollector_start_ptr.");
        pthread_exit(NULL);
    }
    syscollector_sync_message_ptr = NULL;
    syscollector_start_ptr = NULL;
    syscollector_stop_ptr = NULL;

    if (queue_fd) {
        close(queue_fd);
        queue_fd = 0;
    }
    so_free_library(syscollector_module);
    syscollector_module = NULL;
    mtinfo(WM_SYS_LOGTAG, "Module finished.");
    w_mutex_lock(&sys_stop_mutex);
    w_cond_signal(&sys_stop_condition);
    w_mutex_unlock(&sys_stop_mutex);
    return 0;
}

void wm_sys_destroy(wm_sys_t *data) {
    free(data);
}

void wm_sys_stop(__attribute__((unused))wm_sys_t *data) {
    mtinfo(WM_SYS_LOGTAG, "Stop received for Syscollector.");
    syscollector_sync_message_ptr = NULL;
    if (syscollector_stop_ptr){
        shutdown_process_started = true;
        syscollector_stop_ptr();
    }
    w_mutex_lock(&sys_stop_mutex);
    if (need_shutdown_wait) {
        w_cond_wait(&sys_stop_condition, &sys_stop_mutex);
    }
    w_mutex_unlock(&sys_stop_mutex);

    w_cond_destroy(&sys_stop_condition);
    w_mutex_destroy(&sys_stop_mutex);
    w_mutex_destroy(&sys_reconnect_mutex);
}

cJSON *wm_sys_dump(const wm_sys_t *sys) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

    // System provider values
    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys,"disabled","no"); else cJSON_AddStringToObject(wm_sys,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sys,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sys,"interval",sys->interval);
    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sys,"network","yes"); else cJSON_AddStringToObject(wm_sys,"network","no");
    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sys,"os","yes"); else cJSON_AddStringToObject(wm_sys,"os","no");
    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sys,"hardware","yes"); else cJSON_AddStringToObject(wm_sys,"hardware","no");
    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sys,"packages","yes"); else cJSON_AddStringToObject(wm_sys,"packages","no");
    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sys,"ports","yes"); else cJSON_AddStringToObject(wm_sys,"ports","no");
    if (sys->flags.allports) cJSON_AddStringToObject(wm_sys,"ports_all","yes"); else cJSON_AddStringToObject(wm_sys,"ports_all","no");
    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sys,"processes","yes"); else cJSON_AddStringToObject(wm_sys,"processes","no");
#ifdef WIN32
    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sys,"hotfixes","yes"); else cJSON_AddStringToObject(wm_sys,"hotfixes","no");
#endif
    // Database synchronization values
    cJSON_AddNumberToObject(wm_sys,"sync_max_eps",sys->sync.sync_max_eps);

    cJSON_AddItemToObject(root,"syscollector",wm_sys);

    return root;
}

int wm_sync_message(const char *data)
{
    int ret_val = 0;

    if (syscollector_sync_message_ptr) {
        ret_val = syscollector_sync_message_ptr(data);
    }

    return ret_val;
}
