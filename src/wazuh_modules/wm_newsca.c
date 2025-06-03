/*
 * Wazuh NEWSCA
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
#include "wm_newsca.h"
#include "newsca.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"
#include "headers/logging_helper.h"
#include "commonDefs.h"

#ifndef CLIENT
#include "router.h"
#include "utils/flatbuffers/include/rsync_schema.h"
#include "utils/flatbuffers/include/syscollector_deltas_schema.h"
#include "agent_messages_adapter.h"
#endif // CLIENT

#ifdef WIN32
static DWORD WINAPI wm_newsca_main(void *arg);         // Module main function. It won't return
#else
static void* wm_newsca_main(wm_newsca_t *sys);        // Module main function. It won't return
#endif
static void wm_newsca_destroy(wm_newsca_t *data);      // Destroy data
static void wm_newsca_stop(wm_newsca_t *sys);         // Module stopper
const char *WM_NEWSCA_LOCATION = "newsca";   // Location field for event sending
cJSON *wm_newsca_dump(const wm_newsca_t *sys);
int wm_sca_message(const char *data);
pthread_cond_t newsca_stop_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t newsca_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool need_shutdown_wait = false;
pthread_mutex_t newsca_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool shutdown_process_started = false;

const wm_context WM_NEWSCA_CONTEXT = {
    .name = "newsca",
    .start = (wm_routine)wm_newsca_main,
    .destroy = (void(*)(void *))wm_newsca_destroy,
    .dump = (cJSON * (*)(const void *))wm_newsca_dump,
    .sync = (int(*)(const char*))wm_sca_message,
    .stop = (void(*)(void *))wm_newsca_stop,
    .query = NULL,
};

void *newsca_module = NULL;
newsca_start_func newsca_start_ptr = NULL;
newsca_stop_func newsca_stop_ptr = NULL;
newsca_sync_message_func newsca_sync_message_ptr = NULL;

#ifndef CLIENT
void *router_module_ptr = NULL;
router_provider_create_func router_provider_create_func_ptr = NULL;
router_provider_send_fb_func router_provider_send_fb_func_ptr = NULL;
ROUTER_PROVIDER_HANDLE rsync_handle = NULL;
ROUTER_PROVIDER_HANDLE newsca_handle = NULL;
int disable_manager_scan = 1;
#endif // CLIENT

long newsca_sync_max_eps = 10;    // Database synchronization number of events per second (default value)
static int queue_fd = 0;                       // Output queue file descriptor

static bool is_shutdown_process_started() {
    bool ret_val = shutdown_process_started;
    return ret_val;
}

static void wm_newsca_send_message(const void* data, const char queue_id) {
    if (!is_shutdown_process_started()) {
        const int eps = 1000000/newsca_sync_max_eps;
        if (wm_sendmsg_ex(eps, queue_fd, data, WM_NEWSCA_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
    #ifdef CLIENT
            mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' (wazuh-agentd might be down). Attempting to reconnect.", DEFAULTQUEUE);
    #else
            mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' (wazuh-analysisd might be down). Attempting to reconnect.", DEFAULTQUEUE);
    #endif
            // Since this method is beign called by multiple threads it's necessary this particular portion of code
            // to be mutually exclusive. When one thread is successfully reconnected, the other ones will make use of it.
            w_mutex_lock(&newsca_reconnect_mutex);
            if (!is_shutdown_process_started() && wm_sendmsg_ex(eps, queue_fd, data, WM_NEWSCA_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
                if (queue_fd = MQReconnectPredicated(DEFAULTQUEUE, &is_shutdown_process_started), 0 <= queue_fd) {
                    mtinfo(WM_SYS_LOGTAG, "Successfully reconnected to '%s'", DEFAULTQUEUE);
                    if (wm_sendmsg_ex(eps, queue_fd, data, WM_NEWSCA_LOCATION, queue_id, &is_shutdown_process_started) < 0) {
                        mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' after a successfull reconnection...", DEFAULTQUEUE);
                    }
                }
            }
            w_mutex_unlock(&newsca_reconnect_mutex);
        }
    }
}

static void wm_newsca_send_diff_message(const void* data) {
    wm_newsca_send_message(data, SYSCOLLECTOR_MQ);
#ifndef CLIENT
    if(!disable_manager_scan)
    {
        char* msg_to_send = adapt_delta_message(data, "localhost", "000", "127.0.0.1", NULL);
        if (msg_to_send && router_provider_send_fb_func_ptr) {
            router_provider_send_fb_func_ptr(newsca_handle, msg_to_send, newsca_deltas_SCHEMA);
        }
        cJSON_free(msg_to_send);
    }
#endif // CLIENT
}

static void wm_newsca_send_dbsync_message(const void* data) {
    wm_newsca_send_message(data, DBSYNC_MQ);
#ifndef CLIENT
    if(!disable_manager_scan)
    {
        char* msg_to_send = adapt_sync_message(data, "localhost", "000", "127.0.0.1", NULL);
        if (msg_to_send && router_provider_send_fb_func_ptr) {
            router_provider_send_fb_func_ptr(rsync_handle, msg_to_send, rsync_SCHEMA);
        }
        cJSON_free(msg_to_send);
    }
#endif // CLIENT
}

static void wm_newsca_log_config(wm_newsca_t *sys)
{
    cJSON * config_json = wm_newsca_dump(sys);
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
DWORD WINAPI wm_newsca_main(void *arg) {
    wm_newsca_t *sys = (wm_newsca_t *)arg;
#else
void* wm_newsca_main(wm_newsca_t *sys) {
#endif

    if (sys->flags.running) {
        // Already running
        return 0;
    }

    sys->flags.running = true;

    w_cond_init(&newsca_stop_condition, NULL);
    w_mutex_init(&newsca_stop_mutex, NULL);
    w_mutex_init(&newsca_reconnect_mutex, NULL);

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

    if (newsca_module = so_get_module_handle("newsca"), newsca_module)
    {
        newsca_start_ptr = so_get_function_sym(newsca_module, "newsca_start");
        newsca_stop_ptr = so_get_function_sym(newsca_module, "newsca_stop");
        newsca_sync_message_ptr = so_get_function_sym(newsca_module, "newsca_sync_message");

        void* rsync_module = NULL;
        if(rsync_module = so_check_module_loaded("rsync"), rsync_module) {
            rsync_initialize_full_log_func rsync_initialize_log_function_ptr = so_get_function_sym(rsync_module, "rsync_initialize_full_log_function");
            if(rsync_initialize_log_function_ptr) {
                rsync_initialize_log_function_ptr(mtLoggingFunctionsWrapper);
            }
            // Even when the RTLD_NOLOAD flag was used for dlopen(), we need a matching call to dlclose()
#ifndef WIN32
            so_free_library(rsync_module);
#endif
        }
#ifndef CLIENT
        // Load router module only for manager if is enabled
        disable_manager_scan = getDefine_Int("vulnerability-detection", "disable_scan_manager", 0, 1);
        if (router_module_ptr = so_get_module_handle("router"), router_module_ptr) {
                router_provider_create_func_ptr = so_get_function_sym(router_module_ptr, "router_provider_create");
                router_provider_send_fb_func_ptr = so_get_function_sym(router_module_ptr, "router_provider_send_fb");
                if (router_provider_create_func_ptr && router_provider_send_fb_func_ptr) {
                    mtdebug1(WM_SYS_LOGTAG, "Router module loaded.");
                } else {
                    mwarn("Failed to load methods from router module.");
                }
            } else {
                mwarn("Failed to load router module.");
            }
#endif // CLIENT
    } else {
#ifdef __hpux
        mtinfo(WM_SYS_LOGTAG, "Not supported in HP-UX.");
#else
        mterror(WM_SYS_LOGTAG, "Can't load newsca.");
#endif
        pthread_exit(NULL);
    }
    if (newsca_start_ptr) {
        mtdebug1(WM_SYS_LOGTAG, "Starting Syscollector.");
        w_mutex_lock(&newsca_stop_mutex);
        need_shutdown_wait = true;
        w_mutex_unlock(&newsca_stop_mutex);
        const long max_eps = sys->sync.newsca_max_eps;
        if (0 != max_eps) {
            newsca_sync_max_eps = max_eps;
        }
        // else: if max_eps is 0 (from configuration) let's use the default max_eps value (10)
        wm_newsca_log_config(sys);
#ifndef CLIENT
        // Router providers initialization
        if (router_provider_create_func_ptr){
            if(newsca_handle = router_provider_create_func_ptr("deltas-newsca", true), !newsca_handle) {
                mdebug2("Failed to create router handle for 'newsca'.");
            }

            if (rsync_handle = router_provider_create_func_ptr("rsync-newsca", true), !rsync_handle) {
                mdebug2("Failed to create router handle for 'rsync'.");
            }
        }
#endif // CLIENT
        newsca_start_ptr(sys->interval,
                               wm_newsca_send_diff_message,
                               wm_newsca_send_dbsync_message,
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
        mterror(WM_SYS_LOGTAG, "Can't get newsca_start_ptr.");
        pthread_exit(NULL);
    }
    newsca_sync_message_ptr = NULL;
    newsca_start_ptr = NULL;
    newsca_stop_ptr = NULL;

    if (queue_fd) {
        close(queue_fd);
        queue_fd = 0;
    }

#ifndef CLIENT
    so_free_library(router_module_ptr);
    router_module_ptr = NULL;
#endif // CLIENT

    mtinfo(WM_SYS_LOGTAG, "Module finished.");
    w_mutex_lock(&newsca_stop_mutex);
    w_cond_signal(&newsca_stop_condition);
    w_mutex_unlock(&newsca_stop_mutex);
    return 0;
}

void wm_newsca_destroy(wm_newsca_t *data) {
    w_cond_destroy(&newsca_stop_condition);
    w_mutex_destroy(&newsca_stop_mutex);
    w_mutex_destroy(&newsca_reconnect_mutex);

    free(data);
}

void wm_newsca_stop(__attribute__((unused))wm_newsca_t *data) {
    if (!data->flags.running) {
        // Already stopped
        return;
    }

    data->flags.running = false;

    mtinfo(WM_SYS_LOGTAG, "Stop received for Syscollector.");
    newsca_sync_message_ptr = NULL;
    if (newsca_stop_ptr){
        shutdown_process_started = true;
        newsca_stop_ptr();
    }
    w_mutex_lock(&newsca_stop_mutex);
    if (need_shutdown_wait) {
        w_cond_wait(&newsca_stop_condition, &newsca_stop_mutex);
    }
    w_mutex_unlock(&newsca_stop_mutex);
}

cJSON *wm_newsca_dump(const wm_newsca_t *sys) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sca = cJSON_CreateObject();

    // System provider values
    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sca,"disabled","no"); else cJSON_AddStringToObject(wm_sca,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sca,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sca,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sca,"interval",sys->interval);
    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sca,"network","yes"); else cJSON_AddStringToObject(wm_sca,"network","no");
    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sca,"os","yes"); else cJSON_AddStringToObject(wm_sca,"os","no");
    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sca,"hardware","yes"); else cJSON_AddStringToObject(wm_sca,"hardware","no");
    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sca,"packages","yes"); else cJSON_AddStringToObject(wm_sca,"packages","no");
    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sca,"ports","yes"); else cJSON_AddStringToObject(wm_sca,"ports","no");
    if (sys->flags.allports) cJSON_AddStringToObject(wm_sca,"ports_all","yes"); else cJSON_AddStringToObject(wm_sca,"ports_all","no");
    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sca,"processes","yes"); else cJSON_AddStringToObject(wm_sca,"processes","no");
#ifdef WIN32
    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sca,"hotfixes","yes"); else cJSON_AddStringToObject(wm_sca,"hotfixes","no");
#endif
    // Database synchronization values
    cJSON_AddNumberToObject(wm_sca,"newsca_max_eps",sys->sync.newsca_max_eps);

    cJSON_AddItemToObject(root,"newsca",wm_sca);

    return root;
}

int wm_sca_message(const char *data)
{
    int ret_val = 0;

    if (newsca_sync_message_ptr) {
        ret_val = newsca_sync_message_ptr(data);
    }

    return ret_val;
}
