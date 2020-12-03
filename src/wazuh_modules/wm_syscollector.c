/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 11, 2020.
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

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void wm_sys_destroy(wm_sys_t *sys);      // Destroy data
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);
int wm_sync_message(const char *data);

const wm_context WM_SYS_CONTEXT = {
    "syscollector",
    (wm_routine)wm_sys_main,
    (wm_routine)(void *)wm_sys_destroy,
    (cJSON * (*)(const void *))wm_sys_dump,
    (int(*)(const char*))wm_sync_message,
};

void *syscollector_module = NULL;
syscollector_start_func syscollector_start_ptr = NULL;
syscollector_stop_func syscollector_stop_ptr = NULL;
syscollector_sync_message_func syscollector_sync_message_ptr = NULL;


int queue_fd = 0;                                   // Output queue file descriptor

void wm_sys_send_message(const void* data) {
    const int eps = 1000000/wm_max_eps;
    wm_sendmsg(eps,queue_fd, data, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
}

void* wm_sys_main(wm_sys_t *sys) 
{
    #ifndef WIN32
    // Connect to socket
    queue_fd = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS);

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
    } else {
        mterror(WM_SYS_LOGTAG, "Can't load syscollector. %s", dlerror());
        pthread_exit(NULL);
    }

    if (syscollector_start_ptr) {
        mtinfo(WM_SYS_LOGTAG, "Starting Syscollector.");
        syscollector_start_ptr(sys->interval,
                               wm_sys_send_message,
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
    }
    
    return 0;
}

void wm_sys_destroy(wm_sys_t *data) 
{
    mtinfo(WM_SYS_LOGTAG, "Destroy received for Syscollector.");
    if (queue_fd) {
        close(queue_fd);
    }

    if (syscollector_stop_ptr){
        syscollector_stop_ptr();
    }

    if (syscollector_module){
        so_free_library(syscollector_module);
    }
    queue_fd = 0;
    syscollector_module = NULL;
    syscollector_start_ptr = NULL;
    syscollector_stop_ptr = NULL;
    syscollector_sync_message_ptr = NULL;
    free(data);
}

cJSON *wm_sys_dump(const wm_sys_t *sys) 
{
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

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