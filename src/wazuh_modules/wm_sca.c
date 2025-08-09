/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #include "../../wmodules_def.h"
#include "wmodules.h"
#include <os_net/os_net.h>
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "expression.h"
#include "shared.h"
#include "sym_load.h"
#include "logging_helper.h"

#include "sca.h"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

#ifdef WIN32
static DWORD WINAPI wm_sca_main(void *arg);         // Module main function. It won't return
#else
static void * wm_sca_main(wm_sca_t * data);   // Module main function. It won't return
#endif
static void wm_sca_destroy(wm_sca_t * data);  // Destroy data
static int wm_sca_start(wm_sca_t * data);  // Start

cJSON *wm_sca_dump(const wm_sca_t * data);     // Read config

const wm_context WM_SCA_CONTEXT = {
    .name = SCA_WM_NAME,
    .start = (wm_routine)wm_sca_main,
    .destroy = (void(*)(void *))wm_sca_destroy,
    .dump = (cJSON * (*)(const void *))wm_sca_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

void *sca_module = NULL;
sca_start_func sca_start_ptr = NULL;
sca_stop_func sca_stop_ptr = NULL;
sca_sync_message_func sca_sync_message_ptr = NULL;
sca_set_wm_exec_func sca_set_wm_exec_ptr = NULL;

// Logging callback function for SCA module
static void sca_log_callback(const modules_log_level_t level, const char* log, const char* tag) {
    switch(level) {
        case LOG_DEBUG:
            mdebug1("%s", log);
            break;
        case LOG_INFO:
            minfo("%s", log);
            break;
        case LOG_WARNING:
            mwarn("%s", log);
            break;
        case LOG_ERROR:
            merror("%s", log);
            break;
        default:
            minfo("%s", log);
            break;
    }
}

// Module main function. It won't return
#ifdef WIN32
DWORD WINAPI wm_sca_main(void *arg) {
    wm_sca_t *data = (wm_sca_t *)arg;
#else
void * wm_sca_main(wm_sca_t * data) {
#endif
    // If module is disabled, exit
    if (data->enabled) {
        minfo("SCA module enabled.");
    } else {
        minfo("SCA module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (sca_module = so_get_module_handle(SCA_WM_NAME), sca_module)
    {
        sca_start_ptr = so_get_function_sym(sca_module, "sca_start");
        sca_stop_ptr = so_get_function_sym(sca_module, "sca_stop");
        sca_sync_message_ptr = so_get_function_sym(sca_module, "sca_sync_message");
        sca_set_wm_exec_ptr = so_get_function_sym(sca_module, "sca_set_wm_exec");

        // Set the wm_exec function pointer in the SCA module
        if (sca_set_wm_exec_ptr) {
            sca_set_wm_exec_ptr(wm_exec);
        }
    } else {
        merror("Can't get SCA module handle.");
        pthread_exit(NULL);
    }

    data->commands_timeout = getDefine_Int("sca", "commands_timeout", 1, 300);
#ifdef CLIENT
    data->remote_commands = getDefine_Int("sca", "remote_commands", 0, 1);
#else
    data->remote_commands = 1;  // Only agents require this setting. For manager it's always enabled.
#endif

    minfo("Starting SCA module...");

    wm_sca_start(data);

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static int wm_sca_start(wm_sca_t *sca) {
    sca_start_ptr(sca_log_callback, sca);
    return 0;
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {

    sca_stop_ptr();

    if (data) {
        os_free(data);
    }
}

cJSON *wm_sca_dump(const wm_sca_t * data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");

    if (data->policies && *data->policies) {
        cJSON *policies = cJSON_CreateArray();
        int i;
        for (i=0;data->policies[i];i++) {
            if(data->policies[i]->enabled == 1){
                cJSON_AddStringToObject(policies, "policy", data->policies[i]->policy_path);
            }
        }
        cJSON_AddItemToObject(wm_wd,"policies", policies);
    }

    cJSON_AddItemToObject(root,"sca",wm_wd);


    return root;
}
