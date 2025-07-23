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
#include "wm_exec.h"

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

// Module main function. It won't return
#ifdef WIN32
DWORD WINAPI wm_sca_main(void *arg) {
    wm_sca_t *data = (wm_sca_t *)arg;
#else
void * wm_sca_main(wm_sca_t * data) {
#endif
    // If module is disabled, exit
    if (data->enabled) {
        minfo("New SCA Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (sca_module = so_get_module_handle(SCA_WM_NAME), sca_module)
    {
        minfo("SCA handle acquired.");
        sca_start_ptr = so_get_function_sym(sca_module, "sca_start");
        if (!sca_start_ptr) {
            merror("Failed to get sca_start function pointer");
            pthread_exit(NULL);
        }
        minfo("SCA start function pointer acquired.");
        sca_stop_ptr = so_get_function_sym(sca_module, "sca_stop");
        if (!sca_stop_ptr) {
            merror("Failed to get sca_stop function pointer");
            pthread_exit(NULL);
        }
        minfo("SCA stop function pointer acquired.");
        sca_sync_message_ptr = so_get_function_sym(sca_module, "sca_sync_message");
        if (!sca_sync_message_ptr) {
            merror("Failed to get sca_sync_message function pointer");
            pthread_exit(NULL);
        }
        minfo("SCA sync message function pointer acquired.");
        sca_set_wm_exec_ptr = so_get_function_sym(sca_module, "sca_set_wm_exec");
        if (!sca_set_wm_exec_ptr) {
            merror("Failed to get sca_set_wm_exec function pointer");
            pthread_exit(NULL);
        }
        minfo("SCA set wm_exec function pointer acquired.");
        // Set the wm_exec function pointer in the SCA module
        if (sca_set_wm_exec_ptr) {
            sca_set_wm_exec_ptr(wm_exec);
            minfo("SCA wm_exec function pointer set.");
        }
    } else {
        merror("Can't get SCA module handle.");
        pthread_exit(NULL);
    }

    minfo("Starting SCA module...");

    wm_sca_start(data);
    minfo("SCA module started.");
#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef WIN32
void wm_sca_push_request_win(char * msg){
   
}

#endif

static int wm_sca_start(wm_sca_t *sca) {
    do
    {

    } while(FOREVER());

    return 0;
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {
    os_free(data);
}

cJSON *wm_sca_dump(const wm_sca_t * data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");

    cJSON_AddItemToObject(root,"sca",wm_wd);


    return root;
}
