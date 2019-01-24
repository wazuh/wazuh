/*
 * Wazuh Module for remote key requests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include "shared.h"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void * wm_policy_monitoring_main(wm_policy_monitoring_t * data);   // Module main function. It won't return
static void wm_policy_monitoring_destroy(wm_policy_monitoring_t * data);  // Destroy data
cJSON *wm_policy_monitoring_dump(const wm_policy_monitoring_t * data);     // Read config

const wm_context WM_POLICY_MONITORING_CONTEXT = {
    PM_WM_NAME,
    (wm_routine)wm_policy_monitoring_main,
    (wm_routine)wm_policy_monitoring_destroy,
    (cJSON * (*)(const void *))wm_policy_monitoring_dump
};

typedef enum _request_type{
    W_TYPE_ID,W_TYPE_IP
} _request_type_t;

// Module main function. It won't return
void * wm_policy_monitoring_main(wm_policy_monitoring_t * data) {
    unsigned int i;

    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }
    
    return NULL;
}


// Destroy data
void wm_policy_monitoring_destroy(wm_policy_monitoring_t * data) {
    os_free(data);
}

cJSON *wm_policy_monitoring_dump(const wm_policy_monitoring_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddItemToObject(root,"policy-monitoring",wm_wd);
    return root;
}
