/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "shared.h"

static void* wm_gcp_main(wm_gcp *gcp_config);           // Module main function. It won't return
static void wm_gcp_destroy(wm_gcp *gcp_config);         // Destroy data
cJSON *wm_gcp_dump(const wm_gcp *gcp_config);           // Read config

/* Context definition */

const wm_context WM_GCP_CONTEXT = {
    GCP_WM_NAME,
    (wm_routine)wm_gcp_main,
    (wm_routine)(void *)wm_gcp_destroy,
    (cJSON * (*)(const void *))wm_gcp_dump
};

// Module main function. It won't return
void* wm_gcp_main(wm_gcp *data) {
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }
}

void wm_gcp_destroy(wm_gcp * data) {
    os_free(data);
}

cJSON *wm_gcp_dump(const wm_gcp *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "pull_on_start", data->pull_on_start ? "yes" : "no");
    if (data->interval) cJSON_AddNumberToObject(wm_wd, "interval", data->interval);
    if (data->max_messages) cJSON_AddNumberToObject(wm_wd, "max_messages", data->max_messages);
    if (data->project_id) cJSON_AddStringToObject(wm_wd, "project_id", data->project_id);
    if (data->subscription_name) cJSON_AddStringToObject(wm_wd, "subscription_name", data->subscription_name);
    if (data->credentials_file) cJSON_AddStringToObject(wm_wd, "credentials_file", data->credentials_file);

    switch (data->logging) {
        case 0:
            cJSON_AddStringToObject(wm_wd, "logging", "disabled");
            break;
        case 1:
            cJSON_AddStringToObject(wm_wd, "logging", "debug");
            break;
        case 2:
            cJSON_AddStringToObject(wm_wd, "logging", "trace");
            break;
        case 3:
        default:
            cJSON_AddStringToObject(wm_wd, "logging", "info");
            break;
    }

    cJSON_AddItemToObject(root, "gcp", wm_wd);

    return root;
}
