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

static void* wm_gcp_main(wm_gcp *gcp_config);                        // Module main function. It won't return
void wm_gcp_run(wm_gcp *data);                                       // Running python script
static void wm_gcp_destroy(wm_gcp *gcp_config);                      // Destroy data
cJSON *wm_gcp_dump(const wm_gcp *gcp_config);                        // Read config

/* Context definition */

const wm_context WM_GCP_CONTEXT = {
    GCP_WM_NAME,
    (wm_routine)wm_gcp_main,
    (wm_routine)(void *)wm_gcp_destroy,
    (cJSON * (*)(const void *))wm_gcp_dump
};

// Module main function. It won't return
void* wm_gcp_main(wm_gcp *data) {
    time_t time_start;
    time_t time_sleep = 0;

    // If module is disabled, exit
    if (data->enabled) {
        mtinfo(WM_GCP_LOGTAG, "Module started");
    } else {
        mtinfo(WM_GCP_LOGTAG, "Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (!data->pull_on_start) {
        time_start = time(NULL);

        // On first run, take into account the interval of time specified
        if (data->time_interval == 0) {
            data->time_interval = time_start + data->interval;
        }

        if (data->time_interval > time_start) {
            mtinfo(WM_GCP_LOGTAG, "Waiting interval to start fetching.");
            time_sleep = data->time_interval - time_start;
            wm_delay(1000 * time_sleep);
        }
    }

    while (1) {
        mtdebug1(WM_GCP_LOGTAG, "Starting fetching of logs.");

        // Get time and execute
        time_start = time(NULL);

        wm_gcp_run(data);

        mtdebug1(WM_GCP_LOGTAG, "Fetching logs finished.");

        if (data->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)data->interval >= time_sleep) {
                time_sleep = data->interval - time_sleep;
                data->time_interval = data->interval + time_start;
            } else {
                mtwarn(WM_GCP_LOGTAG, "Interval overtaken.");
                time_sleep = data->time_interval = 0;
            }
        }

        // If time_sleep=0, yield CPU
        wm_delay(1000 * time_sleep);
    }

    return NULL;
}

void wm_gcp_run(wm_gcp *data) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Create arguments
    mtdebug2(WM_GCP_LOGTAG, "Create argument list");

    wm_strcat(&command, "python3 ", ' ');
    wm_strcat(&command, WM_GCP_DEFAULT_DIR, '\0');

    if (data->project_id) {
        wm_strcat(&command, "--project", ' ');
        wm_strcat(&command, data->project_id, ' ');
    }
    if (data->subscription_name) {
        wm_strcat(&command, "--subscription_id", ' ');
        wm_strcat(&command, data->subscription_name, ' ');
    }
    if (data->credentials_file) {
        wm_strcat(&command, "--credentials_file", ' ');
        wm_strcat(&command, data->credentials_file, ' ');
    }

    if (data->max_messages) {
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", data->max_messages);
        wm_strcat(&command, "--max_messages", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }
    if (data->logging) {
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", data->logging);
        wm_strcat(&command, "--log_level", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }

    // Execute

    mtinfo(WM_GCP_LOGTAG, "Launching command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code != 0){
        mterror(WM_GCP_LOGTAG, "Internal error. Exiting...");
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    }

    os_free(output);
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
