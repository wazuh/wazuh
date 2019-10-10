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
static int wm_gcp_send_event(wm_gcp * data, cJSON *json_event);      // Send event to analysisd
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
    int i;

    // If module is disabled, exit
    if (data->enabled) {
        mtinfo(WM_GCP_LOGTAG, "Module started");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    data->msg_delay = 1000000 / wm_max_eps;

#ifndef WIN32
    for (i = 0; (data->queue = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++){
        wm_delay(1000 * WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        merror("Can't connect to queue.");
    }
#endif

    wm_gcp_run(data);

    return NULL;
}

void wm_gcp_run(wm_gcp *data) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments
    mtdebug2(WM_GCP_LOGTAG, "Create argument list");

    wm_strcat(&command, WM_GCP_SCRIPT_PATH, '\0');

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
        mterror(WM_AWS_LOGTAG, "Internal error. Exiting...");
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    }

    wm_gcp_send_event(data, output);

    os_free(output);
}

static int wm_gcp_send_event(wm_gcp * data, cJSON *json_event) {
    int queue_fd = data->queue;

    char *msg = cJSON_PrintUnformatted(json_event);
    mdebug2("Sending event: %s",msg);

    if (wm_sendmsg(data->msg_delay, queue_fd, msg, WM_GCP_CONTEXT.name, GCP_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        if(data->queue >= 0){
            close(data->queue);
        }

        if ((data->queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            mwarn("Can't connect to queue.");
        } else {
            if(wm_sendmsg(data->msg_delay, data->queue, msg, WM_GCP_CONTEXT.name, GCP_MQ) < 0) {
                merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                close(data->queue);
            }
        }
    }

    os_free(msg);

    return (0);
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
