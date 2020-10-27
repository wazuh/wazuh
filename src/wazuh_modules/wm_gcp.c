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
#include "os_net/os_net.h"
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "shared.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

static void* wm_gcp_main(wm_gcp *gcp_config);                        // Module main function. It won't return
static void wm_gcp_run(const wm_gcp *data);                                // Running python script
static void wm_gcp_destroy(wm_gcp *gcp_config);                      // Destroy data
cJSON *wm_gcp_dump(const wm_gcp *gcp_config);                        // Read config

/* Context definition */

const wm_context WM_GCP_CONTEXT = {
    GCP_WM_NAME,
    (wm_routine)wm_gcp_main,
    (wm_routine)(void *)wm_gcp_destroy,
    (cJSON * (*)(const void *))wm_gcp_dump
};

#ifdef WAZUH_UNIT_TESTING
// Replace pthread_exit for testing purposes
#define pthread_exit(a) return a
#endif
// Module main function. It won't return
void* wm_gcp_main(wm_gcp *data) {
    char * timestamp = NULL;
    // If module is disabled, exit
    if (data->enabled) {
        mtinfo(WM_GCP_LOGTAG, "Module started.");
    } else {
        mtinfo(WM_GCP_LOGTAG, "Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(data->scan_config), WM_GCP_LOGTAG, data->pull_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(data->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_GCP_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtdebug1(WM_GCP_LOGTAG, "Starting fetching of logs.");

        wm_gcp_run(data);

        mtdebug1(WM_GCP_LOGTAG, "Fetching logs finished.");
    } while (FOREVER());

    return NULL;
}

#ifdef WAZUH_UNIT_TESTING
/* Replace pthread_exit for testing purposes */
#undef pthread_exit
#define pthread_exit(a) return

__attribute__((weak))
#endif
void wm_gcp_run(const wm_gcp *data) {
    int status;
    char *output = NULL;
    char *command = NULL;

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

    mtdebug1(WM_GCP_LOGTAG, "Launching command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code != 0){
        mterror(WM_GCP_LOGTAG, "Internal error. Exiting...");
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_GCP_LOGTAG, "Command returned exit code %d", status);
        if(status == 1) {
            char * unknown_error_msg = strstr(output,"Unknown error");
            if (unknown_error_msg == NULL)
                mtwarn(WM_GCP_LOGTAG, "Unknown error.");
            else
                mtwarn(WM_GCP_LOGTAG, "%s", unknown_error_msg);
        } else if(status == 2) {
            char * ptr;
            if (ptr = strstr(output, "integration.py: error:"), ptr) {
                ptr += 16;
                mtwarn(WM_GCP_LOGTAG, "Error parsing arguments: %s", ptr);
            } else {
                mtwarn(WM_GCP_LOGTAG, "Error parsing arguments.");
            }
        } else {
            char * ptr;
            if (ptr = strstr(output, "ERROR: "), ptr) {
                ptr += 7;
                mtwarn(WM_GCP_LOGTAG, "%s", ptr);
            } else {
                mtwarn(WM_GCP_LOGTAG, "%s", output);
            }
        }
        mtdebug1(WM_GCP_LOGTAG, "OUTPUT: %s", output);
    }

    char *line;
    char *save_ptr;

    for (line = strtok_r(output, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr)) {
        switch (data->logging) {
            case 0:
                mtinfo(WM_GCP_LOGTAG, "Logging disabled.");
                break;
            case 1:
                if (strstr(line, "- DEBUG -")) {
                    mtdebug1(WM_GCP_LOGTAG, "%s", line);
                } else if (!strstr(line, "- WARNING -") && !strstr(line, "- INFO -")
                && !strstr(line, "- ERROR -") && !strstr(line, "- CRITICAL -")) {
                    mtdebug1(WM_GCP_LOGTAG, "%s", line);
                }
                break;
            case 2:
                if (line = strstr(line, "- INFO -"), line) {
                    mtinfo(WM_GCP_LOGTAG, "%s", line);
                }
                break;
            case 3:
                if (line = strstr(line, "- WARNING -"), line) {
                    mtwarn(WM_GCP_LOGTAG, "%s", line);
                }
                break;
            case 4:
                if (line = strstr(line, "- ERROR -"), line) {
                    mterror(WM_GCP_LOGTAG, "%s", line);
                }
                break;
            case 5:
                if (line = strstr(line, "- CRITICAL -"), line) {
                    mterror(WM_GCP_LOGTAG, "%s", line);
                }
                break;
            default:
                if (line = strstr(line, "- INFO -"), line) {
                    mtinfo(WM_GCP_LOGTAG, "%s", line);
                }
                break;
        }
    }

    os_free(output);
}

void wm_gcp_destroy(wm_gcp * data) {
    os_free(data);
}

cJSON *wm_gcp_dump(const wm_gcp *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "pull_on_start", data->pull_on_start ? "yes" : "no");
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
        case 3:
            cJSON_AddStringToObject(wm_wd, "logging", "warning");
            break;
        case 4:
            cJSON_AddStringToObject(wm_wd, "logging", "error");
            break;
        case 5:
            cJSON_AddStringToObject(wm_wd, "logging", "critical");
            break;
        case 2:
        default:
            cJSON_AddStringToObject(wm_wd, "logging", "info");
            break;
    }

    cJSON_AddItemToObject(root, "gcp-pubsub", wm_wd);

    return root;
}
