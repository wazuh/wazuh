/*
 * Wazuh Module for Azure integration
 * Copyright (C) 2018 Wazuh Inc.
 * September, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#ifndef CLIENT

#include "wmodules.h"
#include "wm_azure.h"

static wm_azure_t *azure_config;                               // Pointer to Azure-logs configuration
static int queue_fd;                                           // Output queue file descriptor
static unsigned int default_timeout;                           // Default timeout for every query

static void* wm_azure_main(wm_azure_t *azure_config);          // Module main function. It won't return
static void wm_azure_setup(wm_azure_t *_azure_config);           // Setup module
static void wm_azure_cleanup();                                  // Cleanup function, doesn't overwrite wm_cleanup
static void wm_azure_check();         // Check configuration
static void wm_azure_destroy(wm_azure_t *azure_config);        // Destroy data

static void wm_azure_log_analytics(wm_azure_api_t *log_analytics);      // Run log analytics queries
static void wm_azure_graphs(wm_azure_api_t *graph);                     // Run graph queries
static void wm_azure_storage(wm_azure_storage_t *storage);              // Run storage queries

//  Azure module context definition

const wm_context WM_AZURE_CONTEXT = {
    "azure-logs",
    (wm_routine)wm_azure_main,
    (wm_routine)wm_azure_destroy
};

// Module main function. It won't return.

void* wm_azure_main(wm_azure_t *azure_config) {

    time_t time_start;
    time_t time_sleep = 0;
    wm_azure_api_t *curr_api;
    wm_azure_storage_t *curr_storage;
    char msg[OS_SIZE_6144];
    int status = 0;

    wm_azure_setup(azure_config);
    mtinfo(WM_AZURE_LOGTAG, "Module started.");

    // First sleeping

    if (!azure_config->flags.run_on_start) {
        time_start = time(NULL);

        if (azure_config->scan_day) {
            do {
                status = check_day_to_scan(azure_config->scan_day, azure_config->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(azure_config->scan_time);
                } else {
                    wm_delay(1000); // Sleep one second to avoid an infinite loop
                    time_sleep = get_time_to_hour("00:00");
                }

                mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while (status < 0);

        } else if (azure_config->scan_wday >= 0) {

            time_sleep = get_time_to_day(azure_config->scan_wday, azure_config->scan_time);
            mtinfo(WM_AZURE_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (azure_config->scan_time) {

            time_sleep = get_time_to_hour(azure_config->scan_time);
            mtinfo(WM_AZURE_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (azure_config->state.next_time > time_start) {

            mtinfo(WM_AZURE_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %ld seconds", (long)(azure_config->state.next_time - time_start));
            wm_delay(1000 * azure_config->state.next_time - time_start);

        }
    }

    // Main loop

    while (1) {

        mtinfo(WM_AZURE_LOGTAG, "Starting fetching of logs.");

        snprintf(msg, OS_SIZE_6144, "Starting Azure-logs scan.");
        SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

        // Get time and execute
        time_start = time(NULL);

        for (curr_api = azure_config->api_config; curr_api; curr_api = curr_api->next) {
            if (curr_api->type == LOG_ANALYTICS) {
                mtinfo(WM_AZURE_LOGTAG, "Starting Log Analytics collection for the domain '%s'.", curr_api->tenantdomain);
                wm_azure_log_analytics(curr_api);
            } else if (curr_api->type == GRAPHS) {
                mtinfo(WM_AZURE_LOGTAG, "Starting Graphs log collection for the domain '%s'.", curr_api->tenantdomain);
                wm_azure_graphs(curr_api);
            }
        }

        for (curr_storage = azure_config->storage; curr_storage; curr_storage = curr_storage->next) {
            mtinfo(WM_AZURE_LOGTAG, "Starting Storage log collection for '%s'.", curr_storage->tag);
            wm_azure_storage(curr_storage);
        }

        snprintf(msg, OS_SIZE_6144, "Ending Azure-logs scan.");
        SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

        mtinfo(WM_AZURE_LOGTAG, "Fetching logs finished.");

        time_sleep = time(NULL) - time_start;

        if (azure_config->scan_day) {
            int interval = 0, i = 0;
            status = 0;
            interval = azure_config->interval / 60;   // interval in num of months

            do {
                status = check_day_to_scan(azure_config->scan_day, azure_config->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(azure_config->scan_time);
                    i++;
                } else {
                    wm_delay(1000);
                    time_sleep = get_time_to_hour("00:00");     // Sleep until the start of the next day
                }

                mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while ((status < 0) && (i < interval));

        } else {

            if (azure_config->scan_wday >= 0) {
                time_sleep = get_time_to_day(azure_config->scan_wday, azure_config->scan_time);
                time_sleep += WEEK_SEC * ((azure_config->interval / WEEK_SEC) - 1);
                azure_config->state.next_time = (time_t)time_sleep + time_start;
            } else if (azure_config->scan_time) {
                time_sleep = get_time_to_hour(azure_config->scan_time);
                time_sleep += DAY_SEC * ((azure_config->interval / DAY_SEC) - 1);
                azure_config->state.next_time = (time_t)time_sleep + time_start;
            } else if ((time_t)azure_config->interval >= time_sleep) {
                time_sleep = azure_config->interval - time_sleep;
                azure_config->state.next_time = azure_config->interval + time_start;
            } else {
                mterror(WM_AZURE_LOGTAG, "Interval overtaken.");
                time_sleep = azure_config->state.next_time = 0;
            }

            if (wm_state_io(WM_AZURE_CONTEXT.name, WM_IO_WRITE, &azure_config->state, sizeof(azure_config->state)) < 0)
                mterror(WM_AZURE_LOGTAG, "Couldn't save running state.");

            mtdebug2(WM_AZURE_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);
        }
    }

    return NULL;
}

void wm_azure_log_analytics(wm_azure_api_t *log_analytics) {

    wm_azure_request_t * curr_request;
    char query[OS_SIZE_1024];
    int status;
    unsigned int timeout;

    for (curr_request = log_analytics->request; curr_request; curr_request = curr_request->next) {

        char * command;
        char * output;

        // Create argument list
        mtdebug2(WM_AZURE_LOGTAG, "Creating argument list.");

        wm_strcat(&command, WM_AZURE_SCRIPT_PATH, '\0');
        wm_strcat(&command, "--log-analytics", ' ');

        if (log_analytics->auth_path) {
            wm_strcat(&command, "--la_auth_path", ' ');
            wm_strcat(&command, log_analytics->auth_path, ' ');
        } else {
            wm_strcat(&command, "--la_id", ' ');
            wm_strcat(&command, log_analytics->application_id, ' ');
            wm_strcat(&command, "--la_key", ' ');
            wm_strcat(&command, log_analytics->application_key, ' ');
        }

        wm_strcat(&command, "--la_tenant_domain", ' ');
        wm_strcat(&command, log_analytics->tenantdomain, ' ');

        wm_strcat(&command, "--la_tag", ' ');
        wm_strcat(&command, curr_request->tag, ' ');

        wm_strcat(&command, "--la_query", ' ');
        snprintf(query, OS_SIZE_1024 - 1, "\'%s\'", curr_request->query);
        wm_strcat(&command, query, ' ');

        wm_strcat(&command, "--workspace", ' ');
        wm_strcat(&command, curr_request->workspace, ' ');

        wm_strcat(&command, "--la_time_offset", ' ');
        wm_strcat(&command, curr_request->time_offset, ' ');

        // Check timeout defined
        if (curr_request->timeout)
            timeout = curr_request->timeout;
        else
            timeout = default_timeout;

        // Run script
        mtdebug1(WM_AZURE_LOGTAG, "Launching command: %s", command);
        switch (wm_exec(command, &output, &status, timeout)) {
            case 0:
                if (status > 0) {
                    mtwarn(WM_AZURE_LOGTAG, "%s: Returned error code: '%d'.", curr_request->tag, status);
                    mtdebug2(WM_AZURE_LOGTAG, "OUTPUT: %s", output);
                }
                break;
            case WM_ERROR_TIMEOUT:
                mterror(WM_AZURE_LOGTAG, "Timeout expired at request '%s'.", curr_request->tag);
                break;

            default:
                mterror(WM_AZURE_LOGTAG, "Internal calling. Exiting...");
                pthread_exit(NULL);
        }

        mtinfo(WM_AZURE_LOGTAG, "Finished Log Analytics collection for the domain '%s'.", log_analytics->tenantdomain);

        free(command);
        free(output);
    }
}

void wm_azure_graphs(wm_azure_api_t *graph) {

    wm_azure_request_t * curr_request;
    char query[OS_SIZE_1024];
    int status;
    unsigned int timeout;

    for (curr_request = graph->request; curr_request; curr_request = curr_request->next) {

        char * command;
        char * output;

        // Create argument list
        mtdebug2(WM_AZURE_LOGTAG, "Creating argument list.");

        wm_strcat(&command, WM_AZURE_SCRIPT_PATH, '\0');
        wm_strcat(&command, "--graph", ' ');

        if (graph->auth_path) {
            wm_strcat(&command, "--graph_auth_path", ' ');
            wm_strcat(&command, graph->auth_path, ' ');
        } else {
            wm_strcat(&command, "--graph_id", ' ');
            wm_strcat(&command, graph->application_id, ' ');
            wm_strcat(&command, "--graph_key", ' ');
            wm_strcat(&command, graph->application_key, ' ');
        }

        wm_strcat(&command, "--graph_tenant_domain", ' ');
        wm_strcat(&command, graph->tenantdomain, ' ');

        wm_strcat(&command, "--graph_tag", ' ');
        wm_strcat(&command, curr_request->tag, ' ');

        wm_strcat(&command, "--graph_query", ' ');
        snprintf(query, OS_SIZE_1024 - 1, "\'%s\'", curr_request->query);
        wm_strcat(&command, query, ' ');

        wm_strcat(&command, "--graph_time_offset", ' ');
        wm_strcat(&command, curr_request->time_offset, ' ');

        // Check timeout defined
        if (curr_request->timeout)
            timeout = curr_request->timeout;
        else
            timeout = default_timeout;

        // Run script
        mtdebug1(WM_AZURE_LOGTAG, "Launching command: %s", command);
        switch (wm_exec(command, &output, &status, timeout)) {
            case 0:
                if (status > 0) {
                    mtwarn(WM_AZURE_LOGTAG, "%s: Returned error code: '%d'.", curr_request->tag, status);
                    mtdebug2(WM_AZURE_LOGTAG, "OUTPUT: %s", output);
                }
                break;
            case WM_ERROR_TIMEOUT:
                mterror(WM_AZURE_LOGTAG, "Timeout expired at request '%s'.", curr_request->tag);
                break;

            default:
                mterror(WM_AZURE_LOGTAG, "Internal calling. Exiting...");
                pthread_exit(NULL);
        }

        mtinfo(WM_AZURE_LOGTAG, "Finished Graphs log collection for the domain '%s'.", graph->tenantdomain);

        free(command);
        free(output);
    }
}

void wm_azure_storage(wm_azure_storage_t *storage) {

    wm_azure_container_t * curr_container;
    char name[OS_SIZE_256];
    char blobs[OS_SIZE_256];
    int status;
    unsigned int timeout;

    for (curr_container = storage->container; curr_container; curr_container = curr_container->next) {

        char * command;
        char * output;

        // Create argument list
        mtdebug2(WM_AZURE_LOGTAG, "Creating argument list.");

        wm_strcat(&command, WM_AZURE_SCRIPT_PATH, '\0');
        wm_strcat(&command, "--storage", ' ');

        if (storage->auth_path) {
            wm_strcat(&command, "--storage_auth_path", ' ');
            wm_strcat(&command, storage->auth_path, ' ');
        } else {
            wm_strcat(&command, "--account_name", ' ');
            wm_strcat(&command, storage->account_name, ' ');
            wm_strcat(&command, "--account_key", ' ');
            wm_strcat(&command, storage->account_key, ' ');
        }

        wm_strcat(&command, "--container", ' ');
        snprintf(name, OS_SIZE_256 - 1, "\'%s\'", curr_container->name);
        wm_strcat(&command, name, ' ');

        wm_strcat(&command, "--blobs", ' ');
        snprintf(blobs, OS_SIZE_256 - 1, "\'%s\'", curr_container->blobs);
        wm_strcat(&command, blobs, ' ');

        wm_strcat(&command, "--storage_tag", ' ');
        wm_strcat(&command, storage->tag, ' ');

        if (!strncmp(curr_container->content_type, "file", 4)) {
            wm_strcat(&command, "--json_file", ' ');
        } else if (!strncmp(curr_container->content_type, "inline", 6)) {
            wm_strcat(&command, "--json_inline", ' ');
        }

        wm_strcat(&command, "--storage_time_offset", ' ');
        wm_strcat(&command, curr_container->time_offset, ' ');

        // Check timeout defined
        if (curr_container->timeout)
            timeout = curr_container->timeout;
        else
            timeout = default_timeout;

        // Run script
        mtdebug1(WM_AZURE_LOGTAG, "Launching command: %s", command);
        switch (wm_exec(command, &output, &status, timeout)) {
            case 0:
                if (status > 0) {
                    mtwarn(WM_AZURE_LOGTAG, "%s: Returned error code: '%d'.", curr_container->name, status);
                    mtdebug2(WM_AZURE_LOGTAG, "OUTPUT: %s", output);
                }
                break;
            case WM_ERROR_TIMEOUT:
                mterror(WM_AZURE_LOGTAG, "Timeout expired at request '%s'.", curr_container->name);
                break;

            default:
                mterror(WM_AZURE_LOGTAG, "Internal calling. Exiting...");
                pthread_exit(NULL);
        }

        mtinfo(WM_AZURE_LOGTAG, "Finished Storage log collection for '%s'.", curr_container->name);

        free(command);
        free(output);
    }
}

// Setup module

void wm_azure_setup(wm_azure_t *_azure_config) {

    int i;
    azure_config = _azure_config;
    wm_azure_check();

    // Read running state

    if (wm_state_io(WM_AZURE_CONTEXT.name, WM_IO_READ, &azure_config->state, sizeof(azure_config->state)) < 0)
        memset(&azure_config->state, 0, sizeof(azure_config->state));

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        sleep(WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_AZURE_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_azure_cleanup);
}

// Check configuration

void wm_azure_check() {

    // Check if disabled
    if (!azure_config->flags.enabled) {
        mtinfo(WM_AZURE_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if necessary configuration is defined

    if (!azure_config->api_config && !azure_config->storage) {
        mtwarn(WM_AZURE_LOGTAG, "No API (log_analytics, graph or storage) defined. Exiting...");
        pthread_exit(NULL);
    }

    // Set default timeout
    default_timeout = azure_config->timeout;

}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_azure_cleanup() {
    close(queue_fd);
    mtinfo(WM_AZURE_LOGTAG, "Module finished.");
}

// Destroy data

void wm_azure_destroy(wm_azure_t *azure_config) {

    wm_azure_api_t *curr_api = NULL;
    wm_azure_api_t *next_api = NULL;
    wm_azure_storage_t *curr_storage = NULL;
    wm_azure_storage_t *next_storage = NULL;

    for (curr_api = azure_config->api_config; curr_api; curr_api = next_api) {

        next_api = curr_api->next;
        free(curr_api->tenantdomain);
        if (curr_api->application_id)
            free(curr_api->application_id);
        if (curr_api->application_key)
            free(curr_api->application_key);
        if (curr_api->auth_path)
            free(curr_api->auth_path);

        wm_azure_request_t *curr_request = NULL;
        wm_azure_request_t *next_request = NULL;

        for (curr_request = curr_api->request; curr_request; curr_request = next_request) {

            next_request = curr_request->next;
            free(curr_request->tag);
            free(curr_request->query);
            free(curr_request->time_offset);
            if (curr_api->type == LOG_ANALYTICS)
                free(curr_request->workspace);

            free(curr_request);
        }

        free(curr_api);
    }

    for (curr_storage = azure_config->storage; curr_storage; curr_storage = next_storage) {

        next_storage = curr_storage->next;
        free(curr_storage->tag);
        if (curr_storage->account_name)
            free(curr_storage->account_name);
        if (curr_storage->account_key)
            free(curr_storage->account_key);
        if (curr_storage->auth_path)
            free(curr_storage->auth_path);

        wm_azure_container_t *curr_container = NULL;
        wm_azure_container_t *next_container = NULL;

        for (curr_container = curr_storage->container; curr_container; curr_container = next_container) {

            next_container = curr_container->next;
            free(curr_container->name);
            free(curr_container->blobs);
            free(curr_container->content_type);
            free(curr_container->time_offset);
            free(curr_container);

        }

        free(curr_storage);
    }

    free(azure_config);
}

#endif
#endif
