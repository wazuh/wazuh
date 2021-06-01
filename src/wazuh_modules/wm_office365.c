/*
 * Wazuh Module for Office365 events
 * Copyright (C) 2015-2021, Wazuh Inc.
 * May 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#if defined (WIN32) || (__linux__) || defined (__MACH__)

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"

STATIC void* wm_office365_main(wm_office365* office365_config);    // Module main function. It won't return
STATIC void wm_office365_destroy(wm_office365* office365_config);
STATIC void wm_office365_auth_destroy(wm_office365_auth* office365_auth);
STATIC void wm_office365_subscription_destroy(wm_office365_subscription* office365_subscription);
STATIC int wm_office365_execute_scan(wm_office365 *office365_config, int initial_scan);

cJSON *wm_office365_dump(const wm_office365* office365_config);

/* Context definition */
const wm_context WM_OFFICE365_CONTEXT = {
    OFFICE365_WM_NAME,
    (wm_routine)wm_office365_main,
    (wm_routine)(void *)wm_office365_destroy,
    (cJSON * (*)(const void *))wm_office365_dump,
    NULL
};

void * wm_office365_main(wm_office365* office365_config) {

    if (office365_config->enabled) {
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 started.");

#ifndef WIN32
        // Connect to queue
        office365_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (office365_config->queue_fd < 0) {
            mterror(WM_OFFICE365_LOGTAG, "Can't connect to queue. Closing module.");
            return NULL;
        }
#endif

        // Execute initial scan
        wm_office365_execute_scan(office365_config, 1);

        while (1) {
            sleep(office365_config->interval);
            wm_office365_execute_scan(office365_config, 0);
            #ifdef WAZUH_UNIT_TESTING
                break;
            #endif
        }
    } else {
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 disabled.");
    }

    return NULL;
}

void wm_office365_destroy(wm_office365* office365_config) {
    mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 finished.");
    wm_office365_auth_destroy(office365_config->auth);
    wm_office365_subscription_destroy(office365_config->subscription);
    os_free(office365_config);
}

void wm_office365_auth_destroy(wm_office365_auth* office365_auth)
{
    wm_office365_auth* current = office365_auth;
    wm_office365_auth* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->tenant_id);
        os_free(current->client_id);
        os_free(current->client_secret_path);
        os_free(current->client_secret);
        os_free(current);
        current = next;
    }
    office365_auth = NULL;
}

void wm_office365_subscription_destroy(wm_office365_subscription* office365_subscription)
{
    wm_office365_subscription* current = office365_subscription;
    wm_office365_subscription* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->subscription_name);
        os_free(current);
        current = next;
    }
    office365_subscription = NULL;
}

cJSON *wm_office365_dump(const wm_office365* office365_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (office365_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    if (office365_config->only_future_events) {
        cJSON_AddStringToObject(wm_info, "only_future_events", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "only_future_events", "no");
    }
    if (office365_config->interval) {
        cJSON_AddNumberToObject(wm_info, "interval", office365_config->interval);
    }
    if (office365_config->auth) {
        wm_office365_auth *iter;
        cJSON *arr_auth = cJSON_CreateArray();
        for (iter = office365_config->auth; iter; iter = iter->next) {
            cJSON *api_auth = cJSON_CreateObject();
            if (iter->tenant_id) {
                cJSON_AddStringToObject(api_auth, "tenant_id", iter->tenant_id);
            }
            if (iter->client_id) {
                cJSON_AddStringToObject(api_auth, "client_id", iter->client_id);
            }
            if (iter->client_secret_path) {
                cJSON_AddStringToObject(api_auth, "client_secret_path", iter->client_secret_path);
            }
            if (iter->client_secret) {
                cJSON_AddStringToObject(api_auth, "client_secret", iter->client_secret);
            }
            cJSON_AddItemToArray(arr_auth, api_auth);
        }
        if (cJSON_GetArraySize(arr_auth) > 0) {
            cJSON_AddItemToObject(wm_info, "api_auth", arr_auth);
        } else {
            cJSON_free(arr_auth);
        }
    }
    if (office365_config->subscription) {
        wm_office365_subscription *iter;
        cJSON *arr_subscription = cJSON_CreateArray();
        for (iter = office365_config->subscription; iter; iter = iter->next) {
            cJSON_AddItemToArray(arr_subscription, cJSON_CreateString(iter->subscription_name));
        }
        if (cJSON_GetArraySize(arr_subscription) > 0) {
            cJSON_AddItemToObject(wm_info, "subscriptions", arr_subscription);
        } else {
            cJSON_free(arr_subscription);
        }
    }

    cJSON_AddItemToObject(root, "office365", wm_info);

    return root;
}

STATIC int wm_office365_execute_scan(wm_office365 *office365_config, int initial_scan) {
    //char url[OS_SIZE_8192];
    char tenant_state_name[OS_SIZE_1024];
    //char auth_header[PATH_MAX];
    //time_t last_scan_time;
    time_t new_scan_time;
    //curl_response *response;
    wm_office365_state tenant_state_struc;
    wm_office365_auth* next_auth = NULL;
    wm_office365_auth* current_auth = office365_config->auth;

    while (current_auth != NULL)
    {
        next_auth = current_auth->next;

        mtdebug1(WM_OFFICE365_LOGTAG, "Scanning tenant: '%s'", current_auth->tenant_id);

        // TODO: Obtain access token

        wm_office365_subscription* next_subscription = NULL;
        wm_office365_subscription* current_subscription = office365_config->subscription;

        while (current_subscription != NULL)
        {
            next_subscription = current_subscription->next;

            memset(tenant_state_name, '\0', OS_SIZE_1024);
            snprintf(tenant_state_name, OS_SIZE_1024 -1, "%s-%s-%s", WM_OFFICE365_CONTEXT.name, current_auth->tenant_id, current_subscription->subscription_name);

            memset(&tenant_state_struc, 0, sizeof(tenant_state_struc));

            // Load state for tenant
            if (wm_state_io(tenant_state_name, WM_IO_READ, &tenant_state_struc, sizeof(tenant_state_struc)) < 0) {
                memset(&tenant_state_struc, 0, sizeof(tenant_state_struc));
            }

            new_scan_time = time(0);

            if (initial_scan && (!tenant_state_struc.last_log_time || office365_config->only_future_events)) {
                tenant_state_struc.last_log_time = new_scan_time;
                if (wm_state_io(tenant_state_name, WM_IO_WRITE, &tenant_state_struc, sizeof(tenant_state_struc)) < 0) {
                    mterror(WM_OFFICE365_LOGTAG, "Couldn't save running state.");
                }
                current_subscription = next_subscription;
                continue;
            }

            // TODO: Start subscription and get logs

            current_subscription = next_subscription;
        }

        current_auth = next_auth;
    }

    return 0;
}
#endif
