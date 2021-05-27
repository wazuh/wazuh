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
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 started");
    } else {
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 disabled");
    }

    return NULL;
}

void wm_office365_destroy(wm_office365* office365_config) {
    mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 finished.");
    wm_office365_auth_destroy(office365_config->auth);
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
    cJSON *arr_subscription = cJSON_CreateArray();

    if (office365_config->subscription.azure) {
        cJSON_AddItemToArray(arr_subscription, cJSON_CreateString("Audit.AzureActiveDirectory"));
    }
    if (office365_config->subscription.exchange) {
        cJSON_AddItemToArray(arr_subscription, cJSON_CreateString("Audit.Exchange"));
    }
    if (office365_config->subscription.sharepoint) {
        cJSON_AddItemToArray(arr_subscription, cJSON_CreateString("Audit.SharePoint"));
    }
    if (office365_config->subscription.general) {
        cJSON_AddItemToArray(arr_subscription, cJSON_CreateString("Audit.General"));
    }
    if (office365_config->subscription.dlp) {
        cJSON_AddItemToArray(arr_subscription, cJSON_CreateString("DLP.All"));
    }

    if (cJSON_GetArraySize(arr_subscription) > 0) {
        cJSON_AddItemToObject(wm_info, "subscriptions", arr_subscription);
    } else {
        cJSON_free(arr_subscription);
    }
    cJSON_AddItemToObject(root, "office365", wm_info);

    return root;
}

#endif
