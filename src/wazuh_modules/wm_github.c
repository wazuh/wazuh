/*
 * Wazuh Module for GitHub logs
 * Copyright (C) 2015-2021, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "shared.h"

static void* wm_github_main(wm_github* github_config);    // Module main function. It won't return
static void wm_github_destroy(wm_github* github_config);
static void wm_github_auth_destroy(wm_github_auth* github_auth);
cJSON *wm_github_dump(const wm_github* github_config);

/* Context definition */
const wm_context WM_GITHUB_CONTEXT = {
    GITHUB_WM_NAME,
    (wm_routine)wm_github_main,
    (wm_routine)(void *)wm_github_destroy,
    (cJSON * (*)(const void *))wm_github_dump,
    NULL
};

void * wm_github_main(wm_github* github_config) {

    if (github_config->enabled) {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub started.");
    } else {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub disabled.");
    }
    return NULL;
}

void wm_github_destroy(wm_github* github_config) {
    mtinfo(WM_GITHUB_LOGTAG, "Module GitHub finished.");
    wm_github_auth_destroy(github_config->auth);
    os_free(github_config->event_type);
    os_free(github_config);
}

void wm_github_auth_destroy(wm_github_auth* github_auth)
{
    wm_github_auth* current = github_auth;
    wm_github_auth* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->api_token);
        os_free(current->org_name);
        os_free(current);
        current = next;
    }
    github_auth = NULL;
}

cJSON *wm_github_dump(const wm_github* github_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (github_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    if (github_config->run_on_start) {
        cJSON_AddStringToObject(wm_info, "run_on_start", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "run_on_start", "no");
    }
    if (github_config->only_future_events) {
        cJSON_AddStringToObject(wm_info, "only_future_events", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "only_future_events", "no");
    }
    if (github_config->interval) {
        cJSON_AddNumberToObject(wm_info, "interval", github_config->interval);
    }
    if (github_config->time_delay) {
        cJSON_AddNumberToObject(wm_info, "time_delay", github_config->time_delay);
    }
    if (github_config->auth) {
        wm_github_auth *iter;
        cJSON *arr_auth = cJSON_CreateArray();
        for (iter = github_config->auth; iter; iter = iter->next) {
            cJSON *api_auth = cJSON_CreateObject();
            if (iter->org_name) {
                cJSON_AddStringToObject(api_auth, "org_name", iter->org_name);
            }
            if (iter->api_token) {
                cJSON_AddStringToObject(api_auth, "api_token", iter->api_token);
            }
            cJSON_AddItemToArray(arr_auth, api_auth);
        }
        if (cJSON_GetArraySize(arr_auth) > 0) {
            cJSON_AddItemToObject(wm_info, "api_auth", arr_auth);
        } else {
            cJSON_free(arr_auth);
        }
    }
    if (github_config->event_type) {
        cJSON_AddStringToObject(wm_info, "event_type", github_config->event_type);
    }
    cJSON_AddItemToObject(root, "github", wm_info);

    return root;
}
