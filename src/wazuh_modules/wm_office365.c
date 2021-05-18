/*
 * Wazuh Module for Office365 events
 * Copyright (C) 2015-2021, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined (WIN32) || (__linux__) || defined (__MACH__)

#include "wmodules.h"
#include "shared.h"

static void* wm_office365_main(wm_office365* office365_config);    // Module main function. It won't return
static void wm_office365_destroy(wm_office365* office365_config);
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
    mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 finished");
    os_free(office365_config);
}

cJSON *wm_office365_dump(const wm_office365* office365_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (office365_config->enabled) {
        cJSON_AddStringToObject(wm_info,"enabled","yes");
    } else {
        cJSON_AddStringToObject(wm_info,"enabled","no");
    }
    cJSON_AddItemToObject(root,"office365",wm_info);
    return root;
}

#endif
