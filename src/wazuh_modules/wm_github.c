/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2021, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_github.h"

static void* wm_github_main(wm_github* github_config);    // Module main function. It won't return
static void wm_github_destroy(wm_github* github_config);
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
    mtinfo(WM_GITHUB_LOGTAG, "Module GitHub started");
    return NULL;
}

void wm_github_destroy(wm_github* github_config) {
    mtinfo(WM_GITHUB_LOGTAG, "Module GitHub finished");
    os_free(github_config);
}

cJSON *wm_github_dump(const wm_github* github_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (github_config->enabled) {
        cJSON_AddStringToObject(wm_info,"enabled","yes");
    } else {
        cJSON_AddStringToObject(wm_info,"enabled","no");
    }
    cJSON_AddItemToObject(root,"github",wm_info);
    return root;
}
