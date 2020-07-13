/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wm_task_manager_db.h"

static void wm_task_manager_init(wm_task_manager *task_config);
static void* wm_task_manager_main(wm_task_manager* task_config);    // Module main function. It won't return
static void wm_task_manager_destroy(wm_task_manager* task_config);
static cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

/* Context definition */
const wm_context WM_TASK_MANAGER_CONTEXT = {
    TASK_MANAGER_WM_NAME,
    (wm_routine)wm_task_manager_main,
    (wm_routine)(void *)wm_task_manager_destroy,
    (cJSON * (*)(const void *))wm_task_manager_dump
};

void wm_task_manager_init(wm_task_manager *task_config) {
    // Check if module is enabled
    if (!task_config->enabled) {
        mtinfo(WM_TASK_MANAGER_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check or create tasks DB
    if (wm_task_manager_check_db(TASKS_DB, schema_task_manager_sql)) {
        mterror(WM_TASK_MANAGER_LOGTAG, "DB integrity is invalid. Exiting...");
        pthread_exit(NULL);
    }
}

void * wm_task_manager_main(wm_task_manager* task_config) {
    wm_task_manager_init(task_config);

    mtinfo(WM_TASK_MANAGER_LOGTAG, "Module Task Manager started.");

    while (1) {
        // Main loop
    }

    return NULL;
}

void wm_task_manager_destroy(wm_task_manager* task_config) {
    mtinfo(WM_TASK_MANAGER_LOGTAG, "Module Task Manager finished.");
    os_free(task_config);
}

cJSON *wm_task_manager_dump(const wm_task_manager* task_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (task_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes"); 
    } else { 
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    cJSON_AddItemToObject(root, "task-manager", wm_info);

    return root;
}

#endif
