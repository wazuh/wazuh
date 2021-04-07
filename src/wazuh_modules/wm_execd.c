/*
 * Wazuh EXECD
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 5, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include "../../wmodules_def.h"
#include "wmodules.h"
#include "wm_execd.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"

static void* wm_execd_main(wm_execd_t *sys);        // Module main function. It won't return
static void wm_execd_destroy(wm_execd_t *sys);      // Destroy data
const char *WM_EXECD_LOCATION = "execd";            // Location field for event sending
cJSON *wm_execd_dump(const wm_execd_t *sys);
int wm_execd_message(const char *data);

const wm_context WM_EXECD_CONTEXT = {
    "execd",
    (wm_routine)wm_execd_main,
    (wm_routine)(void *)wm_execd_destroy,
    (cJSON * (*)(const void *))wm_execd_dump,
    (int(*)(const char*))wm_execd_message,
};

void *execd_module = NULL;

//int queue_fd = 0;                       // Output queue file descriptor

static void wm_execd_log_config(wm_execd_t *sys) {
    cJSON* config_json = wm_execd_dump(sys);
    if (config_json) {
        char* config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_EXECD_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_execd_main(wm_execd_t *sys) {
    mtdebug1(WM_EXECD_LOGTAG, "Starting Execd.");

    mtinfo(WM_EXECD_LOGTAG, "Module finished.");
    return 0;
}

void wm_execd_destroy(wm_execd_t *data) {
    mtinfo(WM_EXECD_LOGTAG, "Destroy received for Execd.");
    free(data);
}

cJSON *wm_execd_dump(const wm_execd_t *sys) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_execd = cJSON_CreateObject();
    cJSON_AddItemToObject(root,"execd", wm_execd);
    return root;
}

int wm_execd_message(const char *data) {
    int ret_val = 0;
    return ret_val;
}