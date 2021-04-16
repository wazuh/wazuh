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
#include "os_execd/execd.h"
#include "wmodules.h"
#include "wm_execd.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"
#include "../os_net/os_net.h"

static void* wm_execd_main(wm_execd_t *data);        // Module main function. It won't return
static void wm_execd_destroy(wm_execd_t *data);      // Destroy data
const char *WM_EXECD_LOCATION = "execd";             // Location field for event sending
cJSON *wm_execd_dump(const wm_execd_t *data);
int wm_execd_message(const char *data);

const wm_context WM_EXECD_CONTEXT = {
    "execd",
    (wm_routine)wm_execd_main,
    (wm_routine)(void *)wm_execd_destroy,
    (cJSON * (*)(const void *))wm_execd_dump,
    NULL,
};

void *execd_module = NULL;

static void wm_execd_log_config(wm_execd_t *data) {
    cJSON* config_json = wm_execd_dump(data);
    if (config_json) {
        char* config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_EXECD_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_execd_main(wm_execd_t *data) {
    mtdebug1(WM_EXECD_LOGTAG, "Starting Execd.");

    wm_execd_log_config(data);

#ifdef WIN32
    w_queue_t *winexec_queue = queue_init(OS_SIZE_128);
    while(1) {
        win_execd_run(queue_pop_ex(winexec_queue));
    }
    queue_free(winexec_queue);
#else
    int queue = 0;
    // Start exec queue
    if ((queue = StartMQ(EXECQUEUE, READ, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_ERROR, EXECQUEUE, strerror(errno));
    }

    int queue_health_status = 0;
    // Connect wazuh health status checks.
    if ((queue_health_status = StartMQ(WMODULES_HSTATUS_QUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_ERROR, WMODULES_HSTATUS_QUEUE, strerror(errno));
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "operation", "initialization");
    cJSON_AddStringToObject(root, "wmodule", WM_EXECD_CONTEXT.name);
    char* raw_message_health_status = cJSON_PrintUnformatted(root);

    if (raw_message_health_status) {
        if (queue_health_status >= 0) {
            if (OS_SendUnix(queue_health_status, raw_message_health_status, 0) < 0) {
                merror("Error communicating with execd");
            }
        }
        cJSON_free(raw_message_health_status);
    }
    cJSON_Delete(root);

    // The real daemon Now
    execd_start(queue);

    if (queue) {
        close(queue);
        queue = 0;
    }

    if (queue_health_status) {
        close(queue_health_status);
        queue_health_status = 0;
    }
#endif // WIN32
    mtinfo(WM_EXECD_LOGTAG, "Module finished.");
    return 0;
}

void wm_execd_destroy(wm_execd_t *data) {
    execd_shutdown();
    os_free(data);
}

cJSON *wm_execd_dump(__attribute__((unused)) const wm_execd_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "ARConfig", get_ar_config());
    cJSON_AddItemToObject(root, "ExecdInternalOptions", get_execd_internal_options());
    return root;
}
