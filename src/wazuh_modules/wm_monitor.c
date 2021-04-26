/*
 * Wazuh MONITOR
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 26, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdlib.h>
#include "../../wmodules_def.h"
#include "wmodules.h"
#include "wm_monitor.h"
#include "defs.h"

static void* wm_monitor_main(wm_monitor_t *data);        // Module main function. It won't return
static void wm_monitor_destroy(wm_monitor_t *data);      // Destroy data
const char *WM_MONITOR_LOCATION = "monitor";            // Location field for event sending
cJSON *wm_monitor_dump(const wm_monitor_t *data);

const wm_context WM_MONITOR_CONTEXT = {
    WM_MONITOR_LOCATION,
    (wm_routine)wm_monitor_main,
    (wm_routine)(void *)wm_monitor_destroy,
    (cJSON * (*)(const void *))wm_monitor_dump,
    NULL,
};

static void wm_monitor_log_config(wm_monitor_t *data)
{
    cJSON * config_json = wm_monitor_dump(data);
    if (config_json) {
        char * config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_MONITOR_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_monitor_main(wm_monitor_t *data) {
    /*/if (!data->flags.enabled) {
        mtinfo(WM_MONITOR_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }*/

    mtinfo(WM_MONITOR_LOGTAG, "Module finished.");

    return 0;
}

void wm_monitor_destroy(wm_monitor_t *data) {
    mtinfo(WM_MONITOR_LOGTAG, "Destroy received for monitor.");

    os_free(data);
}

cJSON *wm_monitor_dump(const wm_monitor_t *data) {
    return NULL;
}
