/*
 * Wazuh Module for Container Image Inventory
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives scheduling, scan_on_start, and a placeholder scan invocation.
 * Disabled by default. Does not publish inventory state.
 */

#ifndef WIN32

#include "wmodules.h"
#include "wm_container_images.h"

static void *wm_container_images_main(wm_container_images_t *data);
static void  wm_container_images_destroy(wm_container_images_t *data);
static cJSON *wm_container_images_dump(const wm_container_images_t *data);
static void  wm_container_images_run_scan(const wm_container_images_t *data);

const wm_context WM_CONTAINER_IMAGES_CONTEXT = {
    .name    = CONTAINER_IMAGES_WM_NAME,
    .start   = (wm_routine)wm_container_images_main,
    .destroy = (void (*)(void *))wm_container_images_destroy,
    .dump    = (cJSON * (*)(const void *))wm_container_images_dump,
    .sync    = NULL,
    .stop    = NULL,
    .query   = NULL,
};

static void *wm_container_images_main(wm_container_images_t *data)
{
    if (!data) {
        return NULL;
    }

    if (!data->flags.enabled) {
        mtinfo(WM_CONTAINER_IMAGES_LOGTAG, "Module disabled. Exiting.");
        return NULL;
    }

    if (!data->interval) {
        data->interval = WM_CONTAINER_IMAGES_DEFAULT_INTERVAL;
    }

    mtinfo(WM_CONTAINER_IMAGES_LOGTAG,
           "Module started. Interval: %us, scan_on_start: %s, packages: %s.",
           data->interval,
           data->flags.scan_on_start ? "yes" : "no",
           data->flags.packages ? "yes" : "no");

    data->flags.running = 1;

    // Decide first scan time
    if (data->flags.scan_on_start) {
        data->state.next_time = time(NULL);
    } else {
        data->state.next_time = time(NULL) + data->interval;
    }

    while (FOREVER() && !wm_shutdown_requested) {
        time_t now = time(NULL);
        if (data->state.next_time > now) {
            mtdebug2(WM_CONTAINER_IMAGES_LOGTAG,
                     "Sleeping %ld seconds until next scan.",
                     (long)(data->state.next_time - now));
            wm_sleep_until_interruptible(data->state.next_time);
            if (wm_shutdown_requested) {
                break;
            }
        }

        if (data->flags.packages) {
            mtinfo(WM_CONTAINER_IMAGES_LOGTAG, "Scan starting.");
            wm_container_images_run_scan(data);
            mtinfo(WM_CONTAINER_IMAGES_LOGTAG, "Scan finished.");
        } else {
            mtinfo(WM_CONTAINER_IMAGES_LOGTAG,
                   "Package inventory disabled. Skipping scan.");
        }

        data->state.next_time = time(NULL) + data->interval;
    }

    data->flags.running = 0;
    mtinfo(WM_CONTAINER_IMAGES_LOGTAG, "Module finished.");
    return NULL;
}

// Placeholder for the scan path. No image sources are configurable yet, so this
// is a no-op that exercises the lifecycle. Source parsing and inventory
// persistence are implemented separately.
static void wm_container_images_run_scan(const wm_container_images_t *data)
{
    (void)data;
    mtdebug1(WM_CONTAINER_IMAGES_LOGTAG,
             "No image sources configured. Skipping scan body.");
}

static cJSON *wm_container_images_dump(const wm_container_images_t *data)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *cfg  = cJSON_CreateObject();

    cJSON_AddStringToObject(cfg, "enabled",       data->flags.enabled       ? "yes" : "no");
    cJSON_AddStringToObject(cfg, "scan_on_start", data->flags.scan_on_start ? "yes" : "no");
    cJSON_AddStringToObject(cfg, "packages",      data->flags.packages      ? "yes" : "no");
    cJSON_AddNumberToObject(cfg, "interval",      data->interval);

    cJSON_AddItemToObject(root, CONTAINER_IMAGES_WM_NAME, cfg);
    return root;
}

static void wm_container_images_destroy(wm_container_images_t *data)
{
    free(data);
}

#endif // WIN32
