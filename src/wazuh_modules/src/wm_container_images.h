/*
 * Wazuh Module for Container Image Inventory
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Parses configuration, schedules scans, invokes the extraction library, and
 * logs results. Does not publish inventory state.
 */

#ifndef WM_CONTAINER_IMAGES_H
#define WM_CONTAINER_IMAGES_H

#include "wmodules_def.h"
#include "os_xml.h"

#define WM_CONTAINER_IMAGES_LOGTAG       ARGV0 ":container-images"
#define WM_CONTAINER_IMAGES_DEFAULT_INTERVAL W_HOUR_SECONDS

#define CONTAINER_IMAGES_WM_NAME         "container_images"

extern const wm_context WM_CONTAINER_IMAGES_CONTEXT;

typedef struct wm_container_images_flags_t {
    unsigned int enabled:1;         // Main switch
    unsigned int scan_on_start:1;   // Trigger a scan as soon as the module starts
    unsigned int packages:1;        // Collect package inventory from images
    unsigned int running:1;         // Module is currently running
} wm_container_images_flags_t;

typedef struct wm_container_images_state_t {
    time_t next_time;               // Absolute time for the next scan
} wm_container_images_state_t;

typedef struct wm_container_images_t {
    unsigned int interval;                  // Interval between cycles, in seconds
    wm_container_images_flags_t flags;
    wm_container_images_state_t state;
} wm_container_images_t;

// Parse XML configuration
int wm_container_images_read(const OS_XML *xml, XML_NODE node, wmodule *module);

#endif // WM_CONTAINER_IMAGES_H
