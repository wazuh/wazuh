/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_CONTAINER_IMAGES_H
#define WM_CONTAINER_IMAGES_H

#include "wmodules_def.h"
#include "os_xml.h"

extern const wm_context WM_CONTAINER_IMAGES_CONTEXT;     // Context

#define WM_CONTAINER_IMAGES_LOGTAG ARGV0 ":container_images" // Tag for log messages
#define WM_CONTAINER_IMAGES_DEFAULT_INTERVAL W_HOUR_SECONDS

// One configured image source: the reference entry type and the value it holds.
typedef struct wm_container_images_reference_t {
    char *type;                         // Entry type: "ref", "archive" or "local"
    char *value;                        // Path or image reference
} wm_container_images_reference_t;

typedef struct wm_container_images_t {
    unsigned int enabled:1;             // Main switch
    unsigned int scan_on_start:1;       // Scan on module start
    unsigned int interval;              // Time interval between scans (seconds)
    wm_container_images_reference_t *references; // Configured image sources
    int references_count;               // Number of configured image sources
} wm_container_images_t;

// Parse XML configuration
int wm_container_images_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_CONTAINER_IMAGES_H
