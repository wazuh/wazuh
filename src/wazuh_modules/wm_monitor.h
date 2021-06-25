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

#include "wmodules_def.h"
#include "os_xml/os_xml.h"
#include "../monitord/monitord.h"

#ifndef WM_MONITOR
#define WM_MONITOR

extern const wm_context WM_MONITOR_CONTEXT; // Context

typedef struct wm_monitor_t {
    monitor_config *mond;
    bool *worker_node;
    OSHash *agents_to_alert_hash;
    monitor_time_control *mond_time_control;
} wm_monitor_t;

// Parse XML configuration
int wm_monitor_read(const OS_XML *xml, XML_NODE node, wmodule *module);

#endif
