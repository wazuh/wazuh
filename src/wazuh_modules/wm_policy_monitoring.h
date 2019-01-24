/*
 * Wazuh Module for remote key requests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_POLICY_MONITORING_H
#define WM_POLICY_MONITORING_H

#define WM_POLICY_MONITORING_LOGTAG ARGV0 ":" KEY_WM_NAME

typedef struct wm_policy_monitoring_t {
    int enabled:1;
    int scan_on_start:1;
    char* week_day;
    char* time;
    char** profile;
} wm_policy_monitoring_t;

extern const wm_context WM_POLICY_MONITORING_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_policy_monitoring_read(xml_node **nodes, wmodule *module);

#endif // WM_KEY_REQUEST_H
