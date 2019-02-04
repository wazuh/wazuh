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

#define WM_POLICY_MONITORING_LOGTAG ARGV0 ":" PM_WM_NAME
#define WM_POLICY_MONITORING_INVALID_RKCL_VAR   "(1254): Invalid pm variable: '%s'."
#define WM_POLICY_MONITORING_INVALID_RKCL_NAME  "(1251): Invalid pm configuration name: '%s'."
#define WM_POLICY_MONITORING_INVALID_RKCL_VALUE "(1252): Invalid pm configuration value: '%s'."
#define WM_POLICY_MONITORING_INVALID_ROOTDIR    "(1253): Invalid rootdir (unable to retrieve)."
#define WM_POLICY_MONITORING_INVALID_RKCL_VAR   "(1254): Invalid pm variable: '%s'."

#define WM_POLICY_MONITORING_ALERT_POLICY_VIOLATION  4

/* Types of values */
#define WM_POLICY_MONITORING_TYPE_FILE      1
#define WM_POLICY_MONITORING_TYPE_REGISTRY  2
#define WM_POLICY_MONITORING_TYPE_PROCESS   3
#define WM_POLICY_MONITORING_TYPE_DIR       4

#define WM_POLICY_MONITORING_COND_ALL       0x001
#define WM_POLICY_MONITORING_COND_ANY       0x002
#define WM_POLICY_MONITORING_COND_REQ       0x004
#define WM_POLICY_MONITORING_COND_NON       0x008
#define WM_POLICY_MONITORING_COND_INV       0x016
#define WM_POLICY_MONITORING_STAMP          "policy-monitoring"

#ifdef WIN32
HKEY wm_policy_monitoring_sub_tree;
#endif

typedef struct wm_policy_monitoring_t {
    int enabled:1;
    int scan_on_start:1;
    int skip_nfs:1;
    unsigned int interval;          
    int scan_day;                   
    int scan_wday;
    time_t next_time;               
    char* scan_time;
    char** profile;
    char **alert_msg;
    int queue;
} wm_policy_monitoring_t;

extern const wm_context WM_POLICY_MONITORING_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_policy_monitoring_read(xml_node **nodes, wmodule *module);

#endif // WM_KEY_REQUEST_H
