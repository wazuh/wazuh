/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_SCA_H
#define WM_SCA_H

#include "../os_xml/os_xml.h"
#include "wmodules_def.h"
#include "schedule_scan.h"

#define WM_SCA_LOGTAG ARGV0 ":sca"

typedef struct wm_sca_policy_t {
    unsigned int enabled:1;
    unsigned int remote:1;
    char *policy_path;
    char *policy_id;
    char *policy_regex_type;
} wm_sca_policy_t;

typedef struct wm_sca_db_sync_flags_t {
    unsigned int enable_synchronization:1;  // Enable database synchronization
    uint32_t sync_interval;                 // Synchronization interval
    uint32_t sync_response_timeout;         // Minimum interval for the synchronization process
    long sync_max_eps;                      // Maximum events per second for synchronization messages.
} wm_sca_db_sync_flags_t;

typedef struct wm_sca_t {
    int enabled;
    int scan_on_start;
    int max_eps;
    wm_sca_policy_t** policies;
    int remote_commands:1;
    int commands_timeout;
    sched_scan_config scan_config;
    wm_sca_db_sync_flags_t sync;
} wm_sca_t;

extern const wm_context WM_SCA_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_sca_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_SCA_H
