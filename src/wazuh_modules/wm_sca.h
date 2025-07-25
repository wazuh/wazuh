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

typedef struct wm_sca_t {
    int enabled;
    int scan_on_start;
    int skip_nfs;
    int msg_delay;
    unsigned int summary_delay;
    unsigned int request_db_interval;
    char* scan_time;
    wm_sca_policy_t** policies;
    char **alert_msg;
    int queue;
    int remote_commands:1;
    int commands_timeout;
    sched_scan_config scan_config;
} wm_sca_t;

typedef struct cis_db_info_t {
    char *result;
    cJSON *event;
    int id;
} cis_db_info_t;

typedef struct cis_db_hash_info_t {
    cis_db_info_t **elem;
} cis_db_hash_info_t;

extern const wm_context WM_SCA_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_sca_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_SCA_H
