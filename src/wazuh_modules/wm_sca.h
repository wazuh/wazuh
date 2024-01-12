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

#define WM_SCA_LOGTAG SCA_WM_NAME

/* Types of values */
#define WM_SCA_TYPE_FILE      1
#define WM_SCA_TYPE_REGISTRY  2
#define WM_SCA_TYPE_PROCESS   3
#define WM_SCA_TYPE_DIR       4
#define WM_SCA_TYPE_COMMAND   5

#define WM_SCA_COND_ALL       0x001
#define WM_SCA_COND_ANY       0x002
#define WM_SCA_COND_REQ       0x004
#define WM_SCA_COND_NON       0x008
#define WM_SCA_COND_INV       0x010
#define WM_SCA_STAMP          "sca"
#define WM_CONFIGURATION_ASSESSMENT_DB_DUMP                   "sca-dump"

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
int wm_sca_read(const OS_XML *xml,xml_node **nodes, wmodule *module);
char *wm_sca_hash_integrity_file(const char *file);
char **wm_sort_variables(const cJSON * const variables);
#ifdef WIN32
void wm_sca_push_request_win(char *msg);
#endif


#endif // WM_KEY_REQUEST_H
