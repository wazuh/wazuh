/*
 * Wazuh Module for Configuration Assessment
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_CONFIGURATION_ASSESSMENT_MONITORING_H
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_H

#define WM_CONFIGURATION_ASSESSMENT_MONITORING_LOGTAG CA_WM_NAME
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_INVALID_RKCL_NAME  "(1251): Invalid configuration name: '%s'."
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_INVALID_RKCL_VALUE "(1252): Invalid configuration value: '%s'."
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_INVALID_ROOTDIR    "(1253): Invalid rootdir (unable to retrieve)."
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_INVALID_RKCL_VAR   "(1254): Invalid variable: '%s'."


/* Types of values */
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_TYPE_FILE      1
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_TYPE_REGISTRY  2
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_TYPE_PROCESS   3
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_TYPE_DIR       4

#define WM_CONFIGURATION_ASSESSMENT_MONITORING_COND_ALL       0x001
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_COND_ANY       0x002
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_COND_REQ       0x004
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_COND_NON       0x008
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_COND_INV       0x016
#define WM_CONFIGURATION_ASSESSMENT_MONITORING_STAMP          "configuration-assessment"
#define WM_CONFIGURATION_ASSESSMENT_DB_DUMP                   "configuration-assessment-dump"

#ifdef WIN32
HKEY wm_configuration_assessment_sub_tree;
#endif

typedef struct wm_configuration_assessment_profile_t {
    unsigned int enabled:1;
    char *profile;
    char *policy_id;
} wm_configuration_assessment_profile_t;

typedef struct wm_configuration_assessment_t {
    int enabled:1;
    int scan_on_start:1;
    int skip_nfs:1;
    unsigned int interval;
    int scan_day;                   
    int scan_wday;
    int msg_delay;
    unsigned int summary_delay;
    time_t next_time;
    unsigned int request_db_interval;
    char* scan_time;
    wm_configuration_assessment_profile_t** profile;
    char **alert_msg;
    int queue;
} wm_configuration_assessment_t;

extern const wm_context WM_CONFIGURATION_ASSESSMENT_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_configuration_assessment_read(const OS_XML *xml,xml_node **nodes, wmodule *module);

#ifdef WIN32
void wm_configuration_assessment_push_request_win(char *msg);
#endif

#endif // WM_KEY_REQUEST_H
