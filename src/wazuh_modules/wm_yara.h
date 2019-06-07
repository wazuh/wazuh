/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_YARA_H
#define WM_YARA_H
#include <external/yara/libyara/include/yara.h>

#define WM_YARA_LOGTAG YARA_WM_NAME

typedef struct wm_yara_rule_t {
    unsigned int enabled:1;
    unsigned int remote:1;
    unsigned int timeout;
    char *description;
    char *path;
} wm_yara_rule_t;

typedef struct wm_yara_path_t {
    unsigned int ignore:1;
    unsigned int recursive:1;
    char *path;
} wm_yara_path_t;

typedef struct wm_yara_external_variable_t {
    char *name;
    char *value;
    unsigned int ignore:1;
} wm_yara_external_variable_t;


typedef struct wm_yara_set_t {
    unsigned int enabled:1;
    int scan_processes:1;
    unsigned int timeout;
    wm_yara_rule_t** rule;
    wm_yara_path_t** path;
    char *name;
    char *description;
    OSHash *exclude_hash;
    char *exclude_path;
    YR_RULES **compiled_rules;
} wm_yara_set_t;

typedef struct wm_yara_t {
    int enabled:1;
    int scan_on_start:1;
    unsigned int interval;
    int scan_day;                   
    int scan_wday;
    int msg_delay;
    unsigned int summary_delay;
    time_t next_time;
    unsigned int request_db_interval;
    char* scan_time;
    wm_yara_set_t** set;
    wm_yara_external_variable_t** external_variables;
    YR_COMPILER *compiler;
    char **alert_msg;
    char *restrict_processes;
    int queue;
} wm_yara_t;

extern const wm_context WM_YARA_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_yara_read(const OS_XML *xml,xml_node **nodes, wmodule *module);

int wm_yara_read_set(wm_yara_t **yara,const OS_XML *xml,xml_node **nodes, int index);

#define wm_yara_set_foreach(data,set,index) \
        for (index = 0, set = data->set[index]; data->set[index]; index++,set = data->set[index]) \

#define wm_yara_external_var_foreach(data,var,index) \
        for (index = 0, var = data->external_variables[index]; data->external_variables[index]; index++,var = data->external_variables[index]) \

#endif // WM_YARA_H
